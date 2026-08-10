package broker

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryCapabilityStore struct {
	credential StoredCredential
	capability StoredCapability
}

func (s *memoryCapabilityStore) CredentialByName(context.Context, string) (StoredCredential, error) {
	return s.credential, nil
}

func (s *memoryCapabilityStore) CreateCapability(_ context.Context, capability StoredCapability) error {
	s.capability = capability
	return nil
}

func (s *memoryCapabilityStore) CapabilityBySelector(_ context.Context, selector string) (StoredCapability, error) {
	if selector != s.capability.Selector {
		return StoredCapability{}, ErrCapabilityNotFound
	}
	return s.capability, nil
}

func (s *memoryCapabilityStore) UpdateRepositoryObservation(_ context.Context, _ string, repository Repository) error {
	s.capability.Repository = repository
	return nil
}

func TestIssuedCapabilityIsTheOnlyCredentialAcceptedByBroker(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{
		"primary": bytes.Repeat([]byte{0x42}, 32),
	}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := encryptedStoredCredential(t, cipher, StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionNumeric,
	}, "github-pat-that-must-stay-in-the-broker")
	store := &memoryCapabilityStore{credential: credential}
	resolver := NewRepositoryResolver(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"id":1326468465,"owner":{"login":"michaellee8"},"name":"github-proxy","default_branch":"main"}`)),
		}, nil
	}), func() time.Time { return now }, 30*time.Second)
	issuer := NewCapabilityIssuer(store, cipher, resolver, bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)), func() time.Time { return now })
	issued, err := issuer.Issue(context.Background(), IssueRequest{
		CredentialName: "work",
		Repository:     RepositoryRequest{Owner: "michaellee8", Name: "github-proxy"},
		Policy:         Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushNone}},
		ExpiresAt:      ptrTime(now.Add(time.Hour)),
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(issued.Token, "pgh_pat_"))
	assert.NotContains(t, string(store.capability.SecretHash), issued.Token)

	authority := NewCapabilityAuthority(store, cipher, resolver, func() time.Time { return now })
	upstreamCalls := 0
	handler := newTestHandler(t, HandlerOptions{
		Authority: authority,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamCalls++
			assert.Equal(t, "Bearer github-pat-that-must-stay-in-the-broker", req.Header.Get("Authorization"))
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		}),
	})

	assertCapabilityStatus(t, handler, issued.Token, http.StatusOK)
	assertCapabilityStatus(t, handler, issued.Token+"altered", http.StatusUnauthorized)
	require.Equal(t, 1, upstreamCalls)
}

func TestCredentialCipherBindsUpstreamDestinationMetadata(t *testing.T) {
	cipher, err := NewCredentialCipher("primary", map[string][]byte{
		"primary": bytes.Repeat([]byte{0x42}, 32),
	}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionNumeric,
	}
	sealed, err := cipher.EncryptCredential(credential, []byte("upstream-token"))
	require.NoError(t, err)
	credential.Token = sealed

	plaintext, err := cipher.DecryptCredential(credential)
	require.NoError(t, err)
	assert.Equal(t, "upstream-token", string(plaintext))

	credential.APIBaseURL = "https://attacker.example"
	_, err = cipher.DecryptCredential(credential)
	require.Error(t, err)
}

func TestExpiredAndRevokedCapabilitiesAreRejected(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{"primary": bytes.Repeat([]byte{0x42}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := encryptedStoredCredential(t, cipher, StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionNumeric,
	}, "upstream")

	for _, tt := range []struct {
		name      string
		expiresAt *time.Time
		revokedAt *time.Time
	}{
		{name: "expired", expiresAt: ptrTime(now.Add(-time.Second))},
		{name: "revoked", revokedAt: ptrTime(now.Add(-time.Second))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &memoryCapabilityStore{
				credential: credential,
				capability: StoredCapability{
					ID: "cap-1", Selector: "selector", SecretHash: hashCapabilitySecret("secret"), CredentialID: "cred-1",
					Credential: credential,
					Repository: Repository{ID: 1, Owner: "michaellee8", Name: "github-proxy", DefaultBranch: "main"},
					Policy:     Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushNone}}, ExpiresAt: tt.expiresAt, RevokedAt: tt.revokedAt,
				},
			}
			authority := NewCapabilityAuthority(store, cipher, nil, func() time.Time { return now })
			_, err := authority.Resolve(context.Background(), "pgh_pat_selector.secret", AllowCachedRepository)
			require.ErrorIs(t, err, ErrCapabilityInvalid)
		})
	}
}

func TestCapabilityTokenParserRejectsMalformedAndOversizedParts(t *testing.T) {
	tests := []string{
		"pgh_pat_missing-separator",
		"pgh_pat_bad!.secret",
		"pgh_pat_selector.bad!",
		"pgh_pat_" + strings.Repeat("a", 65) + ".secret",
		"pgh_pat_selector." + strings.Repeat("a", 129),
	}
	for _, token := range tests {
		_, _, ok := parseCapabilityToken(token)
		assert.False(t, ok, token)
	}
}

func TestCapabilityIssuerRejectsUnsupportedPolicy(t *testing.T) {
	validPolicy := Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushNone}}
	tests := []struct {
		name   string
		policy Policy
	}{
		{name: "unknown profile", policy: Policy{Name: "readonly", Version: 1, Git: validPolicy.Git}},
		{name: "unknown version", policy: Policy{Name: "developer", Version: 2, Git: validPolicy.Git}},
		{name: "unknown grant", policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"future.write": true}, Git: validPolicy.Git}},
		{name: "invalid Git push mode", policy: Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: "sometimes"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &memoryCapabilityStore{credential: StoredCredential{ID: "cred-1", Name: "work"}}
			issuer := NewCapabilityIssuer(store, nil, nil, bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)), time.Now)

			_, err := issuer.Issue(context.Background(), IssueRequest{
				CredentialName: "work",
				Repository:     RepositoryRequest{Owner: "owner", Name: "repo"},
				Policy:         tt.policy,
			})

			require.Error(t, err)
			assert.Empty(t, store.capability.ID)
		})
	}
}

func TestCapabilityIssuerDerivesRepositoryObservationFromGitHub(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{"primary": bytes.Repeat([]byte{0x42}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := encryptedStoredCredential(t, cipher, StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionNumeric,
	}, "upstream-token")
	store := &memoryCapabilityStore{credential: credential}
	resolver := NewRepositoryResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, "https://api.github.com/repos/requested/repo", req.URL.String())
		assert.Equal(t, "Bearer upstream-token", req.Header.Get("Authorization"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Etag": []string{`"repository-v1"`}},
			Body:       io.NopCloser(strings.NewReader(`{"id":99,"owner":{"login":"Canonical"},"name":"Repo","default_branch":"trunk"}`)),
		}, nil
	}), func() time.Time { return now }, 30*time.Second)
	issuer := NewCapabilityIssuer(store, cipher, resolver, bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)), func() time.Time { return now })
	expectedID := int64(99)

	_, err = issuer.Issue(context.Background(), IssueRequest{
		CredentialName: "work",
		Repository:     RepositoryRequest{Owner: "requested", Name: "repo", ExpectedID: &expectedID},
		Policy:         Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushNone}},
	})

	require.NoError(t, err)
	assert.Equal(t, int64(99), store.capability.Repository.ID)
	assert.Equal(t, "Canonical", store.capability.Repository.Owner)
	assert.Equal(t, "Repo", store.capability.Repository.Name)
	assert.Equal(t, "trunk", store.capability.Repository.DefaultBranch)
	assert.Equal(t, `"repository-v1"`, store.capability.Repository.ETag)
	assert.Equal(t, now, store.capability.Repository.ValidatedAt)
}

func TestCapabilityAuthorityRejectsUnsupportedStoredPolicy(t *testing.T) {
	cipher, err := NewCredentialCipher("primary", map[string][]byte{"primary": bytes.Repeat([]byte{0x42}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := encryptedStoredCredential(t, cipher, StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionNumeric,
	}, "upstream")
	store := &memoryCapabilityStore{capability: StoredCapability{
		ID: "cap-1", Selector: "selector", SecretHash: hashCapabilitySecret("secret"), CredentialID: "cred-1",
		Credential: credential,
		Repository: Repository{ID: 1, Owner: "owner", Name: "repo", DefaultBranch: "main"},
		Policy:     Policy{Name: "developer", Version: 2, Git: GitPolicy{Push: GitPushNone}},
	}}
	authority := NewCapabilityAuthority(store, cipher, nil, time.Now)

	_, err = authority.Resolve(context.Background(), "pgh_pat_selector.secret", AllowCachedRepository)

	require.ErrorIs(t, err, ErrCapabilityInvalid)
}

func TestCapabilityAuthorityCachesReadsAndRevalidatesMutations(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{"primary": bytes.Repeat([]byte{0x42}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := encryptedStoredCredential(t, cipher, StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionNumeric,
	}, "upstream")
	store := &memoryCapabilityStore{capability: StoredCapability{
		ID: "cap-1", Selector: "selector", SecretHash: hashCapabilitySecret("secret"), CredentialID: "cred-1",
		Credential: credential,
		Repository: Repository{ID: 99, Owner: "old", Name: "repo", DefaultBranch: "main", ETag: `"old"`, ValidatedAt: now},
		Policy: Policy{
			Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true},
			Git: GitPolicy{Push: GitPushNonDefault},
		},
	}}
	metadataCalls := 0
	resolver := NewRepositoryResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		metadataCalls++
		assert.Equal(t, "https://api.github.com/repositories/99", req.URL.String())
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Etag": []string{`"new"`}},
			Body: io.NopCloser(strings.NewReader(`{"id":99,"owner":{"login":"new"},"name":"repo","default_branch":"trunk"}`)),
		}, nil
	}), func() time.Time { return now }, 30*time.Second)
	authority := NewCapabilityAuthority(store, cipher, resolver, func() time.Time { return now })
	upstreamCalls := 0
	handler := newTestHandler(t, HandlerOptions{
		Authority: authority,
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			upstreamCalls++
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		}),
	})
	requestRead := func(path string) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer pgh_pat_selector.secret")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		require.Equal(t, http.StatusOK, res.Code)
	}

	requestRead("/api/v3/repos/old/repo")
	require.Equal(t, 0, metadataCalls)

	now = now.Add(31 * time.Second)
	requestRead("/api/v3/repos/new/repo")
	requestRead("/api/v3/repos/new/repo")
	require.Equal(t, 1, metadataCalls)

	req := httptest.NewRequest(http.MethodPut, "/api/v3/repos/new/repo/contents/file.txt", strings.NewReader(`{"message":"update","content":"YQ==","branch":"trunk"}`))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector.secret")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusForbidden, res.Code)
	assert.Contains(t, res.Body.String(), "PGH_REF_DENIED")
	assert.Equal(t, 2, metadataCalls)
	assert.Equal(t, 3, upstreamCalls)
	assert.Equal(t, "trunk", store.capability.Repository.DefaultBranch)
}

func TestCapabilityAuthorityFollowsVerifiedOwnerNameRedirect(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{"primary": bytes.Repeat([]byte{0x42}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	credential := encryptedStoredCredential(t, cipher, StoredCredential{
		ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: RepositoryResolutionName,
	}, "upstream")
	store := &memoryCapabilityStore{capability: StoredCapability{
		ID: "cap-1", Selector: "selector", SecretHash: hashCapabilitySecret("secret"), CredentialID: "cred-1",
		Credential: credential,
		Repository: Repository{ID: 99, Owner: "old", Name: "repo", DefaultBranch: "main", ValidatedAt: now.Add(-time.Hour)},
		Policy:     Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushNone}},
	}}
	requests := 0
	resolver := NewRepositoryResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			assert.Equal(t, "https://api.github.com/repos/old/repo", req.URL.String())
			return &http.Response{
				StatusCode: http.StatusMovedPermanently,
				Header:     http.Header{"Location": []string{"https://api.github.com/repos/new/repo"}},
				Body:       http.NoBody,
			}, nil
		case 2:
			assert.Equal(t, "https://api.github.com/repos/new/repo", req.URL.String())
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"id":99,"owner":{"login":"new"},"name":"repo","default_branch":"trunk"}`)),
			}, nil
		default:
			t.Fatalf("unexpected metadata request %d", requests)
			return nil, nil
		}
	}), func() time.Time { return now }, 30*time.Second)
	authority := NewCapabilityAuthority(store, cipher, resolver, func() time.Time { return now })

	session, err := authority.Resolve(context.Background(), "pgh_pat_selector.secret", RequireFreshRepository)

	require.NoError(t, err)
	assert.Equal(t, int64(99), session.Repository.ID)
	assert.Equal(t, "new", session.Repository.Owner)
	assert.Equal(t, "trunk", session.Repository.DefaultBranch)
	assert.Equal(t, 2, requests)
}

func assertCapabilityStatus(t *testing.T, handler http.Handler, token string, status int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/repos/michaellee8/github-proxy", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, status, res.Code)
}

func ptrTime(value time.Time) *time.Time {
	return &value
}

var _ CapabilityStore = (*memoryCapabilityStore)(nil)

func encryptedStoredCredential(t *testing.T, cipher *CredentialCipher, credential StoredCredential, plaintext string) StoredCredential {
	t.Helper()
	sealed, err := cipher.EncryptCredential(credential, []byte(plaintext))
	require.NoError(t, err)
	credential.Token = sealed
	return credential
}
