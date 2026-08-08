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

func TestIssuedCapabilityIsTheOnlyCredentialAcceptedByBroker(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{
		"primary": bytes.Repeat([]byte{0x42}, 32),
	}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	sealed, err := cipher.Encrypt([]byte("github-pat-that-must-stay-in-the-broker"))
	require.NoError(t, err)

	store := &memoryCapabilityStore{credential: StoredCredential{
		ID:           "cred-1",
		Name:         "work",
		UpstreamHost: "github.com",
		APIBaseURL:   "https://api.github.com",
		APIVersion:   "2022-11-28",
		Token:        sealed,
	}}
	issuer := NewCapabilityIssuer(store, bytes.NewReader(bytes.Repeat([]byte{0x51}, 128)), func() time.Time { return now })
	issued, err := issuer.Issue(context.Background(), IssueRequest{
		CredentialName: "work",
		Repository: Repository{
			ID:            1326468465,
			Owner:         "michaellee8",
			Name:          "github-proxy",
			DefaultBranch: "main",
		},
		Policy:    Policy{Name: "developer", Version: 1},
		ExpiresAt: ptrTime(now.Add(time.Hour)),
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(issued.Token, "pgh_pat_"))
	assert.NotContains(t, string(store.capability.SecretHash), issued.Token)

	authority := NewCapabilityAuthority(store, cipher, func() time.Time { return now })
	upstreamCalls := 0
	handler := NewHandler(HandlerOptions{
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

func TestExpiredAndRevokedCapabilitiesAreRejected(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	cipher, err := NewCredentialCipher("primary", map[string][]byte{"primary": bytes.Repeat([]byte{0x42}, 32)}, bytes.NewReader(bytes.Repeat([]byte{0x24}, 64)))
	require.NoError(t, err)
	sealed, err := cipher.Encrypt([]byte("upstream"))
	require.NoError(t, err)

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
				credential: StoredCredential{ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: sealed},
				capability: StoredCapability{
					ID: "cap-1", Selector: "selector", SecretHash: hashCapabilitySecret("secret"), CredentialID: "cred-1",
					Credential: storeCredential(sealed),
					Repository: Repository{ID: 1, Owner: "michaellee8", Name: "github-proxy", DefaultBranch: "main"},
					Policy:     Policy{Name: "developer", Version: 1}, ExpiresAt: tt.expiresAt, RevokedAt: tt.revokedAt,
				},
			}
			authority := NewCapabilityAuthority(store, cipher, func() time.Time { return now })
			_, err := authority.Resolve(context.Background(), "pgh_pat_selector.secret")
			assert.ErrorIs(t, err, ErrCapabilityInvalid)
		})
	}
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

func storeCredential(token SealedCredential) StoredCredential {
	return StoredCredential{ID: "cred-1", Name: "work", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: token}
}
