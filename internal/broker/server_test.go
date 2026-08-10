package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type authorityFunc func(context.Context, string, RepositoryFreshness) (Session, error)

func (f authorityFunc) Resolve(ctx context.Context, token string, freshness RepositoryFreshness) (Session, error) {
	return f(ctx, token, freshness)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBrokerContextReturnsBoundCapability(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("context request must not call GitHub")
			return nil, nil
		}),
	})

	req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.JSONEq(t, `{
		"capability_id":"cap-1",
		"upstream_host":"github.com",
		"repository":{"id":1326468465,"owner":"michaellee8","name":"github-proxy"},
		"policy":{"name":"developer","version":1},
		"expires_at":null,
		"protocol_version":"1"
	}`, res.Body.String())
}

func TestBrokerRejectsMissingCapability(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{Authority: testAuthority(t)})
	req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	assert.JSONEq(t, `{"message":"missing capability token","code":"PGH_AUTH_REQUIRED"}`, res.Body.String())
}

func TestBrokerAcceptsGitHubCLITokenScheme(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{Authority: testAuthority(t)})
	req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
	req.Header.Set("Authorization", "token pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
}

func TestBrokerHealthDoesNotRequireCapability(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{Authority: testAuthority(t)})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.JSONEq(t, `{"status":"ok"}`, res.Body.String())
}

func TestBrokerAppliesLimitsToResolvedCapabilityID(t *testing.T) {
	limiter, err := NewLocalRequestLimiter(LocalLimitOptions{ReadsPerMinute: 1, MutationsPerMinute: 1, Concurrent: 1})
	require.NoError(t, err)
	handler := newTestHandler(t, HandlerOptions{
		Authority: authorityFunc(func(_ context.Context, _ string, _ RepositoryFreshness) (Session, error) {
			return Session{
				CapabilityID: "cap-authenticated",
				Repository:   Repository{ID: 99, Owner: "owner", Name: "repo", DefaultBranch: "main"},
				Upstream:     UpstreamAccess{Host: "github.com"},
				Policy:       Policy{Name: "developer", Version: 1},
			}, nil
		}),
		Limiter: limiter,
	})

	for index, token := range []string{"first-token", "second-token"} {
		req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler.ServeHTTP(res, req)

		if index == 0 {
			require.Equal(t, http.StatusOK, res.Code)
		} else {
			require.Equal(t, http.StatusTooManyRequests, res.Code)
		}
	}
	local := limiter.(*localRequestLimiter)
	assert.Len(t, local.limits, 1)
	assert.Contains(t, local.limits, "cap-authenticated")
}

func TestBrokerUsesOneBoundedLimiterEntryForInvalidTokens(t *testing.T) {
	limiter, err := NewLocalRequestLimiter(LocalLimitOptions{ReadsPerMinute: 100, MutationsPerMinute: 100, Concurrent: 1})
	require.NoError(t, err)
	handler := newTestHandler(t, HandlerOptions{
		Authority: authorityFunc(func(context.Context, string, RepositoryFreshness) (Session, error) {
			return Session{}, ErrCapabilityInvalid
		}),
		Limiter: limiter,
	})

	for index := range 20 {
		req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer pgh_pat_selector-%d.secret", index))
		res := httptest.NewRecorder()

		handler.ServeHTTP(res, req)

		require.Equal(t, http.StatusUnauthorized, res.Code)
	}
	local := limiter.(*localRequestLimiter)
	assert.Len(t, local.limits, 1)
	assert.Contains(t, local.limits, "invalid")
}

func TestBrokerClassifiesLFSReadAndMutationSemantics(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want RequestClass
	}{
		{name: "batch download", path: "/owner/repo.git/info/lfs/objects/batch", body: `{"operation":"download"}`, want: RequestRead},
		{name: "batch upload", path: "/owner/repo.git/info/lfs/objects/batch", body: `{"operation":"upload"}`, want: RequestMutation},
		{name: "malformed batch", path: "/owner/repo.git/info/lfs/objects/batch", body: `{`, want: RequestMutation},
		{name: "lock verification", path: "/owner/repo.git/info/lfs/locks/verify", body: `{}`, want: RequestRead},
		{name: "lock creation", path: "/owner/repo.git/info/lfs/locks", body: `{}`, want: RequestMutation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))

			got := classifyRequest(req)

			assert.Equal(t, tt.want, got)
			data, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.body, string(data))
		})
	}
}

func TestBrokerDeniesMutationWhenDurableAuditIsUnavailable(t *testing.T) {
	called := false
	handler := newTestHandler(t, HandlerOptions{
		Authority: authorityWithPolicy(t, Policy{Name: "developer", Version: 1}),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("must not be called")
		}),
		Auditor: NewRequestAuditor(&memoryAuditStore{err: errors.New("database unavailable")}, &memoryAuditEmitter{}),
		Limiter: newTestRequestLimiter(t),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v3/repos/michaellee8/github-proxy/issues", strings.NewReader(`{"title":"blocked"}`))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusServiceUnavailable, res.Code)
	assert.Contains(t, res.Body.String(), "PGH_AUDIT_UNAVAILABLE")
	assert.False(t, called)
}

func TestBrokerScopesRESTAndReplacesAuthorization(t *testing.T) {
	var upstreamRequest *http.Request
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamRequest = req.Clone(req.Context())
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"full_name":"michaellee8/github-proxy"}`)),
			}, nil
		}),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v3/repos/michaellee8/github-proxy", nil)
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	req.Header.Set("Cookie", "do-not-forward=1")
	req.Header.Set("X-GitHub-Api-Version", "client-selected")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NotNil(t, upstreamRequest)
	assert.Equal(t, "https://api.github.com/repos/michaellee8/github-proxy", upstreamRequest.URL.String())
	assert.Equal(t, "Bearer upstream-secret", upstreamRequest.Header.Get("Authorization"))
	assert.Equal(t, "2022-11-28", upstreamRequest.Header.Get("X-GitHub-Api-Version"))
	assert.Empty(t, upstreamRequest.Header.Get("Cookie"))

	upstreamRequest = nil
	other := httptest.NewRequest(http.MethodGet, "/api/v3/repos/other/private", nil)
	other.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, other)

	require.Equal(t, http.StatusForbidden, denied.Code)
	assert.Nil(t, upstreamRequest)
	assert.JSONEq(t, `{"message":"repository is outside this capability","code":"PGH_REPOSITORY_DENIED"}`, denied.Body.String())
}

func TestBrokerAppliesRegisteredRESTPolicy(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		grants     []string
		git        GitPolicy
		wantStatus int
		wantCode   string
		wantCall   bool
	}{
		{name: "repository readme", method: http.MethodGet, path: "/api/v3/repos/michaellee8/github-proxy/readme", wantStatus: http.StatusCreated, wantCall: true},
		{name: "developer creates issue", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/issues", body: `{"title":"scoped"}`, wantStatus: http.StatusCreated, wantCall: true},
		{name: "pull merge needs grant", method: http.MethodPut, path: "/api/v3/repos/michaellee8/github-proxy/pulls/12/merge", body: `{}`, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "pull merge granted", method: http.MethodPut, path: "/api/v3/repos/michaellee8/github-proxy/pulls/12/merge", body: `{}`, grants: []string{"pulls.merge"}, wantStatus: http.StatusCreated, wantCall: true},
		{name: "review dismissal needs grant", method: http.MethodPut, path: "/api/v3/repos/michaellee8/github-proxy/pulls/12/reviews/34/dismissals", body: `{"message":"superseded"}`, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "review dismissal granted", method: http.MethodPut, path: "/api/v3/repos/michaellee8/github-proxy/pulls/12/reviews/34/dismissals", body: `{"message":"superseded"}`, grants: []string{"pulls.review.dismiss"}, wantStatus: http.StatusCreated, wantCall: true},
		{name: "developer reads actions", method: http.MethodGet, path: "/api/v3/repos/michaellee8/github-proxy/actions/runs", wantStatus: http.StatusCreated, wantCall: true},
		{name: "workflow dispatch needs grant", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/actions/workflows/test.yml/dispatches", wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "workflow dispatch granted", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/actions/workflows/test.yml/dispatches", body: `{"ref":"main"}`, grants: []string{"actions.write"}, git: GitPolicy{Push: GitPushAll}, wantStatus: http.StatusCreated, wantCall: true},
		{name: "comment deletion needs grant", method: http.MethodDelete, path: "/api/v3/repos/michaellee8/github-proxy/issues/comments/12", wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "comment deletion granted", method: http.MethodDelete, path: "/api/v3/repos/michaellee8/github-proxy/issues/comments/12", grants: []string{"objects.delete"}, wantStatus: http.StatusCreated, wantCall: true},
		{name: "secrets are permanently denied", method: http.MethodGet, path: "/api/v3/repos/michaellee8/github-proxy/actions/secrets", grants: []string{"actions.write", "objects.delete"}, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "issue transfer is permanently denied", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/issues/12/transfer", body: `{"new_owner":"outside","new_repo":"private"}`, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "pull update branch is permanently denied", method: http.MethodPut, path: "/api/v3/repos/michaellee8/github-proxy/pulls/12/update-branch", body: `{}`, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "sub-issue relationships are permanently denied", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/issues/12/sub_issues", body: `{"sub_issue_id":42}`, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "unregistered issue mutation is denied", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/issues/12/future-global-write", body: `{}`, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "encoded separator is rejected", method: http.MethodGet, path: "/api/v3/repos/michaellee8/github-proxy/issues%2F1", wantStatus: http.StatusBadRequest, wantCode: "PGH_PATH_INVALID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			var gotBody string
			policy := Policy{Name: "developer", Version: 1, Grants: make(map[string]bool)}
			policy.Git = tt.git
			for _, grant := range tt.grants {
				policy.Grants[grant] = true
			}
			handler := newTestHandler(t, HandlerOptions{
				Authority: authorityWithPolicy(t, policy),
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					called = true
					data, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					gotBody = string(data)
					return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
				}),
			})
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			require.Equal(t, tt.wantStatus, res.Code)
			assert.Equal(t, tt.wantCall, called)
			if tt.wantCall {
				assert.Equal(t, tt.body, gotBody)
			}
			if tt.wantCode != "" {
				assert.Contains(t, res.Body.String(), tt.wantCode)
			}
		})
	}
}

func TestBrokerValidatesRESTRefFieldsAgainstGitPolicy(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		policy     Policy
		wantStatus int
	}{
		{
			name: "workflow default branch denied", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/actions/workflows/test.yml/dispatches", body: `{"ref":"main"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true}, Git: GitPolicy{Push: GitPushNonDefault}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "workflow non-default branch allowed", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/actions/workflows/test.yml/dispatches", body: `{"ref":"agent-work"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true}, Git: GitPolicy{Push: GitPushNonDefault}}, wantStatus: http.StatusCreated,
		},
		{
			name: "contents default branch denied", method: http.MethodPut,
			path: "/api/v3/repos/michaellee8/github-proxy/contents/file.txt", body: `{"message":"update","content":"YQ==","branch":"main"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true}, Git: GitPolicy{Push: GitPushNonDefault}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "release tag needs tag authority", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/releases", body: `{"tag_name":"v1","target_commitish":"agent-work"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"releases.write": true}, Git: GitPolicy{Push: GitPushAll}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "release edit cannot retarget without tag authority", method: http.MethodPatch,
			path: "/api/v3/repos/michaellee8/github-proxy/releases/42", body: `{"tag_name":"v2","target_commitish":"agent-work"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"releases.write": true}, Git: GitPolicy{Push: GitPushAll}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "release metadata edit does not need tag authority", method: http.MethodPatch,
			path: "/api/v3/repos/michaellee8/github-proxy/releases/42", body: `{"name":"renamed"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"releases.write": true}, Git: GitPolicy{Push: GitPushNone}}, wantStatus: http.StatusCreated,
		},
		{
			name: "REST ref update cannot write default branch", method: http.MethodPatch,
			path: "/api/v3/repos/michaellee8/github-proxy/git/refs/heads/main", body: `{"sha":"1111111111111111111111111111111111111111"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true}, Git: GitPolicy{Push: GitPushNonDefault}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "REST ref update can write non-default branch", method: http.MethodPatch,
			path: "/api/v3/repos/michaellee8/github-proxy/git/refs/heads/agent-work", body: `{"sha":"1111111111111111111111111111111111111111"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true}, Git: GitPolicy{Push: GitPushNonDefault}}, wantStatus: http.StatusCreated,
		},
		{
			name: "REST tag creation needs tag authority", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/git/refs", body: `{"ref":"refs/tags/v1","sha":"1111111111111111111111111111111111111111"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true}, Git: GitPolicy{Push: GitPushAll}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "REST ref deletion is always denied", method: http.MethodDelete,
			path:   "/api/v3/repos/michaellee8/github-proxy/git/refs/heads/agent-work",
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true, "objects.delete": true}, Git: GitPolicy{Push: GitPushAll, Tags: true}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "REST non-branch ref creation is denied", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/git/refs", body: `{"ref":"refs/notes/agent","sha":"1111111111111111111111111111111111111111"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"contents.write": true}, Git: GitPolicy{Push: GitPushAll, Tags: true}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "deployment status does not reinterpret status as a ref", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/deployments/42/statuses", body: `{"state":"success"}`,
			policy: Policy{Name: "developer", Version: 1, Grants: map[string]bool{"deployments.write": true}, Git: GitPolicy{Push: GitPushNone}}, wantStatus: http.StatusCreated,
		},
		{
			name: "pull request head cannot name an outside repository", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/pulls", body: `{"title":"outside","head":"outside:branch","base":"main"}`,
			policy: Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushAll}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "pull request head repository cannot name an outside repository", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/pulls", body: `{"title":"outside","head":"branch","head_repo":"outside","base":"main"}`,
			policy: Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushAll}}, wantStatus: http.StatusForbidden,
		},
		{
			name: "pull request head can name a branch in the bound repository", method: http.MethodPost,
			path: "/api/v3/repos/michaellee8/github-proxy/pulls", body: `{"title":"inside","head":"agent-work","base":"main"}`,
			policy: Policy{Name: "developer", Version: 1, Git: GitPolicy{Push: GitPushNone}}, wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := newTestHandler(t, HandlerOptions{
				Authority: authorityWithPolicy(t, tt.policy),
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					called = true
					return &http.Response{StatusCode: http.StatusCreated, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
				}),
			})
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			require.Equal(t, tt.wantStatus, res.Code)
			assert.Equal(t, tt.wantStatus == http.StatusCreated, called)
		})
	}
}

func testAuthority(t *testing.T) Authority {
	t.Helper()
	return authorityWithPolicy(t, Policy{Name: "developer", Version: 1})
}

func authorityWithPolicy(t *testing.T, policy Policy) Authority {
	t.Helper()
	return authorityFunc(func(_ context.Context, token string, _ RepositoryFreshness) (Session, error) {
		require.Equal(t, "pgh_pat_selector_secret", token)
		return Session{
			CapabilityID: "cap-1",
			Repository: Repository{
				ID: 1326468465, Owner: "michaellee8", Name: "github-proxy", DefaultBranch: "main",
			},
			Upstream: UpstreamAccess{Host: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: "upstream-secret"},
			Policy:   policy,
		}, nil
	})
}

func newTestHandler(t *testing.T, options HandlerOptions) http.Handler {
	t.Helper()
	if options.Auditor == nil {
		options.Auditor = NewRequestAuditor(&memoryAuditStore{}, &memoryAuditEmitter{})
	}
	if options.Limiter == nil {
		options.Limiter = newTestRequestLimiter(t)
	}
	return NewHandler(options)
}

func newTestRequestLimiter(t *testing.T) RequestLimiter {
	t.Helper()
	limiter, err := NewLocalRequestLimiter(LocalLimitOptions{ReadsPerMinute: 10_000, MutationsPerMinute: 10_000, Concurrent: 100})
	require.NoError(t, err)
	return limiter
}
