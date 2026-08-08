package broker

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type authorityFunc func(context.Context, string) (Session, error)

func (f authorityFunc) Resolve(ctx context.Context, token string) (Session, error) {
	return f(ctx, token)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBrokerContextReturnsBoundCapability(t *testing.T) {
	handler := NewHandler(HandlerOptions{
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
	handler := NewHandler(HandlerOptions{Authority: testAuthority(t)})
	req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	assert.JSONEq(t, `{"message":"missing capability token","code":"PGH_AUTH_REQUIRED"}`, res.Body.String())
}

func TestBrokerHealthDoesNotRequireCapability(t *testing.T) {
	handler := NewHandler(HandlerOptions{Authority: testAuthority(t)})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.JSONEq(t, `{"status":"ok"}`, res.Body.String())
}

func TestBrokerScopesRESTAndReplacesAuthorization(t *testing.T) {
	var upstreamRequest *http.Request
	handler := NewHandler(HandlerOptions{
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
		{name: "developer creates issue", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/issues", body: `{"title":"scoped"}`, wantStatus: http.StatusCreated, wantCall: true},
		{name: "developer reads actions", method: http.MethodGet, path: "/api/v3/repos/michaellee8/github-proxy/actions/runs", wantStatus: http.StatusCreated, wantCall: true},
		{name: "workflow dispatch needs grant", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/actions/workflows/test.yml/dispatches", wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "workflow dispatch granted", method: http.MethodPost, path: "/api/v3/repos/michaellee8/github-proxy/actions/workflows/test.yml/dispatches", body: `{"ref":"main"}`, grants: []string{"actions.write"}, git: GitPolicy{Push: GitPushAll}, wantStatus: http.StatusCreated, wantCall: true},
		{name: "comment deletion needs grant", method: http.MethodDelete, path: "/api/v3/repos/michaellee8/github-proxy/issues/comments/12", wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
		{name: "comment deletion granted", method: http.MethodDelete, path: "/api/v3/repos/michaellee8/github-proxy/issues/comments/12", grants: []string{"objects.delete"}, wantStatus: http.StatusCreated, wantCall: true},
		{name: "secrets are permanently denied", method: http.MethodGet, path: "/api/v3/repos/michaellee8/github-proxy/actions/secrets", grants: []string{"actions.write", "objects.delete"}, wantStatus: http.StatusForbidden, wantCode: "PGH_POLICY_DENIED"},
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
			handler := NewHandler(HandlerOptions{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := NewHandler(HandlerOptions{
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
	return authorityFunc(func(_ context.Context, token string) (Session, error) {
		require.Equal(t, "pgh_pat_selector_secret", token)
		return Session{
			CapabilityID: "cap-1",
			Repository: Repository{
				ID:            1326468465,
				Owner:         "michaellee8",
				Name:          "github-proxy",
				UpstreamHost:  "github.com",
				APIBaseURL:    "https://api.github.com",
				APIVersion:    "2022-11-28",
				UpstreamToken: "upstream-secret",
				DefaultBranch: "main",
			},
			Policy: policy,
		}, nil
	})
}
