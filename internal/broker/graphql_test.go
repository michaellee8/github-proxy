package broker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrokerForwardsRegisteredRepositoryGraphQLQuery(t *testing.T) {
	var upstreamRequest *http.Request
	var upstreamBody struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamRequest = req.Clone(req.Context())
			require.NoError(t, json.NewDecoder(req.Body).Decode(&upstreamBody))
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"data":{"repository":{"name":"github-proxy"}}}`)),
			}, nil
		}),
	})

	body := `{
		"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name issues(first: 10) { nodes { number author { login } } } } }",
		"variables":{"owner":"other","name":"private"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	req.Header.Set("Cookie", "do-not-forward=1")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NotNil(t, upstreamRequest)
	assert.Equal(t, "https://api.github.com/graphql", upstreamRequest.URL.String())
	assert.Equal(t, "Bearer upstream-secret", upstreamRequest.Header.Get("Authorization"))
	assert.Empty(t, upstreamRequest.Header.Get("Cookie"))
	assert.Equal(t, "michaellee8", upstreamBody.Variables["owner"])
	assert.Equal(t, "github-proxy", upstreamBody.Variables["name"])
	assert.Contains(t, upstreamBody.Query, "query RepositoryInfo")
	assert.JSONEq(t, `{"data":{"repository":{"name":"github-proxy"}}}`, res.Body.String())
}

func TestBrokerSupportsPinnedGHRepositoryReadFamilies(t *testing.T) {
	var variables map[string]any
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var payload graphQLRequest
			require.NoError(t, json.NewDecoder(req.Body).Decode(&payload))
			variables = payload.Variables
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":{"repository":{"issues":{"nodes":[]}}}}`))}, nil
		}),
	})
	body := `{
		"query":"query IssueList($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { issues(first: 10) { nodes { number } } } }",
		"variables":{"owner":"outside","repo":"private"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.Equal(t, "michaellee8", variables["owner"])
	assert.Equal(t, "github-proxy", variables["repo"])
}

func TestBrokerSupportsPinnedGHRepositoryIssueTypesQuery(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"data":{"repository":{"issueTypes":{"nodes":[]}}}}`)),
			}, nil
		}),
	})
	body := `{
		"query":"query RepositoryIssueTypes($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { issueTypes(first: 50) { nodes { id name description color } } } }",
		"variables":{"owner":"outside","name":"private"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
}

func TestBrokerSupportsPinnedGHReleaseListQuery(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"data":{"repository":{"releases":{"nodes":[]}}}}`)),
			}, nil
		}),
	})
	body := `{
		"query":"query RepositoryReleaseList($owner: String!, $name: String!, $perPage: Int!, $endCursor: String, $direction: OrderDirection!) { repository(owner: $owner, name: $name) { releases(first: $perPage, orderBy: {field: CREATED_AT, direction: $direction}, after: $endCursor) { nodes { name tagName isDraft isLatest isPrerelease immutable createdAt publishedAt } pageInfo { hasNextPage endCursor } } } }",
		"variables":{"owner":"outside","name":"private","perPage":5,"endCursor":null,"direction":"DESC"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
}

func TestBrokerSupportsPinnedGHReleaseFeatureProbe(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"data":{"Release":{"fields":[{"name":"immutable"}]}}}`)),
			}, nil
		}),
	})
	body := `{"query":"query Release_fields { Release: __type(name: \"Release\") { fields { name } } }"}`
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
}

func TestBrokerRejectsUnscopedGraphQLRequests(t *testing.T) {
	valid := `query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name } }`
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "batch",
			method:     http.MethodPost,
			body:       `[{"query":"` + valid + `","variables":{"owner":"other","name":"private"}}]`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "PGH_GRAPHQL_INVALID",
		},
		{
			name:       "multiple operations",
			method:     http.MethodPost,
			body:       `{"query":"` + valid + ` query Second { viewer { login } }"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "PGH_GRAPHQL_INVALID",
		},
		{
			name:       "anonymous operation",
			method:     http.MethodPost,
			body:       `{"query":"{ repository(owner: \"other\", name: \"private\") { name } }"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "PGH_GRAPHQL_INVALID",
		},
		{
			name:       "unregistered operation",
			method:     http.MethodPost,
			body:       `{"query":"query Arbitrary($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { name } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_OPERATION_UNKNOWN",
		},
		{
			name:       "literal repository",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo { repository(owner: \"other\", name: \"private\") { name } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "different repository variable",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($login: String!, $name: String!) { repository(owner: $login, name: $name) { name } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "introspection",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { __schema { types { name } } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "release feature probe with variables",
			method:     http.MethodPost,
			body:       `{"query":"query Release_fields { Release: __type(name: \"Release\") { fields { name } } }","variables":{"outside":"value"}}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "release feature probe with directive",
			method:     http.MethodPost,
			body:       `{"query":"query Release_fields { Release: __type(name: \"Release\") @include(if: true) { fields { name } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "release feature probe with nested alias",
			method:     http.MethodPost,
			body:       `{"query":"query Release_fields { Release: __type(name: \"Release\") { fields { fieldName: name } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "global node",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!, $id: ID!) { node(id: $id) { id } repository(owner: $owner, name: $name) { name } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "global search",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!, $query: String!) { search(query: $query, type: ISSUE) { issueCount } repository(owner: $owner, name: $name) { name } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "sensitive repository field",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { collaborators { totalCount } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "repository owner graph traversal",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { owner { repositories(first: 1) { nodes { name } } } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "nested repository traversal",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { owner { repository(name: \"outside\") { name } } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "issue author global issue traversal",
			method:     http.MethodPost,
			body:       `{"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { issues(first: 1) { nodes { author { ... on User { issues(first: 10) { nodes { title body } } } } } } } }"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
		{
			name:       "operation name mismatch",
			method:     http.MethodPost,
			body:       `{"query":"` + valid + `","operationName":"Other"}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "PGH_GRAPHQL_INVALID",
		},
		{
			name:       "GET",
			method:     http.MethodGet,
			body:       `{"query":"` + valid + `"}`,
			wantStatus: http.StatusForbidden,
			wantCode:   "PGH_POLICY_DENIED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestHandler(t, HandlerOptions{
				Authority: testAuthority(t),
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("denied GraphQL request must not call GitHub")
					return nil, nil
				}),
			})
			req := httptest.NewRequest(tt.method, "/api/graphql", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
			res := httptest.NewRecorder()

			handler.ServeHTTP(res, req)

			require.Equal(t, tt.wantStatus, res.Code)
			assert.Contains(t, res.Body.String(), tt.wantCode)
		})
	}
}

func TestBrokerLimitsGraphQLDocumentComplexity(t *testing.T) {
	handler := newTestHandler(t, HandlerOptions{
		Authority: testAuthority(t),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("oversized GraphQL document must not call GitHub")
			return nil, nil
		}),
	})
	query := `query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) {` + strings.Repeat(" name", 5000) + ` } }`
	body, err := json.Marshal(map[string]any{"query": query})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/graphql", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer pgh_pat_selector_secret")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusBadRequest, res.Code)
	assert.Contains(t, res.Body.String(), "PGH_GRAPHQL_INVALID")
}
