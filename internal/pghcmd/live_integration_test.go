package pghcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/stretchr/testify/require"
)

const (
	liveHelperEnvironment = "PGH_LIVE_COMMAND_HELPER"
	liveTraceEnvironment  = "PGH_LIVE_COMMAND_TRACE"
	liveMutationBlocked   = "live command audit blocked an upstream mutation"
)

type liveCommandAuthority struct {
	session broker.Session
}

type liveCommandAuditStore struct{}

func (liveCommandAuditStore) RecordAuditEvent(context.Context, broker.AuditEvent) error { return nil }

func newLiveCommandHandler(t *testing.T, options broker.HandlerOptions) http.Handler {
	t.Helper()
	limiter, err := broker.NewLocalRequestLimiter(broker.LocalLimitOptions{ReadsPerMinute: 10_000, MutationsPerMinute: 10_000, Concurrent: 100})
	require.NoError(t, err)
	options.Auditor = broker.NewRequestAuditor(liveCommandAuditStore{}, broker.NewJSONAuditEmitter(io.Discard))
	options.Limiter = limiter
	return broker.NewHandler(options)
}

func (a liveCommandAuthority) Resolve(_ context.Context, token string, _ broker.RepositoryFreshness) (broker.Session, error) {
	if token != "live-capability" {
		return broker.Session{}, errors.New("unexpected capability token")
	}
	return a.session, nil
}

type handlerTransport struct {
	handler   http.Handler
	traceFile string
}

func (t handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.traceFile != "" {
		trace, err := os.OpenFile(t.traceFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open live command trace: %w", err)
		}
		_, writeErr := fmt.Fprintf(trace, "%s %s\n", request.Method, request.URL.RequestURI())
		closeErr := trace.Close()
		if writeErr != nil {
			return nil, fmt.Errorf("write live command trace: %w", writeErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close live command trace: %w", closeErr)
		}
	}
	recorder := httptest.NewRecorder()
	forwarded := request.Clone(request.Context())
	forwarded.RequestURI = request.URL.RequestURI()
	t.handler.ServeHTTP(recorder, forwarded)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

type githubCLIAuthTransport struct {
	base  http.RoundTripper
	token string
}

type liveReadOnlyTransport struct {
	base http.RoundTripper
}

// GraphQL reaches this transport only after the Broker has accepted a registered
// query document. REST writes are blocked here so live CLI audits cannot mutate
// GitHub even when a command maps to an otherwise authorized REST route.
func (t liveReadOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet || request.Method == http.MethodHead ||
		(request.Method == http.MethodPost && request.URL.Path == "/graphql") {
		return t.base.RoundTrip(request)
	}
	return &http.Response{
		StatusCode: http.StatusConflict,
		Status:     http.StatusText(http.StatusConflict),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"message":"` + liveMutationBlocked + `"}`)),
		Request:    request,
	}, nil
}

func TestLiveReadOnlyTransportBlocksRESTMutations(t *testing.T) {
	forwarded := 0
	transport := liveReadOnlyTransport{base: handlerTransport{handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusNoContent)
	})}}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		request, err := http.NewRequest(method, "https://api.github.com/repos/owner/repo/issues", nil)
		require.NoError(t, err)
		response, err := transport.RoundTrip(request)
		require.NoError(t, err)
		require.Equal(t, http.StatusConflict, response.StatusCode)
		require.NoError(t, response.Body.Close())
	}
	require.Zero(t, forwarded)

	request, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/owner/repo", nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Equal(t, 1, forwarded)

	request, err = http.NewRequest(http.MethodPost, "https://api.github.com/graphql", strings.NewReader(`{"query":"query RepositoryInfo { viewer { login } }"}`))
	require.NoError(t, err)
	response, err = transport.RoundTrip(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Equal(t, 2, forwarded)
}

func (t githubCLIAuthTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Authorization", "token "+t.token)
	return t.base.RoundTrip(request)
}

func TestLivePGHRepoViewCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "repo", "view", repositoryName, "--json", "nameWithOwner", "--jq", ".nameWithOwner")

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.Equal(t, repositoryName+"\n", result.stdout)
}

func TestLivePGHRepoViewPlainCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "repo", "view", repositoryName)

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.Contains(t, result.stdout, repositoryName)
}

func TestLivePGHRESTAPICompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "api", "repos/"+repositoryName, "--jq", ".full_name")

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.Equal(t, repositoryName+"\n", result.stdout)
}

func TestLivePGHGraphQLAPICompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	query := `query RepositoryInfo($owner: String!, $name: String!) {
		repository(owner: $owner, name: $name) { nameWithOwner }
	}`

	result := runLivePGH(t,
		"api", "graphql",
		"-f", "query="+query,
		"-F", "owner="+owner,
		"-F", "name="+name,
		"--jq", ".data.repository.nameWithOwner",
	)

	require.Equal(t, 0, result.exitCode, result.stderr)
	require.Equal(t, repositoryName+"\n", result.stdout)
}

func TestLivePGHRegisteredGraphQLFamilyCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")

	tests := []struct {
		name      string
		query     string
		fields    []string
		wantError string
	}{
		{
			name:   "RepositoryInfo",
			query:  `query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { nameWithOwner } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "IssueList",
			query:  `query IssueList($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { hasIssuesEnabled issues(first: 1) { totalCount nodes { number } pageInfo { hasNextPage endCursor } } } }`,
			fields: []string{"owner=" + owner, "repo=" + name},
		},
		{
			name:      "IssueByNumber",
			query:     `query IssueByNumber($owner: String!, $repo: String!, $number: Int!) { repository(owner: $owner, name: $repo) { hasIssuesEnabled issue: issueOrPullRequest(number: $number) { __typename ... on Issue { number } ... on PullRequest { number } } } }`,
			fields:    []string{"owner=" + owner, "repo=" + name, "number=999999999"},
			wantError: "Could not resolve to an issue or pull request",
		},
		{
			name:      "IssueNodeID",
			query:     `query IssueNodeID($owner: String!, $name: String!, $number: Int!) { repository(owner: $owner, name: $name) { issue(number: $number) { id } } }`,
			fields:    []string{"owner=" + owner, "name=" + name, "number=999999999"},
			wantError: "Could not resolve to an Issue",
		},
		{
			name:   "IssueRepositoryInfo",
			query:  `query IssueRepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id name owner { login } hasIssuesEnabled viewerPermission } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "IssueTemplates",
			query:  `query IssueTemplates($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { issueTemplates { name body title } } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "LabelList",
			query:  `query LabelList($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { labels(first: 1) { totalCount nodes { id name color description } pageInfo { hasNextPage endCursor } } } }`,
			fields: []string{"owner=" + owner, "repo=" + name},
		},
		{
			name:   "PullRequestList",
			query:  `query PullRequestList($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { pullRequests(first: 1) { totalCount nodes { number title } pageInfo { hasNextPage endCursor } } } }`,
			fields: []string{"owner=" + owner, "repo=" + name},
		},
		{
			name:      "PullRequestByNumber",
			query:     `query PullRequestByNumber($owner: String!, $repo: String!, $pr_number: Int!) { repository(owner: $owner, name: $repo) { pullRequest(number: $pr_number) { number title } } }`,
			fields:    []string{"owner=" + owner, "repo=" + name, "pr_number=999999999"},
			wantError: "Could not resolve to a PullRequest",
		},
		{
			name:   "PullRequestForBranch",
			query:  `query PullRequestForBranch($owner: String!, $repo: String!, $headRefName: String!, $states: [PullRequestState!]) { repository(owner: $owner, name: $repo) { pullRequests(headRefName: $headRefName, states: $states, first: 1) { nodes { number } } defaultBranchRef { name } } }`,
			fields: []string{"owner=" + owner, "repo=" + name, "headRefName=pgh-missing", "states[]=OPEN"},
		},
		{
			name:   "PullRequestTemplates",
			query:  `query PullRequestTemplates($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { pullRequestTemplates { filename body } } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "RepositoryIssueTypes",
			query:  `query RepositoryIssueTypes($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { issueTypes(first: 50) { nodes { id name description color } } } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "RepositoryLabelList",
			query:  `query RepositoryLabelList($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { labels(first: 1) { nodes { id name } pageInfo { hasNextPage endCursor } } } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "RepositoryMilestoneList",
			query:  `query RepositoryMilestoneList($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { milestones(first: 1) { nodes { id title } pageInfo { hasNextPage endCursor } } } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
		{
			name:   "RepositoryReleaseList",
			query:  `query RepositoryReleaseList($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { releases(first: 1) { nodes { name tagName isDraft isLatest isPrerelease immutable createdAt publishedAt } pageInfo { hasNextPage endCursor } } } }`,
			fields: []string{"owner=" + owner, "name=" + name},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arguments := []string{"api", "graphql", "-f", "query=" + tt.query}
			for _, field := range tt.fields {
				arguments = append(arguments, "-F", field)
			}
			result := runLivePGH(t, arguments...)
			if tt.wantError != "" {
				require.NotEqual(t, 0, result.exitCode)
				require.Contains(t, result.stderr, tt.wantError)
				require.NotContains(t, result.stderr, "PGH_")
				return
			}
			require.Equal(t, 0, result.exitCode, result.stderr)
			var payload struct {
				Errors []json.RawMessage `json:"errors"`
			}
			require.NoError(t, json.Unmarshal([]byte(result.stdout), &payload), result.stdout)
			require.Empty(t, payload.Errors, result.stdout)
		})
	}
}

func TestLivePGHIssueListCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "issue", "list", "--repo", repositoryName, "--limit", "5", "--json", "number,title")

	require.Equal(t, 0, result.exitCode, result.stderr)
	var issues []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &issues), result.stdout)
}

func TestLivePGHPullRequestListCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "pr", "list", "--repo", repositoryName, "--limit", "5", "--json", "number,title")

	require.Equal(t, 0, result.exitCode, result.stderr)
	var pullRequests []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &pullRequests), result.stdout)
}

func TestLivePGHLabelListCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "label", "list", "--repo", repositoryName, "--limit", "5", "--json", "name")

	require.Equal(t, 0, result.exitCode, result.stderr)
	var labels []struct {
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &labels), result.stdout)
}

func TestLivePGHReleaseListCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "release", "list", "--repo", repositoryName, "--limit", "5", "--json", "name,tagName")

	require.Equal(t, 0, result.exitCode, result.stderr)
	var releases []struct {
		Name    string `json:"name"`
		TagName string `json:"tagName"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.stdout), &releases), result.stdout)
}

func TestLivePGHWorkflowListCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "workflow", "list", "--repo", repositoryName, "--limit", "5", "--json", "id,name,path,state")

	require.Equal(t, 0, result.exitCode, result.stderr)
	var workflows []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if result.stdout != "" {
		require.NoError(t, json.Unmarshal([]byte(result.stdout), &workflows), result.stdout)
	}
}

func TestLivePGHRunListCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}

	result := runLivePGH(t, "run", "list", "--repo", repositoryName, "--limit", "5", "--json", "databaseId,workflowName,status")

	require.Equal(t, 0, result.exitCode, result.stderr)
	var runs []struct {
		DatabaseID   int64  `json:"databaseId"`
		WorkflowName string `json:"workflowName"`
		Status       string `json:"status"`
	}
	if result.stdout != "" {
		require.NoError(t, json.Unmarshal([]byte(result.stdout), &runs), result.stdout)
	}
}

func TestLivePGHReadOnlyCommandAudit(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, _, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")

	tests := []struct {
		name                string
		args                []string
		wantExitCode        int
		wantStdoutContains  string
		wantStderrContains  string
		wantRequestContains []string
		wantNoRequests      bool
	}{
		{name: "agent-task list", args: []string{"agent-task", "list", "--limit", "1", "--json", "id"}, wantExitCode: 1, wantStderrContains: "agent tasks are not supported on this host", wantNoRequests: true},
		{name: "browse", args: []string{"browse", "--repo", repositoryName, "--no-browser"}, wantStdoutContains: "https://broker.test/" + repositoryName, wantRequestContains: []string{"HEAD /api/v3/repos/" + repositoryName}},
		{name: "cache list", args: []string{"cache", "list", "--repo", repositoryName, "--limit", "1", "--json", "id"}, wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/actions/caches"}},
		{name: "codespace list", args: []string{"codespace", "list", "--repo", repositoryName, "--limit", "1", "--json", "name"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/codespaces"}},
		{name: "discussion list", args: []string{"discussion", "list", "--repo", repositoryName, "--limit", "1"}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "extension search", args: []string{"extension", "search", "pgh"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/search/repositories"}},
		{name: "gist list", args: []string{"gist", "list", "--limit", "1"}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "gpg-key list", args: []string{"gpg-key", "list"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/user/gpg_keys"}},
		{name: "issue status", args: []string{"issue", "status", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "org list", args: []string{"org", "list", "--limit", "1"}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "pr status", args: []string{"pr", "status", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "project list", args: []string{"project", "list", "--owner", owner, "--limit", "1"}, wantExitCode: 1, wantStderrContains: "unknown owner type", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "release view", args: []string{"release", "view", "pgh-command-audit-missing", "--repo", repositoryName, "--json", "tagName"}, wantExitCode: 1, wantStderrContains: "release not found", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/releases/tags/pgh-command-audit-missing"}},
		{name: "repo autolink list", args: []string{"repo", "autolink", "list", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/autolinks"}},
		{name: "repo deploy-key list", args: []string{"repo", "deploy-key", "list", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/keys"}},
		{name: "repo gitignore list", args: []string{"repo", "gitignore", "list"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/gitignore/templates"}},
		{name: "repo license list", args: []string{"repo", "license", "list"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/licenses"}},
		{name: "repo list", args: []string{"repo", "list", owner, "--limit", "1", "--json", "nameWithOwner"}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "repo read-dir", args: []string{"repo", "read-dir", ".", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "repo read-file", args: []string{"repo", "read-file", "pgh-command-audit-missing", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "HTTP 404", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/contents/pgh-command-audit-missing"}},
		{name: "ruleset list", args: []string{"ruleset", "list", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not registered", wantRequestContains: []string{"POST /api/graphql"}},
		{name: "search code", args: []string{"search", "code", "github-proxy", "--repo", repositoryName, "--limit", "1"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/search/code"}},
		{name: "secret list", args: []string{"secret", "list", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/actions/secrets"}},
		{name: "skill search", args: []string{"skill", "search", "pgh", "--limit", "1"}, wantExitCode: 1, wantStderrContains: "GitHub Skills does not currently support GitHub Enterprise Server", wantNoRequests: true},
		{name: "ssh-key list", args: []string{"ssh-key", "list"}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/user/keys", "GET /api/v3/user/ssh_signing_keys"}},
		{name: "status", args: []string{"status"}, wantExitCode: 1, wantStderrContains: "operation is not", wantRequestContains: []string{"GET /api/v3/notifications"}},
		{name: "variable list", args: []string{"variable", "list", "--repo", repositoryName}, wantExitCode: 1, wantStderrContains: "operation is not allowed", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/actions/variables"}},
		{name: "workflow view", args: []string{"workflow", "view", "pgh-command-audit-missing.yml", "--repo", repositoryName, "--yaml"}, wantExitCode: 1, wantStderrContains: "not found on the default branch", wantRequestContains: []string{"GET /api/v3/repos/" + repositoryName + "/actions/workflows/pgh-command-audit-missing.yml"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runLivePGH(t, tt.args...)
			require.Equal(t, tt.wantExitCode, result.exitCode, result.stderr)
			if tt.wantStdoutContains != "" {
				require.Contains(t, result.stdout, tt.wantStdoutContains)
			}
			if tt.wantStderrContains != "" {
				require.Contains(t, result.stderr, tt.wantStderrContains)
			}
			if tt.wantNoRequests {
				require.Empty(t, result.requests, "command unexpectedly exercised the broker or GitHub")
			}
			for _, wantRequest := range tt.wantRequestContains {
				require.True(t, requestTraceContains(result.requests, wantRequest), "requests %q do not contain %q", result.requests, wantRequest)
			}
		})
	}
}

func requestTraceContains(requests []string, substring string) bool {
	for _, request := range requests {
		if strings.Contains(request, substring) {
			return true
		}
	}
	return false
}

func TestLivePGHCommandHelper(t *testing.T) {
	if os.Getenv(liveHelperEnvironment) != "1" {
		t.Skip("live command helper runs only in a subprocess")
	}
	token := readLiveUpstreamToken(t)
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")

	handler := newLiveCommandHandler(t, broker.HandlerOptions{Authority: liveCommandAuthority{session: broker.Session{
		CapabilityID: "live-command-test",
		Repository:   broker.Repository{Owner: owner, Name: name},
		Upstream:     broker.UpstreamAccess{Host: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: token},
		Policy:       broker.Policy{Name: "developer", Version: 1},
	}}, Transport: liveReadOnlyTransport{base: http.DefaultTransport}})
	os.Args = append([]string{"pgh"}, helperArguments(os.Args)...)
	exitCode := mainWithOptions(mainOptions{HTTPClientWrapper: func(client *http.Client) *http.Client {
		client.Transport = githubCLIAuthTransport{
			base:  handlerTransport{handler: handler, traceFile: os.Getenv(liveTraceEnvironment)},
			token: "live-capability",
		}
		return client
	}})
	os.Exit(exitCode)
}

func readLiveUpstreamToken(t *testing.T) string {
	t.Helper()
	fd, err := strconv.Atoi(os.Getenv("PGH_LIVE_TOKEN_FD"))
	require.NoError(t, err, "PGH_LIVE_TOKEN_FD must identify the one-shot credential pipe")
	file := os.NewFile(uintptr(fd), "pgh-live-upstream-token")
	require.NotNil(t, file)
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.NoError(t, os.Unsetenv("PGH_LIVE_TOKEN_FD"))
	require.NotEmpty(t, data)
	require.LessOrEqual(t, len(data), 64*1024)
	return string(data)
}

type liveCommandResult struct {
	exitCode int
	stdout   string
	stderr   string
	requests []string
}

type liveCommandOptions struct {
	directory string
	stdin     string
}

func runLivePGH(t *testing.T, arguments ...string) liveCommandResult {
	return runLivePGHWithOptions(t, liveCommandOptions{}, arguments...)
}

func runLivePGHWithOptions(t *testing.T, opts liveCommandOptions, arguments ...string) liveCommandResult {
	t.Helper()
	traceFile := t.TempDir() + "/requests.log"
	commandArguments := append([]string{"-test.run=^TestLivePGHCommandHelper$", "--"}, arguments...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, os.Args[0], commandArguments...)
	if opts.directory != "" {
		command.Dir = opts.directory
	}
	tokenReader, tokenWriter, err := os.Pipe()
	require.NoError(t, err)
	_, err = tokenWriter.Write([]byte(os.Getenv("PGH_LIVE_TOKEN")))
	require.NoError(t, err)
	require.NoError(t, tokenWriter.Close())
	command.ExtraFiles = []*os.File{tokenReader}
	command.Env = append(environmentWithout(os.Environ(),
		"PGH_LIVE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"),
		liveHelperEnvironment+"=1",
		"PGH_LIVE_TOKEN_FD=3",
		"PGH_HOST=broker.test",
		"PGH_TOKEN=live-capability",
		"PGH_CONFIG_DIR="+t.TempDir(),
		"GH_REPO="+os.Getenv("PGH_LIVE_REPO"),
		liveTraceEnvironment+"="+traceFile,
		"GH_PAGER=cat",
		"GH_BROWSER=echo",
		"GH_PROMPT_DISABLED=1",
		"CI=1",
		"NO_COLOR=1",
	)
	var stdout, stderr bytes.Buffer
	command.Stdin = strings.NewReader(opts.stdin)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	require.NoError(t, tokenReader.Close())
	require.NoError(t, ctx.Err(), "pgh command timed out: %s", strings.Join(arguments, " "))
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		require.ErrorAs(t, err, &exitError)
		exitCode = exitError.ExitCode()
	}
	trace, readErr := os.ReadFile(traceFile)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		require.NoError(t, readErr)
	}
	requests := strings.FieldsFunc(string(trace), func(r rune) bool { return r == '\n' || r == '\r' })
	return liveCommandResult{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String(), requests: requests}
}

func environmentWithout(environment []string, names ...string) []string {
	blocked := make(map[string]bool, len(names))
	for _, name := range names {
		blocked[name] = true
	}
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if !blocked[name] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func helperArguments(arguments []string) []string {
	for index, argument := range arguments {
		if argument == "--" {
			return arguments[index+1:]
		}
	}
	return nil
}
