package pghcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/stretchr/testify/require"
)

const liveHelperEnvironment = "PGH_LIVE_COMMAND_HELPER"

type liveCommandAuthority struct {
	session broker.Session
}

func (a liveCommandAuthority) Resolve(_ context.Context, token string) (broker.Session, error) {
	if token != "live-capability" {
		return broker.Session{}, errors.New("unexpected capability token")
	}
	return a.session, nil
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
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

func TestLivePGHCommandHelper(t *testing.T) {
	if os.Getenv(liveHelperEnvironment) != "1" {
		t.Skip("live command helper runs only in a subprocess")
	}
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")

	handler := broker.NewHandler(broker.HandlerOptions{Authority: liveCommandAuthority{session: broker.Session{
		CapabilityID: "live-command-test",
		Repository: broker.Repository{
			Owner: owner, Name: name, UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
			APIVersion: "2022-11-28", UpstreamToken: token,
		},
		Policy: broker.Policy{Name: "developer", Version: 1},
	}}})
	os.Args = append([]string{"pgh"}, helperArguments(os.Args)...)
	exitCode := mainWithOptions(mainOptions{HTTPClientWrapper: func(client *http.Client) *http.Client {
		client.Transport = githubCLIAuthTransport{
			base:  handlerTransport{handler: handler},
			token: "live-capability",
		}
		return client
	}})
	os.Exit(exitCode)
}

type liveCommandResult struct {
	exitCode int
	stdout   string
	stderr   string
}

func runLivePGH(t *testing.T, arguments ...string) liveCommandResult {
	t.Helper()
	commandArguments := append([]string{"-test.run=^TestLivePGHCommandHelper$", "--"}, arguments...)
	command := exec.Command(os.Args[0], commandArguments...)
	command.Env = append(os.Environ(),
		liveHelperEnvironment+"=1",
		"PGH_HOST=broker.test",
		"PGH_TOKEN=live-capability",
		"PGH_CONFIG_DIR="+t.TempDir(),
		"GH_PAGER=cat",
		"NO_COLOR=1",
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exitError *exec.ExitError
		require.ErrorAs(t, err, &exitError)
		exitCode = exitError.ExitCode()
	}
	return liveCommandResult{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
}

func helperArguments(arguments []string) []string {
	for index, argument := range arguments {
		if argument == "--" {
			return arguments[index+1:]
		}
	}
	return nil
}
