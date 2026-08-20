package broker_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type liveAuthority struct {
	session broker.Session
}

type liveAuthorityFunc func(context.Context, string, broker.RepositoryFreshness) (broker.Session, error)

func (f liveAuthorityFunc) Resolve(ctx context.Context, token string, freshness broker.RepositoryFreshness) (broker.Session, error) {
	return f(ctx, token, freshness)
}

type liveAuditStore struct{}

type liveRoundTripFunc func(*http.Request) (*http.Response, error)

func (f liveRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func (liveAuditStore) RecordAuditEvent(context.Context, broker.AuditEvent) error { return nil }

func newLiveBrokerHandler(t *testing.T, options broker.HandlerOptions) http.Handler {
	t.Helper()
	limiter, err := broker.NewLocalRequestLimiter(broker.LocalLimitOptions{ReadsPerMinute: 10_000, MutationsPerMinute: 10_000, Concurrent: 100})
	require.NoError(t, err)
	options.Auditor = broker.NewRequestAuditor(liveAuditStore{}, broker.NewJSONAuditEmitter(io.Discard))
	options.Limiter = limiter
	return broker.NewHandler(options)
}

func (a liveAuthority) Resolve(_ context.Context, token string, _ broker.RepositoryFreshness) (broker.Session, error) {
	if token != "live-capability" {
		return broker.Session{}, errors.New("unexpected capability token")
	}
	return a.session, nil
}

func TestLiveGitHubReadCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	session := broker.Session{
		CapabilityID: "live-read-test",
		Repository:   broker.Repository{Owner: owner, Name: name},
		Upstream:     broker.UpstreamAccess{Host: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: token},
		Policy:       broker.Policy{Name: "developer", Version: 1},
	}
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{Authority: liveAuthority{session: session}})

	t.Run("REST repository metadata", func(t *testing.T) {
		res := brokerRequest(t, handler, http.MethodGet, "/api/v3/repos/"+owner+"/"+name, "")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		assert.Contains(t, res.Body.String(), `"full_name":"`+owner+`/`+name+`"`)
	})

	t.Run("REST issue list", func(t *testing.T) {
		res := brokerRequest(t, handler, http.MethodGet, "/api/v3/repos/"+owner+"/"+name+"/issues?per_page=1", "")
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	})

	t.Run("GraphQL repository family", func(t *testing.T) {
		body := `{"query":"query RepositoryInfo($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { nameWithOwner } }","variables":{"owner":"outside","name":"private"}}`
		res := brokerRequest(t, handler, http.MethodPost, "/api/graphql", body)
		require.Equal(t, http.StatusOK, res.Code, res.Body.String())
		assert.Contains(t, res.Body.String(), `"nameWithOwner":"`+owner+`/`+name+`"`)
	})
}

func TestLiveCapabilityPolicyReplacementUsesSameToken(t *testing.T) {
	requireLiveWriteOptIn(t)
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("PGH_LIVE_TOKEN")
	}
	if token == "" {
		t.Skip("GH_TOKEN or PGH_LIVE_TOKEN is not set")
	}
	const repositoryName = "michaellee8/github-proxy-test-repo"
	const owner = "michaellee8"
	const name = "github-proxy-test-repo"

	var mu sync.RWMutex
	policy := broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone}}
	revision := int64(1)
	authority := liveAuthorityFunc(func(_ context.Context, capability string, _ broker.RepositoryFreshness) (broker.Session, error) {
		if capability != "live-capability" {
			return broker.Session{}, errors.New("unexpected capability token")
		}
		mu.RLock()
		defer mu.RUnlock()
		return broker.Session{
			CapabilityID: "live-policy-replacement", PolicyRevision: revision,
			Repository: broker.Repository{Owner: owner, Name: name, DefaultBranch: "main"},
			Upstream: broker.UpstreamAccess{
				Host: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: token,
			},
			Policy: policy,
		}, nil
	})
	upstreamCalls := 0
	transport := liveRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		upstreamCalls++
		return http.DefaultTransport.RoundTrip(request)
	})
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{Authority: authority, Transport: transport})
	requestPath := "/api/v3/repos/" + repositoryName + "/actions/runs/0/rerun"

	denied := brokerRequest(t, handler, http.MethodPost, requestPath, "")
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
	require.Contains(t, denied.Body.String(), "PGH_POLICY_DENIED")
	require.Equal(t, 0, upstreamCalls)

	mu.Lock()
	policy = broker.Policy{
		Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
		Git: broker.GitPolicy{Push: broker.GitPushNone},
	}
	revision = 2
	mu.Unlock()
	forwarded := brokerRequest(t, handler, http.MethodPost, requestPath, "")
	require.Equal(t, http.StatusNotFound, forwarded.Code, forwarded.Body.String())
	require.Equal(t, 1, upstreamCalls)

	mu.Lock()
	policy = broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone}}
	revision = 3
	mu.Unlock()
	deniedAgain := brokerRequest(t, handler, http.MethodPost, requestPath, "")
	require.Equal(t, http.StatusForbidden, deniedAgain.Code, deniedAgain.Body.String())
	require.Contains(t, deniedAgain.Body.String(), "PGH_POLICY_DENIED")
	require.Equal(t, 1, upstreamCalls)
}

func TestLiveGitSmartHTTPReadCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-git-test",
		Repository:   broker.Repository{Owner: owner, Name: name},
		Upstream:     broker.UpstreamAccess{Host: "github.com", Token: token},
		Policy:       broker.Policy{Name: "developer", Version: 1},
	}}})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	certificateFile := t.TempDir() + "/broker-ca.pem"
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(certificateFile, certificate, 0o600))
	authorization := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:live-capability"))
	gitEnvironment := append(os.Environ(),
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http.sslCAInfo",
		"GIT_CONFIG_VALUE_0="+certificateFile,
		"GIT_CONFIG_KEY_1=http.extraHeader",
		"GIT_CONFIG_VALUE_1="+authorization,
	)
	repositoryURL := server.URL + "/" + owner + "/" + name + ".git"

	t.Run("ls-remote", func(t *testing.T) {
		command := exec.Command("git", "ls-remote", repositoryURL, "HEAD")
		command.Env = gitEnvironment
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
	})

	t.Run("clone and fetch", func(t *testing.T) {
		cloneDirectory := t.TempDir() + "/repository"
		clone := exec.Command("git", "clone", "--depth=1", "--no-checkout", repositoryURL, cloneDirectory)
		clone.Env = gitEnvironment
		output, err := clone.CombinedOutput()
		require.NoError(t, err, string(output))

		fetch := exec.Command("git", "-C", cloneDirectory, "fetch", "origin")
		fetch.Env = gitEnvironment
		output, err = fetch.CombinedOutput()
		require.NoError(t, err, string(output))
	})
}

func TestLiveGitSmartHTTPNonDefaultPushCompatibility(t *testing.T) {
	requireLiveWriteOptIn(t)
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	defaultBranch := os.Getenv("PGH_LIVE_DEFAULT_BRANCH")
	if token == "" || repositoryName == "" || defaultBranch == "" {
		t.Skip("PGH_LIVE_TOKEN, PGH_LIVE_REPO, and PGH_LIVE_DEFAULT_BRANCH are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	requireLiveGitHubRef(t, token, repositoryName, "heads/"+defaultBranch)
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-git-push-test",
		Repository:   broker.Repository{Owner: owner, Name: name, DefaultBranch: defaultBranch},
		Upstream:     broker.UpstreamAccess{Host: "github.com", Token: token},
		Policy:       broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNonDefault}},
	}}})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	certificateFile := t.TempDir() + "/broker-ca.pem"
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(certificateFile, certificate, 0o600))
	authorization := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:live-capability"))
	gitEnvironment := append(os.Environ(),
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http.sslCAInfo",
		"GIT_CONFIG_VALUE_0="+certificateFile,
		"GIT_CONFIG_KEY_1=http.extraHeader",
		"GIT_CONFIG_VALUE_1="+authorization,
	)
	repositoryURL := server.URL + "/" + owner + "/" + name + ".git"
	cloneDirectory := t.TempDir() + "/repository"
	clone := exec.Command("git", "clone", "--depth=1", repositoryURL, cloneDirectory)
	clone.Env = gitEnvironment
	output, err := clone.CombinedOutput()
	require.NoError(t, err, string(output))

	branch := fmt.Sprintf("pgh-live-test-%d", time.Now().UnixNano())
	checkout := exec.Command("git", "-C", cloneDirectory, "checkout", "-b", branch)
	checkout.Env = gitEnvironment
	output, err = checkout.CombinedOutput()
	require.NoError(t, err, string(output))
	commit := exec.Command("git", "-C", cloneDirectory, "-c", "user.name=pgh live test", "-c", "user.email=pgh-live@example.invalid", "commit", "--allow-empty", "-m", "pgh live Git compatibility")
	commit.Env = gitEnvironment
	output, err = commit.CombinedOutput()
	require.NoError(t, err, string(output))

	branchCreated := false
	defer func() {
		if branchCreated {
			deleteLiveGitHubRef(t, token, repositoryName, "heads/"+branch)
		}
	}()
	push := exec.Command("git", "-C", cloneDirectory, "push", "origin", "HEAD:refs/heads/"+branch)
	push.Env = gitEnvironment
	output, err = push.CombinedOutput()
	require.NoError(t, err, string(output))
	branchCreated = true

	verify := exec.Command("git", "ls-remote", repositoryURL, "refs/heads/"+branch)
	verify.Env = gitEnvironment
	output, err = verify.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "refs/heads/"+branch)

	deleteThroughBroker := exec.Command("git", "-C", cloneDirectory, "push", "origin", ":refs/heads/"+branch)
	deleteThroughBroker.Env = gitEnvironment
	output, err = deleteThroughBroker.CombinedOutput()
	require.Error(t, err, string(output))
}

func TestLiveGitSmartHTTPTagPushCompatibility(t *testing.T) {
	requireLiveWriteOptIn(t)
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	defaultBranch := os.Getenv("PGH_LIVE_DEFAULT_BRANCH")
	if token == "" || repositoryName == "" || defaultBranch == "" {
		t.Skip("PGH_LIVE_TOKEN, PGH_LIVE_REPO, and PGH_LIVE_DEFAULT_BRANCH are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	requireLiveGitHubRef(t, token, repositoryName, "heads/"+defaultBranch)
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-git-tag-test",
		Repository:   broker.Repository{Owner: owner, Name: name, DefaultBranch: defaultBranch},
		Upstream:     broker.UpstreamAccess{Host: "github.com", Token: token},
		Policy:       broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone, Tags: true}},
	}}})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	certificateFile := t.TempDir() + "/broker-ca.pem"
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	require.NoError(t, os.WriteFile(certificateFile, certificate, 0o600))
	authorization := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:live-capability"))
	gitEnvironment := append(os.Environ(),
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http.sslCAInfo",
		"GIT_CONFIG_VALUE_0="+certificateFile,
		"GIT_CONFIG_KEY_1=http.extraHeader",
		"GIT_CONFIG_VALUE_1="+authorization,
	)
	repositoryURL := server.URL + "/" + owner + "/" + name + ".git"
	cloneDirectory := t.TempDir() + "/repository"
	clone := exec.Command("git", "clone", "--depth=1", repositoryURL, cloneDirectory)
	clone.Env = gitEnvironment
	output, err := clone.CombinedOutput()
	require.NoError(t, err, string(output))

	tag := fmt.Sprintf("pgh-live-test-%d", time.Now().UnixNano())
	createTag := exec.Command("git", "-C", cloneDirectory, "tag", tag)
	createTag.Env = gitEnvironment
	output, err = createTag.CombinedOutput()
	require.NoError(t, err, string(output))

	tagCreated := false
	defer func() {
		if tagCreated {
			deleteLiveGitHubRef(t, token, repositoryName, "tags/"+tag)
		}
	}()
	push := exec.Command("git", "-C", cloneDirectory, "push", "origin", "refs/tags/"+tag)
	push.Env = gitEnvironment
	output, err = push.CombinedOutput()
	require.NoError(t, err, string(output))
	tagCreated = true

	verify := exec.Command("git", "ls-remote", repositoryURL, "refs/tags/"+tag)
	verify.Env = gitEnvironment
	output, err = verify.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "refs/tags/"+tag)

	deleteThroughBroker := exec.Command("git", "-C", cloneDirectory, "push", "origin", ":refs/tags/"+tag)
	deleteThroughBroker.Env = gitEnvironment
	output, err = deleteThroughBroker.CombinedOutput()
	require.Error(t, err, string(output))
}

func TestLiveRESTMutationCompatibility(t *testing.T) {
	requireLiveWriteOptIn(t)
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	metadata := liveGitHubJSON(t, token, http.MethodGet, "repos/"+repositoryName, "", http.StatusOK)
	repositoryID, ok := metadata["id"].(float64)
	require.True(t, ok)
	defaultBranch, ok := metadata["default_branch"].(string)
	require.True(t, ok)

	policy := broker.Policy{
		Name: "developer", Version: 1,
		Grants: map[string]bool{
			"contents.write": true, "objects.delete": true, "releases.write": true,
		},
		Git: broker.GitPolicy{Push: broker.GitPushAll, Tags: true},
	}
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-rest-mutation-test",
		Repository: broker.Repository{
			ID: int64(repositoryID), Owner: owner, Name: name, DefaultBranch: defaultBranch,
		},
		Upstream: broker.UpstreamAccess{Host: "github.com", APIBaseURL: "https://api.github.com", APIVersion: "2022-11-28", Token: token},
		Policy:   policy,
	}}})
	prefix := fmt.Sprintf("pgh-live-%d", time.Now().UnixNano())
	labelName := prefix + "-label"

	liveBrokerJSON(t, handler, http.MethodPost, "/api/v3/repos/"+repositoryName+"/labels", `{"name":"`+labelName+`","color":"1d76db"}`, http.StatusCreated)
	defer deleteLiveGitHubResource(t, token, "repos/"+repositoryName+"/labels/"+labelName)

	milestone := liveBrokerJSON(t, handler, http.MethodPost, "/api/v3/repos/"+repositoryName+"/milestones", `{"title":"`+prefix+`"}`, http.StatusCreated)
	milestoneNumber := jsonNumber(t, milestone, "number")
	defer deleteLiveGitHubResource(t, token, fmt.Sprintf("repos/%s/milestones/%d", repositoryName, milestoneNumber))

	issue := liveBrokerJSON(t, handler, http.MethodPost, "/api/v3/repos/"+repositoryName+"/issues", fmt.Sprintf(`{"title":"%s issue","body":"temporary Broker mutation test","labels":["%s"],"milestone":%d}`, prefix, labelName, milestoneNumber), http.StatusCreated)
	issueNumber := jsonNumber(t, issue, "number")
	defer closeLiveGitHubIssue(t, token, repositoryName, issueNumber)

	comment := liveBrokerJSON(t, handler, http.MethodPost, fmt.Sprintf("/api/v3/repos/%s/issues/%d/comments", repositoryName, issueNumber), `{"body":"temporary Broker comment"}`, http.StatusCreated)
	commentID := jsonNumber(t, comment, "id")
	liveBrokerJSON(t, handler, http.MethodPatch, fmt.Sprintf("/api/v3/repos/%s/issues/comments/%d", repositoryName, commentID), `{"body":"updated temporary Broker comment"}`, http.StatusOK)

	reaction := liveBrokerJSON(t, handler, http.MethodPost, fmt.Sprintf("/api/v3/repos/%s/issues/%d/reactions", repositoryName, issueNumber), `{"content":"+1"}`, http.StatusCreated)
	reactionID := jsonNumber(t, reaction, "id")
	liveBrokerJSON(t, handler, http.MethodDelete, fmt.Sprintf("/api/v3/repos/%s/issues/%d/reactions/%d", repositoryName, issueNumber, reactionID), "", http.StatusNoContent)
	liveBrokerJSON(t, handler, http.MethodDelete, fmt.Sprintf("/api/v3/repos/%s/issues/comments/%d", repositoryName, commentID), "", http.StatusNoContent)
	liveBrokerJSON(t, handler, http.MethodPatch, fmt.Sprintf("/api/v3/repos/%s/issues/%d", repositoryName, issueNumber), `{"state":"closed"}`, http.StatusOK)

	defaultRef := ensureLiveDefaultBranch(t, handler, token, repositoryName, defaultBranch)
	object, ok := defaultRef["object"].(map[string]any)
	require.True(t, ok)
	sha, ok := object["sha"].(string)
	require.True(t, ok)
	branch := prefix + "-branch"
	liveBrokerJSON(t, handler, http.MethodPost, "/api/v3/repos/"+repositoryName+"/git/refs", fmt.Sprintf(`{"ref":"refs/heads/%s","sha":"%s"}`, branch, sha), http.StatusCreated)
	defer deleteLiveGitHubRef(t, token, repositoryName, "heads/"+branch)
	branchContent := base64.StdEncoding.EncodeToString([]byte("temporary Broker mutation test\n"))
	liveBrokerJSON(t, handler, http.MethodPut, "/api/v3/repos/"+repositoryName+"/contents/"+prefix+".txt", fmt.Sprintf(`{"message":"Add temporary Broker test content","content":"%s","branch":"%s"}`, branchContent, branch), http.StatusCreated)

	pull := liveBrokerJSON(t, handler, http.MethodPost, "/api/v3/repos/"+repositoryName+"/pulls", fmt.Sprintf(`{"title":"%s pull","head":"%s","base":"%s","body":"temporary Broker mutation test"}`, prefix, branch, defaultBranch), http.StatusCreated)
	pullNumber := jsonNumber(t, pull, "number")
	liveBrokerJSON(t, handler, http.MethodPatch, fmt.Sprintf("/api/v3/repos/%s/pulls/%d", repositoryName, pullNumber), `{"state":"closed"}`, http.StatusOK)

	tag := prefix + "-tag"
	release := liveBrokerJSON(t, handler, http.MethodPost, "/api/v3/repos/"+repositoryName+"/releases", fmt.Sprintf(`{"tag_name":"%s","target_commitish":"%s","name":"%s","draft":true}`, tag, branch, prefix), http.StatusCreated)
	releaseID := jsonNumber(t, release, "id")
	liveBrokerJSON(t, handler, http.MethodDelete, fmt.Sprintf("/api/v3/repos/%s/releases/%d", repositoryName, releaseID), "", http.StatusNoContent)
	deleteLiveGitHubRef(t, token, repositoryName, "tags/"+tag)

	liveBrokerJSON(t, handler, http.MethodDelete, fmt.Sprintf("/api/v3/repos/%s/milestones/%d", repositoryName, milestoneNumber), "", http.StatusNoContent)
	liveBrokerJSON(t, handler, http.MethodDelete, "/api/v3/repos/"+repositoryName+"/labels/"+labelName, "", http.StatusNoContent)
}

func ensureLiveDefaultBranch(t *testing.T, handler http.Handler, token, repositoryName, defaultBranch string) map[string]any {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/repos/"+repositoryName+"/git/ref/heads/"+defaultBranch, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	if response.StatusCode == http.StatusOK {
		var value map[string]any
		require.NoError(t, json.Unmarshal(data, &value))
		return value
	}
	require.Equal(t, http.StatusConflict, response.StatusCode, string(data))
	content := base64.StdEncoding.EncodeToString([]byte("# GitHub Proxy Test Repository\n"))
	liveBrokerJSON(t, handler, http.MethodPut, "/api/v3/repos/"+repositoryName+"/contents/README.md", fmt.Sprintf(`{"message":"Initialize Broker test fixture","content":"%s","branch":"%s"}`, content, defaultBranch), http.StatusCreated)
	return liveGitHubJSON(t, token, http.MethodGet, "repos/"+repositoryName+"/git/ref/heads/"+defaultBranch, "", http.StatusOK)
}

func liveBrokerJSON(t *testing.T, handler http.Handler, method, requestPath, body string, status int) map[string]any {
	t.Helper()
	response := brokerRequest(t, handler, method, requestPath, body)
	require.Equal(t, status, response.Code, response.Body.String())
	if response.Body.Len() == 0 {
		return nil
	}
	var value map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &value), response.Body.String())
	return value
}

func liveGitHubJSON(t *testing.T, token, method, resourcePath, body string, status int) map[string]any {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, "https://api.github.com/"+resourcePath, reader)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	require.NoError(t, err)
	require.Equal(t, status, response.StatusCode, string(data))
	if len(data) == 0 {
		return nil
	}
	var value map[string]any
	require.NoError(t, json.Unmarshal(data, &value))
	return value
}

func jsonNumber(t *testing.T, value map[string]any, field string) int64 {
	t.Helper()
	number, ok := value[field].(float64)
	require.True(t, ok, "response field %s must be numeric", field)
	return int64(number)
}

func deleteLiveGitHubResource(t *testing.T, token, resourcePath string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, "https://api.github.com/"+path.Clean(resourcePath), nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Errorf("delete temporary GitHub resource: %v", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Errorf("delete temporary GitHub resource: status %d: %s", response.StatusCode, data)
	}
}

func closeLiveGitHubIssue(t *testing.T, token, repositoryName string, number int64) {
	t.Helper()
	liveGitHubJSON(t, token, http.MethodPatch, fmt.Sprintf("repos/%s/issues/%d", repositoryName, number), `{"state":"closed"}`, http.StatusOK)
}

func requireLiveWriteOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv("PGH_LIVE_ALLOW_WRITES") != "1" {
		t.Skip("set PGH_LIVE_ALLOW_WRITES=1 to allow temporary refs on the live repository")
	}
}

func deleteLiveGitHubRef(t *testing.T, token, repositoryName, ref string) {
	t.Helper()
	endpoint := "https://api.github.com/repos/" + repositoryName + "/git/refs/" + ref
	request, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, endpoint, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusNotFound ||
		(response.StatusCode == http.StatusUnprocessableEntity && strings.Contains(string(body), "Reference does not exist")) {
		return
	}
	t.Errorf("delete temporary GitHub ref: status %d: %s", response.StatusCode, body)
}

func requireLiveGitHubRef(t *testing.T, token, repositoryName, ref string) {
	t.Helper()
	endpoint := "https://api.github.com/repos/" + repositoryName + "/git/ref/" + ref
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusConflict {
		t.Skip("live Git write tests require an existing default branch so temporary refs can be deleted safely")
	}
	require.Equal(t, http.StatusOK, response.StatusCode)
}

func brokerRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	return brokerRequestWithCapability(t, handler, "live-capability", method, path, body)
}

func brokerRequestWithCapability(t *testing.T, handler http.Handler, capability, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+capability)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}
