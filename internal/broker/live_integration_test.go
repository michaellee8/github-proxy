package broker_test

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type liveAuthority struct {
	session broker.Session
}

func (a liveAuthority) Resolve(_ context.Context, token string) (broker.Session, error) {
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
		Repository: broker.Repository{
			Owner: owner, Name: name, UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
			APIVersion: "2022-11-28", UpstreamToken: token,
		},
		Policy: broker.Policy{Name: "developer", Version: 1},
	}
	handler := broker.NewHandler(broker.HandlerOptions{Authority: liveAuthority{session: session}})

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

func TestLiveGitSmartHTTPReadCompatibility(t *testing.T) {
	token := os.Getenv("PGH_LIVE_TOKEN")
	repositoryName := os.Getenv("PGH_LIVE_REPO")
	if token == "" || repositoryName == "" {
		t.Skip("PGH_LIVE_TOKEN and PGH_LIVE_REPO are not set")
	}
	owner, name, ok := strings.Cut(repositoryName, "/")
	require.True(t, ok, "PGH_LIVE_REPO must be OWNER/NAME")
	handler := broker.NewHandler(broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-git-test",
		Repository:   broker.Repository{Owner: owner, Name: name, UpstreamHost: "github.com", UpstreamToken: token},
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
	handler := broker.NewHandler(broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-git-push-test",
		Repository: broker.Repository{
			Owner: owner, Name: name, DefaultBranch: defaultBranch, UpstreamHost: "github.com", UpstreamToken: token,
		},
		Policy: broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNonDefault}},
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
	handler := broker.NewHandler(broker.HandlerOptions{Authority: liveAuthority{session: broker.Session{
		CapabilityID: "live-git-tag-test",
		Repository: broker.Repository{
			Owner: owner, Name: name, DefaultBranch: defaultBranch, UpstreamHost: "github.com", UpstreamToken: token,
		},
		Policy: broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone, Tags: true}},
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
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer live-capability")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}
