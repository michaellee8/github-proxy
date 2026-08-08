package broker_test

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

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
	command := exec.Command("git", "ls-remote", server.URL+"/"+owner+"/"+name+".git", "HEAD")
	command.Env = append(os.Environ(),
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http.sslCAInfo",
		"GIT_CONFIG_VALUE_0="+certificateFile,
		"GIT_CONFIG_KEY_1=http.extraHeader",
		"GIT_CONFIG_VALUE_1="+authorization,
	)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
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
