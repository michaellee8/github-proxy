package broker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/cli/cli/v2/internal/brokeradmin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresAdminToBrokerCapabilityLifecycle(t *testing.T) {
	databaseURL := os.Getenv("PGH_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PGH_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, broker.Migrate(ctx, pool))
	_, err = pool.Exec(ctx, `TRUNCATE pgh_audit_events, pgh_capabilities, pgh_repositories, pgh_credentials CASCADE`)
	require.NoError(t, err)

	key, err := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	require.NoError(t, err)
	cipher, err := broker.NewCredentialCipher("primary", map[string][]byte{"primary": key}, rand.Reader)
	require.NoError(t, err)
	store := broker.NewPostgresStore(pool)
	resolver := broker.NewRepositoryResolver(repositoryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"id":1326468465,"owner":{"login":"michaellee8"},"name":"github-proxy","default_branch":"main"}`)),
		}, nil
	}), time.Now, 30*time.Second)
	service := brokeradmin.NewAdminService(store, cipher, resolver, rand.Reader, time.Now)

	credential := brokeradmin.NewCommand(brokeradmin.CommandOptions{Service: service, Stdin: strings.NewReader("github-upstream-token\n"), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	credential.SetArgs([]string{"credential", "put", "--name", "work", "--host", "github.com"})
	require.NoError(t, credential.Execute())

	stdout := &bytes.Buffer{}
	issue := brokeradmin.NewCommand(brokeradmin.CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: stdout, Stderr: &bytes.Buffer{}})
	issue.SetArgs([]string{
		"capability", "issue", "--credential", "work", "--repo", "michaellee8/github-proxy",
		"--expected-repository-id", "1326468465", "--git-push", "non-default",
	})
	require.NoError(t, issue.Execute())
	token := strings.TrimSpace(stdout.String())
	require.True(t, strings.HasPrefix(token, "pgh_pat_"))
	rotate := brokeradmin.NewCommand(brokeradmin.CommandOptions{Service: service, Stdin: strings.NewReader("rotated-github-upstream-token\n"), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	rotate.SetArgs([]string{"credential", "put", "--name", "work", "--host", "github.com"})
	require.NoError(t, rotate.Execute())
	secondCredential := brokeradmin.NewCommand(brokeradmin.CommandOptions{Service: service, Stdin: strings.NewReader("second-upstream-token\n"), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	secondCredential.SetArgs([]string{"credential", "put", "--name", "second", "--host", "github.com"})
	require.NoError(t, secondCredential.Execute())
	_, err = service.Issue(ctx, broker.IssueRequest{
		CredentialName: "second",
		Repository:     broker.RepositoryRequest{Owner: "michaellee8", Name: "github-proxy", ExpectedID: ptrInt64(1326468465)},
		Policy:         broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone}},
	})
	require.NoError(t, err)
	var repositoryRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pgh_repositories WHERE id = $1`, 1326468465).Scan(&repositoryRows))
	assert.Equal(t, 2, repositoryRows, "repository identity must be scoped by upstream credential")

	_, err = service.Issue(ctx, broker.IssueRequest{
		CredentialName: "work",
		Repository:     broker.RepositoryRequest{Owner: "outside", Name: "private", ExpectedID: ptrInt64(1326468466)},
		Policy:         broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone}},
	})
	require.Error(t, err)

	authority := broker.NewCapabilityAuthority(store, cipher, resolver, time.Now)
	limiter, err := broker.NewLocalRequestLimiter(broker.LocalLimitOptions{ReadsPerMinute: 300, MutationsPerMinute: 60, Concurrent: 8})
	require.NoError(t, err)
	handler := broker.NewHandler(broker.HandlerOptions{
		Authority: authority,
		Auditor:   broker.NewRequestAuditor(store, broker.NewJSONAuditEmitter(io.Discard)),
		Limiter:   limiter,
	})
	req := httptest.NewRequest(http.MethodGet, "/_pgh/v1/context", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	assert.Contains(t, res.Body.String(), `"owner":"michaellee8"`)
	assert.NotContains(t, res.Body.String(), "github-upstream-token")
	assert.NotContains(t, res.Body.String(), "rotated-github-upstream-token")
	events, err := store.ListAuditEvents(ctx, broker.AuditQuery{CapabilityID: capabilityIDFromToken(t, token), Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, broker.AuditPhasePreflight, events[1].Phase)
	assert.Equal(t, broker.AuditPhaseResult, events[0].Phase)
	deleted, err := store.DeleteAuditEventsBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)
}

type repositoryRoundTripFunc func(*http.Request) (*http.Response, error)

func (f repositoryRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func ptrInt64(value int64) *int64 {
	return &value
}

func capabilityIDFromToken(t *testing.T, token string) string {
	t.Helper()
	remainder, ok := strings.CutPrefix(token, "pgh_pat_")
	require.True(t, ok)
	selector, _, ok := strings.Cut(remainder, ".")
	require.True(t, ok)
	return "cap_" + selector
}
