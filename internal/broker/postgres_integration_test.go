package broker_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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
	_, err = pool.Exec(ctx, `TRUNCATE pgh_audit_events, pgh_capability_policy_events, pgh_capabilities, pgh_repositories, pgh_credentials CASCADE`)
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
	capabilityID := capabilityIDFromToken(t, token)
	initial, err := service.ShowPolicy(ctx, capabilityID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), initial.Policy.Revision)
	assert.Equal(t, broker.CapabilityStateActive, initial.State)

	replaced, err := service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
		CapabilityID: capabilityID,
		Policy: broker.Policy{
			Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
			Git: broker.GitPolicy{Push: broker.GitPushAll, Tags: true},
		},
		Reason: "enable workflow maintenance", Actor: "integration-test",
	})
	require.NoError(t, err)
	assert.True(t, replaced.Changed)
	assert.Equal(t, int64(2), replaced.Capability.Policy.Revision)

	noChange, err := service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
		CapabilityID: capabilityID, Policy: replaced.Capability.Policy.Policy(), Reason: "same policy",
	})
	require.NoError(t, err)
	assert.False(t, noChange.Changed)
	assert.Equal(t, int64(2), noChange.Capability.Policy.Revision)

	concurrentPolicies := []broker.Policy{
		{Name: "developer", Version: 1, Grants: map[string]bool{"checks.write": true}, Git: broker.GitPolicy{Push: broker.GitPushNone}},
		{Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true}, Git: broker.GitPolicy{Push: broker.GitPushNonDefault}},
	}
	var wg sync.WaitGroup
	errorsByUpdate := make(chan error, len(concurrentPolicies))
	for index, policy := range concurrentPolicies {
		wg.Add(1)
		go func(index int, policy broker.Policy) {
			defer wg.Done()
			_, err := service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
				CapabilityID: capabilityID, Policy: policy, Reason: fmt.Sprintf("concurrent update %d", index),
			})
			errorsByUpdate <- err
		}(index, policy)
	}
	wg.Wait()
	close(errorsByUpdate)
	for updateErr := range errorsByUpdate {
		require.NoError(t, updateErr)
	}
	current, err := service.ShowPolicy(ctx, capabilityID)
	require.NoError(t, err)
	assert.Equal(t, int64(4), current.Policy.Revision)

	failedPolicy := broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushAll}}
	_, err = store.ReplaceCapabilityPolicy(ctx, broker.CapabilityPolicyReplacement{
		CapabilityID: capabilityID, Policy: failedPolicy, Reason: strings.Repeat("x", 513),
	})
	require.Error(t, err)
	afterRollback, err := service.ShowPolicy(ctx, capabilityID)
	require.NoError(t, err)
	assert.Equal(t, int64(4), afterRollback.Policy.Revision)

	history, err := service.ListPolicyHistory(ctx, broker.CapabilityPolicyHistoryQuery{CapabilityID: capabilityID, Limit: 10})
	require.NoError(t, err)
	require.Len(t, history, 3)
	assert.Equal(t, int64(4), history[0].AfterRevision)
	assert.Equal(t, int64(1), history[2].BeforeRevision)
	assert.False(t, history[0].OccurredAt.Before(history[1].OccurredAt))
	assert.Equal(t, current.PolicyUpdatedAt, history[0].OccurredAt)
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
	events, err := store.ListAuditEvents(ctx, broker.AuditQuery{CapabilityID: capabilityID, Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, broker.AuditPhasePreflight, events[1].Phase)
	assert.Equal(t, broker.AuditPhaseResult, events[0].Phase)
	assert.Equal(t, int64(4), events[0].PolicyRevision)
	assert.Equal(t, int64(4), events[1].PolicyRevision)
	deleted, err := store.DeleteAuditEventsBefore(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)
	history, err = service.ListPolicyHistory(ctx, broker.CapabilityPolicyHistoryQuery{CapabilityID: capabilityID, Limit: 10})
	require.NoError(t, err)
	assert.Len(t, history, 3, "request-audit retention must not delete permanent policy history")
	_, err = pool.Exec(ctx, `UPDATE pgh_capabilities SET expires_at = $2 WHERE id = $1`, capabilityID, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	_, err = service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
		CapabilityID: capabilityID, Policy: failedPolicy, Reason: "must remain expired",
	})
	require.ErrorIs(t, err, broker.ErrCapabilityExpired)
	_, err = pool.Exec(ctx, `UPDATE pgh_capabilities SET expires_at = NULL WHERE id = $1`, capabilityID)
	require.NoError(t, err)

	require.NoError(t, service.Revoke(ctx, capabilityID))
	_, err = service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
		CapabilityID: capabilityID, Policy: failedPolicy, Reason: "must remain revoked",
	})
	require.ErrorIs(t, err, broker.ErrCapabilityRevoked)
}

func TestPostgresLiveCapabilityPolicyReplacement(t *testing.T) {
	requireLiveWriteOptIn(t)
	databaseURL := os.Getenv("PGH_TEST_DATABASE_URL")
	upstreamToken := os.Getenv("GH_TOKEN")
	if upstreamToken == "" {
		upstreamToken = os.Getenv("PGH_LIVE_TOKEN")
	}
	if databaseURL == "" || upstreamToken == "" {
		t.Skip("PGH_TEST_DATABASE_URL and GH_TOKEN or PGH_LIVE_TOKEN are required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, broker.Migrate(ctx, pool))
	_, err = pool.Exec(ctx, `TRUNCATE pgh_audit_events, pgh_capability_policy_events, pgh_capabilities, pgh_repositories, pgh_credentials CASCADE`)
	require.NoError(t, err)

	key, err := base64.StdEncoding.DecodeString("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=")
	require.NoError(t, err)
	cipher, err := broker.NewCredentialCipher("primary", map[string][]byte{"primary": key}, rand.Reader)
	require.NoError(t, err)
	store := broker.NewPostgresStore(pool)
	resolver := broker.NewRepositoryResolver(http.DefaultTransport, time.Now, 30*time.Second)
	service := brokeradmin.NewAdminService(store, cipher, resolver, rand.Reader, time.Now)
	require.NoError(t, service.PutCredential(ctx, brokeradmin.PutCredentialRequest{
		Name: "live", UpstreamHost: "github.com", APIBaseURL: "https://api.github.com",
		APIVersion: "2022-11-28", RepositoryResolution: broker.RepositoryResolutionNumeric,
		Token: []byte(upstreamToken),
	}))
	issued, err := service.Issue(ctx, broker.IssueRequest{
		CredentialName: "live",
		Repository:     broker.RepositoryRequest{Owner: "michaellee8", Name: "github-proxy-test-repo"},
		Policy:         broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone}},
	})
	require.NoError(t, err)
	handler := newLiveBrokerHandler(t, broker.HandlerOptions{
		Authority: broker.NewCapabilityAuthority(store, cipher, resolver, time.Now),
	})
	requestPath := "/api/v3/repos/michaellee8/github-proxy-test-repo/actions/runs/0/rerun"

	denied := brokerRequestWithCapability(t, handler, issued.Token, http.MethodPost, requestPath, "")
	require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
	require.Contains(t, denied.Body.String(), "PGH_POLICY_DENIED")

	broadened, err := service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
		CapabilityID: issued.ID,
		Policy: broker.Policy{
			Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
			Git: broker.GitPolicy{Push: broker.GitPushNone},
		},
		Reason: "verify live same-token broadening", Actor: "integration-test",
	})
	require.NoError(t, err)
	require.Equal(t, int64(2), broadened.Capability.Policy.Revision)
	forwarded := brokerRequestWithCapability(t, handler, issued.Token, http.MethodPost, requestPath, "")
	require.Equal(t, http.StatusNotFound, forwarded.Code, forwarded.Body.String())

	narrowed, err := service.ReplacePolicy(ctx, brokeradmin.ReplacePolicyRequest{
		CapabilityID: issued.ID,
		Policy: broker.Policy{
			Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone},
		},
		Reason: "verify live same-token narrowing", Actor: "integration-test",
	})
	require.NoError(t, err)
	require.Equal(t, int64(3), narrowed.Capability.Policy.Revision)
	deniedAgain := brokerRequestWithCapability(t, handler, issued.Token, http.MethodPost, requestPath, "")
	require.Equal(t, http.StatusForbidden, deniedAgain.Code, deniedAgain.Body.String())
	require.Contains(t, deniedAgain.Body.String(), "PGH_POLICY_DENIED")

	history, err := service.ListPolicyHistory(ctx, broker.CapabilityPolicyHistoryQuery{CapabilityID: issued.ID, Limit: 10})
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, int64(3), history[0].AfterRevision)
	assert.Equal(t, int64(2), history[1].AfterRevision)
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
