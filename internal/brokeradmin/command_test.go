package brokeradmin

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeService struct {
	credential PutCredentialRequest
	issue      broker.IssueRequest
	revokedID  string
	auditQuery broker.AuditQuery
	audit      []broker.AuditEvent
}

func (s *fakeService) PutCredential(_ context.Context, request PutCredentialRequest) error {
	s.credential = request
	return nil
}

func (s *fakeService) Issue(_ context.Context, request broker.IssueRequest) (broker.IssuedCapability, error) {
	s.issue = request
	return broker.IssuedCapability{ID: "cap-1", Token: "pgh_pat_selector.secret"}, nil
}

func (s *fakeService) Revoke(_ context.Context, id string) error {
	s.revokedID = id
	return nil
}

func (s *fakeService) ListAuditEvents(_ context.Context, query broker.AuditQuery) ([]broker.AuditEvent, error) {
	s.auditQuery = query
	return s.audit, nil
}

func TestCredentialPutReadsPATFromStdinWithoutEchoingIt(t *testing.T) {
	service := &fakeService{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command := NewCommand(CommandOptions{Service: service, Stdin: bytes.NewBufferString("upstream-pat\n"), Stdout: stdout, Stderr: stderr})
	command.SetArgs([]string{"credential", "put", "--name", "work", "--host", "github.com"})

	err := command.Execute()

	require.NoError(t, err, stderr.String())
	assert.Equal(t, "work", service.credential.Name)
	assert.Equal(t, "github.com", service.credential.UpstreamHost)
	assert.Equal(t, "https://api.github.com", service.credential.APIBaseURL)
	assert.Equal(t, "2022-11-28", service.credential.APIVersion)
	assert.Equal(t, broker.RepositoryResolutionNumeric, service.credential.RepositoryResolution)
	assert.Equal(t, "upstream-pat", string(service.credential.Token))
	assert.NotContains(t, stdout.String(), "upstream-pat")
}

func TestCapabilityIssuePrintsOneTimeTokenAndBindsRepository(t *testing.T) {
	service := &fakeService{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	command := NewCommand(CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: stdout, Stderr: stderr, Now: func() time.Time { return now }})
	command.SetArgs([]string{
		"capability", "issue",
		"--credential", "work",
		"--repo", "michaellee8/github-proxy",
		"--expected-repository-id", "1326468465",
		"--grant", "actions.write",
		"--git-push", "non-default",
		"--git-tags",
		"--expires-in", "2h",
	})

	err := command.Execute()

	require.NoError(t, err, stderr.String())
	assert.Equal(t, "pgh_pat_selector.secret\n", stdout.String())
	assert.Equal(t, "work", service.issue.CredentialName)
	require.NotNil(t, service.issue.Repository.ExpectedID)
	assert.Equal(t, int64(1326468465), *service.issue.Repository.ExpectedID)
	assert.Equal(t, "michaellee8", service.issue.Repository.Owner)
	assert.Equal(t, "github-proxy", service.issue.Repository.Name)
	assert.Equal(t, broker.Policy{
		Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
		Git: broker.GitPolicy{Push: broker.GitPushNonDefault, Tags: true},
	}, service.issue.Policy)
	require.NotNil(t, service.issue.ExpiresAt)
	assert.Equal(t, now.Add(2*time.Hour), *service.issue.ExpiresAt)
}

func TestCapabilityRevokeUsesOpaqueID(t *testing.T) {
	service := &fakeService{}
	command := NewCommand(CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	command.SetArgs([]string{"capability", "revoke", "cap_123"})

	require.NoError(t, command.Execute())
	assert.Equal(t, "cap_123", service.revokedID)
}

func TestAuditListPrintsBoundedJSONEvents(t *testing.T) {
	service := &fakeService{audit: []broker.AuditEvent{{
		OccurredAt: time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC), Event: "broker_request",
		RequestID: "request-1", Phase: broker.AuditPhaseResult, CapabilityID: "cap_1", RepositoryID: 99,
		Method: "GET", Path: "/api/v3/repos/owner/repo", Status: 200,
	}}}
	stdout := &bytes.Buffer{}
	command := NewCommand(CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: stdout, Stderr: &bytes.Buffer{}})
	command.SetArgs([]string{"audit", "list", "--capability", "cap_1", "--repository-id", "99", "--since", "2026-08-09T12:00:00Z", "--limit", "25"})

	require.NoError(t, command.Execute())

	assert.Equal(t, "cap_1", service.auditQuery.CapabilityID)
	require.NotNil(t, service.auditQuery.RepositoryID)
	assert.Equal(t, int64(99), *service.auditQuery.RepositoryID)
	require.NotNil(t, service.auditQuery.Since)
	assert.Equal(t, 25, service.auditQuery.Limit)
	assert.JSONEq(t, `{"time":"2026-08-10T12:00:00Z","event":"broker_request","request_id":"request-1","phase":"result","capability_id":"cap_1","repository_id":99,"method":"GET","path":"/api/v3/repos/owner/repo","mutation":false,"status":200}`, stdout.String())
}

func TestAuditListCommandCuratesOptionsForInjectedRunner(t *testing.T) {
	var got *auditListOptions
	command := newAuditListCommand(&fakeService{}, func(opts *auditListOptions) error {
		got = opts
		return nil
	})
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"--capability", "cap_1", "--repository-id", "99", "--since", "2026-08-09T12:00:00Z", "--limit", "25"})

	require.NoError(t, command.Execute())

	require.NotNil(t, got)
	assert.Equal(t, "cap_1", got.capabilityID)
	assert.Equal(t, int64(99), got.repositoryID)
	assert.Equal(t, "2026-08-09T12:00:00Z", got.sinceValue)
	assert.Equal(t, 25, got.limit)
}

func TestAuditListRunRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*auditListOptions)
		message string
	}{
		{name: "capability ID", mutate: func(opts *auditListOptions) { opts.capabilityID = "selector" }, message: "capability must be an opaque cap_ ID"},
		{name: "repository ID", mutate: func(opts *auditListOptions) { opts.repositoryID = -1 }, message: "repository-id must be positive"},
		{name: "limit", mutate: func(opts *auditListOptions) { opts.limit = 1001 }, message: "limit must be between 1 and 1000"},
		{name: "since", mutate: func(opts *auditListOptions) { opts.sinceValue = "yesterday" }, message: "since must be an RFC3339 timestamp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &auditListOptions{service: &fakeService{}, context: context.Background(), stdout: &bytes.Buffer{}, limit: 100}
			tt.mutate(opts)

			err := auditListRun(opts)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.message)
		})
	}
}
