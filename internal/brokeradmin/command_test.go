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
	credential         PutCredentialRequest
	issue              broker.IssueRequest
	revokedID          string
	auditQuery         broker.AuditQuery
	audit              []broker.AuditEvent
	policyView         broker.CapabilityPolicyView
	policyReplacement  ReplacePolicyRequest
	policyResult       broker.CapabilityPolicyReplacementResult
	policyHistoryQuery broker.CapabilityPolicyHistoryQuery
	policyHistory      []broker.CapabilityPolicyEvent
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

func (s *fakeService) ShowPolicy(_ context.Context, _ string) (broker.CapabilityPolicyView, error) {
	return s.policyView, nil
}

func (s *fakeService) ReplacePolicy(_ context.Context, request ReplacePolicyRequest) (broker.CapabilityPolicyReplacementResult, error) {
	s.policyReplacement = request
	return s.policyResult, nil
}

func (s *fakeService) ListPolicyHistory(_ context.Context, query broker.CapabilityPolicyHistoryQuery) ([]broker.CapabilityPolicyEvent, error) {
	s.policyHistoryQuery = query
	return s.policyHistory, nil
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

func TestCapabilityPolicyReplaceRequiresAndCuratesCompletePolicy(t *testing.T) {
	service := &fakeService{policyResult: broker.CapabilityPolicyReplacementResult{
		Changed: true,
		Capability: broker.CapabilityPolicyView{
			CapabilityID: "cap_123", State: broker.CapabilityStateActive,
			Repository: broker.CapabilityRepository{ID: 99, Owner: "owner", Name: "repo"},
			Policy: broker.NewPolicyRepresentation(broker.Policy{
				Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
				Git: broker.GitPolicy{Push: broker.GitPushNonDefault, Tags: false},
			}, 2),
		},
	}}
	stdout := &bytes.Buffer{}
	command := NewCommand(CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: stdout, Stderr: &bytes.Buffer{}})
	command.SetArgs([]string{
		"capability", "policy", "replace", "cap_123",
		"--grant", "actions.write", "--git-push", "non-default", "--git-tags=false",
		"--reason", "agent needs workflow retries", "--actor", "operator@example",
	})

	require.NoError(t, command.Execute())

	assert.Equal(t, "cap_123", service.policyReplacement.CapabilityID)
	assert.Equal(t, map[string]bool{"actions.write": true}, service.policyReplacement.Policy.Grants)
	assert.Equal(t, broker.GitPushNonDefault, service.policyReplacement.Policy.Git.Push)
	assert.False(t, service.policyReplacement.Policy.Git.Tags)
	assert.Equal(t, "agent needs workflow retries", service.policyReplacement.Reason)
	assert.Equal(t, "operator@example", service.policyReplacement.Actor)
	assert.JSONEq(t, `{
		"changed":true,
		"capability":{
			"capability_id":"cap_123","state":"active",
			"repository":{"id":99,"owner":"owner","name":"repo"},
			"policy":{"name":"developer","version":1,"revision":2,"grants":["actions.write"],"git":{"push":"non-default","tags":false}},
			"expires_at":null,"revoked_at":null,"created_at":"0001-01-01T00:00:00Z","policy_updated_at":"0001-01-01T00:00:00Z"
		}
	}`, stdout.String())
}

func TestCapabilityPolicyReplaceRejectsIncompleteOrInvalidState(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "missing Git push", args: []string{"--no-grants", "--git-tags=false", "--reason", "reduce access"}, message: "git-push must be explicitly set"},
		{name: "missing Git tags", args: []string{"--no-grants", "--git-push", "none", "--reason", "reduce access"}, message: "git-tags must be explicitly set"},
		{name: "missing grants decision", args: []string{"--git-push", "none", "--git-tags=false", "--reason", "reduce access"}, message: "either grant or no-grants"},
		{name: "conflicting grants", args: []string{"--grant", "actions.write", "--no-grants", "--git-push", "none", "--git-tags=false", "--reason", "reduce access"}, message: "mutually exclusive"},
		{name: "duplicate grant", args: []string{"--grant", "actions.write,actions.write", "--git-push", "none", "--git-tags=false", "--reason", "reduce access"}, message: "duplicate policy grant"},
		{name: "missing reason", args: []string{"--no-grants", "--git-push", "none", "--git-tags=false"}, message: "reason is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := NewCommand(CommandOptions{Service: &fakeService{}, Stdin: &bytes.Buffer{}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
			command.SetArgs(append([]string{"capability", "policy", "replace", "cap_123"}, tt.args...))

			err := command.Execute()

			require.ErrorContains(t, err, tt.message)
		})
	}
}

func TestCapabilityPolicyShowAndHistoryUseJSONContracts(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	service := &fakeService{
		policyView: broker.CapabilityPolicyView{
			CapabilityID: "cap_123", State: broker.CapabilityStateRevoked,
			Repository: broker.CapabilityRepository{ID: 99, Owner: "owner", Name: "repo"},
			Policy: broker.NewPolicyRepresentation(broker.Policy{
				Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone},
			}, 2),
		},
		policyHistory: []broker.CapabilityPolicyEvent{{
			OccurredAt: now, Event: "capability_policy_changed", CapabilityID: "cap_123", RepositoryID: 99,
			BeforeRevision: 1, AfterRevision: 2, Direction: broker.PolicyChangeNarrowed, Reason: "reduce access",
		}},
	}

	showOut := &bytes.Buffer{}
	show := NewCommand(CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: showOut, Stderr: &bytes.Buffer{}})
	show.SetArgs([]string{"capability", "policy", "show", "cap_123"})
	require.NoError(t, show.Execute())
	assert.Contains(t, showOut.String(), `"state":"revoked"`)
	assert.Contains(t, showOut.String(), `"revision":2`)

	historyOut := &bytes.Buffer{}
	history := NewCommand(CommandOptions{Service: service, Stdin: &bytes.Buffer{}, Stdout: historyOut, Stderr: &bytes.Buffer{}})
	history.SetArgs([]string{"capability", "policy", "history", "cap_123", "--since", "2026-08-19T00:00:00Z", "--limit", "25"})
	require.NoError(t, history.Execute())
	assert.Contains(t, historyOut.String(), `"event":"capability_policy_changed"`)
	assert.Equal(t, "cap_123", service.policyHistoryQuery.CapabilityID)
	require.NotNil(t, service.policyHistoryQuery.Since)
	assert.Equal(t, 25, service.policyHistoryQuery.Limit)
}

func TestAuditListPrintsBoundedJSONEvents(t *testing.T) {
	service := &fakeService{audit: []broker.AuditEvent{{
		OccurredAt: time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC), Event: "broker_request",
		RequestID: "request-1", Phase: broker.AuditPhaseResult, CapabilityID: "cap_1", PolicyRevision: 2, RepositoryID: 99,
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
	assert.JSONEq(t, `{"time":"2026-08-10T12:00:00Z","event":"broker_request","request_id":"request-1","phase":"result","capability_id":"cap_1","policy_revision":2,"repository_id":99,"method":"GET","path":"/api/v3/repos/owner/repo","mutation":false,"status":200}`, stdout.String())
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
