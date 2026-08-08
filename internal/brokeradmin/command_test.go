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

func TestCredentialPutReadsPATFromStdinWithoutEchoingIt(t *testing.T) {
	service := &fakeService{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command := NewCommand(service, bytes.NewBufferString("upstream-pat\n"), stdout, stderr)
	command.SetArgs([]string{"credential", "put", "--name", "work", "--host", "github.com"})

	err := command.Execute()

	require.NoError(t, err, stderr.String())
	assert.Equal(t, "work", service.credential.Name)
	assert.Equal(t, "github.com", service.credential.UpstreamHost)
	assert.Equal(t, "https://api.github.com", service.credential.APIBaseURL)
	assert.Equal(t, "2022-11-28", service.credential.APIVersion)
	assert.Equal(t, "upstream-pat", string(service.credential.Token))
	assert.NotContains(t, stdout.String(), "upstream-pat")
}

func TestCapabilityIssuePrintsOneTimeTokenAndBindsRepository(t *testing.T) {
	service := &fakeService{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command := NewCommand(service, &bytes.Buffer{}, stdout, stderr)
	command.SetArgs([]string{
		"capability", "issue",
		"--credential", "work",
		"--repo", "michaellee8/github-proxy",
		"--repository-id", "1326468465",
		"--default-branch", "main",
		"--grant", "actions.write",
		"--git-push", "non-default",
		"--git-tags",
		"--expires-in", "2h",
	})

	err := command.Execute()

	require.NoError(t, err, stderr.String())
	assert.Equal(t, "pgh_pat_selector.secret\n", stdout.String())
	assert.Equal(t, "work", service.issue.CredentialName)
	assert.Equal(t, int64(1326468465), service.issue.Repository.ID)
	assert.Equal(t, "michaellee8", service.issue.Repository.Owner)
	assert.Equal(t, "github-proxy", service.issue.Repository.Name)
	assert.Equal(t, "main", service.issue.Repository.DefaultBranch)
	assert.Equal(t, broker.Policy{
		Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
		Git: broker.GitPolicy{Push: broker.GitPushNonDefault, Tags: true},
	}, service.issue.Policy)
	require.NotNil(t, service.issue.ExpiresAt)
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), *service.issue.ExpiresAt, 5*time.Second)
}

func TestCapabilityRevokeUsesOpaqueID(t *testing.T) {
	service := &fakeService{}
	command := NewCommand(service, &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{"capability", "revoke", "cap_123"})

	require.NoError(t, command.Execute())
	assert.Equal(t, "cap_123", service.revokedID)
}
