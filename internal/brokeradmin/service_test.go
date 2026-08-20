package brokeradmin

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/broker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type serviceStore struct {
	replacement broker.CapabilityPolicyReplacement
	view        broker.CapabilityPolicyView
	events      []broker.CapabilityPolicyEvent
}

func (s *serviceStore) CredentialByName(context.Context, string) (broker.StoredCredential, error) {
	return broker.StoredCredential{}, broker.ErrCredentialNotFound
}
func (s *serviceStore) CreateCapability(context.Context, broker.StoredCapability) error { return nil }
func (s *serviceStore) CapabilityBySelector(context.Context, string) (broker.StoredCapability, error) {
	return broker.StoredCapability{}, broker.ErrCapabilityNotFound
}
func (s *serviceStore) UpdateRepositoryObservation(context.Context, string, broker.Repository) error {
	return nil
}
func (s *serviceStore) RecordAuditEvent(context.Context, broker.AuditEvent) error { return nil }
func (s *serviceStore) ListAuditEvents(context.Context, broker.AuditQuery) ([]broker.AuditEvent, error) {
	return nil, nil
}
func (s *serviceStore) DeleteAuditEventsBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (s *serviceStore) PutCredential(context.Context, broker.StoredCredential) error { return nil }
func (s *serviceStore) RevokeCapability(context.Context, string, time.Time) error    { return nil }
func (s *serviceStore) CapabilityPolicyByID(context.Context, string, time.Time) (broker.CapabilityPolicyView, error) {
	return s.view, nil
}
func (s *serviceStore) ReplaceCapabilityPolicy(_ context.Context, replacement broker.CapabilityPolicyReplacement) (broker.CapabilityPolicyReplacementResult, error) {
	s.replacement = replacement
	return broker.CapabilityPolicyReplacementResult{Changed: true, Capability: s.view}, nil
}
func (s *serviceStore) ListCapabilityPolicyEvents(_ context.Context, query broker.CapabilityPolicyHistoryQuery) ([]broker.CapabilityPolicyEvent, error) {
	return s.events, nil
}

func TestAdminServiceReplacesPolicyWithSanitizedMetadataAndClock(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	store := &serviceStore{}
	service := NewAdminService(store, nil, nil, bytes.NewReader(nil), func() time.Time { return now })
	policy := broker.Policy{
		Name: "developer", Version: 1, Grants: map[string]bool{"actions.write": true},
		Git: broker.GitPolicy{Push: broker.GitPushNonDefault},
	}

	_, err := service.ReplacePolicy(context.Background(), ReplacePolicyRequest{
		CapabilityID: "cap_123", Policy: policy, Reason: "  approved for retries  ", Actor: "  operator  ",
	})

	require.NoError(t, err)
	assert.Equal(t, "cap_123", store.replacement.CapabilityID)
	assert.Equal(t, policy, store.replacement.Policy)
	assert.Equal(t, "approved for retries", store.replacement.Reason)
	assert.Equal(t, "operator", store.replacement.Actor)
}

func TestAdminServiceRejectsInvalidPolicyReplacementMetadata(t *testing.T) {
	tests := []struct {
		name    string
		request ReplacePolicyRequest
		message string
	}{
		{
			name:    "blank reason",
			request: ReplacePolicyRequest{CapabilityID: "cap_123", Policy: developerPolicy(), Reason: "  "},
			message: "reason are required",
		},
		{
			name:    "reason control character",
			request: ReplacePolicyRequest{CapabilityID: "cap_123", Policy: developerPolicy(), Reason: "line one\nline two"},
			message: "without control characters",
		},
		{
			name:    "long actor",
			request: ReplacePolicyRequest{CapabilityID: "cap_123", Policy: developerPolicy(), Reason: "approved", Actor: strings.Repeat("a", 129)},
			message: "actor must be at most 128 bytes",
		},
		{
			name:    "invalid policy",
			request: ReplacePolicyRequest{CapabilityID: "cap_123", Policy: broker.Policy{Name: "developer", Version: 2}, Reason: "approved"},
			message: "developer version 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewAdminService(&serviceStore{}, nil, nil, bytes.NewReader(nil), time.Now)

			_, err := service.ReplacePolicy(context.Background(), tt.request)

			require.ErrorContains(t, err, tt.message)
		})
	}
}

func developerPolicy() broker.Policy {
	return broker.Policy{Name: "developer", Version: 1, Git: broker.GitPolicy{Push: broker.GitPushNone}}
}

var _ Store = (*serviceStore)(nil)
