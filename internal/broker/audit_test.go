package broker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryAuditStore struct {
	events []AuditEvent
	err    error
}

func (s *memoryAuditStore) RecordAuditEvent(_ context.Context, event AuditEvent) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	return nil
}

type memoryAuditEmitter struct {
	events []AuditEvent
	err    error
}

func (e *memoryAuditEmitter) EmitAuditEvent(_ context.Context, event AuditEvent) error {
	if e.err != nil {
		return e.err
	}
	e.events = append(e.events, event)
	return nil
}

func TestRequestAuditorRequiresDurablePreflightForMutations(t *testing.T) {
	store := &memoryAuditStore{err: errors.New("database unavailable")}
	emitter := &memoryAuditEmitter{}
	auditor := NewRequestAuditor(store, emitter)
	event := AuditEvent{RequestID: "request-1", CapabilityID: "cap-1", Mutation: true}

	err := auditor.Preflight(context.Background(), event)

	require.ErrorIs(t, err, ErrAuditUnavailable)
	require.Len(t, emitter.events, 1)
	assert.Empty(t, store.events)
}

func TestRequestAuditorAllowsReadAfterStructuredLogWhenDatabaseIsUnavailable(t *testing.T) {
	store := &memoryAuditStore{err: errors.New("database unavailable")}
	emitter := &memoryAuditEmitter{}
	auditor := NewRequestAuditor(store, emitter)
	event := AuditEvent{RequestID: "request-1", CapabilityID: "cap-1"}

	err := auditor.Preflight(context.Background(), event)

	require.NoError(t, err)
	require.Len(t, emitter.events, 1)
}

func TestRequestAuditorDeniesReadWhenStructuredLogCannotBeEmitted(t *testing.T) {
	auditor := NewRequestAuditor(&memoryAuditStore{}, &memoryAuditEmitter{err: errors.New("log unavailable")})

	err := auditor.Preflight(context.Background(), AuditEvent{RequestID: "request-1", CapabilityID: "cap-1"})

	require.ErrorIs(t, err, ErrAuditUnavailable)
}

func TestJSONAuditEmitterWritesOnlyRedactedEventFields(t *testing.T) {
	output := &bytes.Buffer{}
	emitter := NewJSONAuditEmitter(output)
	event := AuditEvent{
		OccurredAt: time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC),
		RequestID:  "request-1", Phase: AuditPhasePreflight, CapabilityID: "cap-1",
		RepositoryID: 99, Method: "POST", Path: "/api/v3/repos/owner/repo/issues", Mutation: true,
	}

	require.NoError(t, emitter.EmitAuditEvent(context.Background(), event))

	assert.JSONEq(t, `{
		"time":"2026-08-10T12:00:00Z","event":"broker_request","request_id":"request-1",
		"phase":"preflight","capability_id":"cap-1","repository_id":99,
		"method":"POST","path":"/api/v3/repos/owner/repo/issues","mutation":true
	}`, output.String())
	assert.NotContains(t, output.String(), "Authorization")
}

var _ AuditStore = (*memoryAuditStore)(nil)
var _ AuditEmitter = (*memoryAuditEmitter)(nil)
