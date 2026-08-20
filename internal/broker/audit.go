package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

var ErrAuditUnavailable = errors.New("request audit is unavailable")

const (
	// AuditPhasePreflight identifies an authorization decision recorded before forwarding.
	AuditPhasePreflight = "preflight"
	// AuditPhaseResult identifies the observed result of a forwarded request.
	AuditPhaseResult = "result"
)

// AuditEvent is the redacted request record shared by durable storage and JSON logs.
type AuditEvent struct {
	OccurredAt     time.Time `json:"time"`
	Event          string    `json:"event"`
	RequestID      string    `json:"request_id"`
	Phase          string    `json:"phase"`
	CapabilityID   string    `json:"capability_id"`
	PolicyRevision int64     `json:"policy_revision"`
	RepositoryID   int64     `json:"repository_id"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Mutation       bool      `json:"mutation"`
	Status         int       `json:"status,omitempty"`
	DurationMS     int64     `json:"duration_ms,omitempty"`
}

// AuditStore is the durable audit persistence boundary.
type AuditStore interface {
	RecordAuditEvent(context.Context, AuditEvent) error
}

// AuditQuery bounds and filters offline audit inspection.
type AuditQuery struct {
	CapabilityID string
	RepositoryID *int64
	Since        *time.Time
	Limit        int
}

// AuditArchive adds operator queries and retention to the append-only write path.
type AuditArchive interface {
	AuditStore
	ListAuditEvents(context.Context, AuditQuery) ([]AuditEvent, error)
	DeleteAuditEventsBefore(context.Context, time.Time) (int64, error)
}

// AuditEmitter writes an event to the deployment's structured log transport.
type AuditEmitter interface {
	EmitAuditEvent(context.Context, AuditEvent) error
}

// RequestAuditor owns the different availability rules for read and mutation audits.
type RequestAuditor interface {
	Preflight(context.Context, AuditEvent) error
	Result(context.Context, AuditEvent)
}

type requestAuditor struct {
	store   AuditStore
	emitter AuditEmitter
}

// NewRequestAuditor combines durable storage with a structured event emitter.
func NewRequestAuditor(store AuditStore, emitter AuditEmitter) RequestAuditor {
	return &requestAuditor{store: store, emitter: emitter}
}

func (a *requestAuditor) Preflight(ctx context.Context, event AuditEvent) error {
	if a == nil || a.emitter == nil {
		return ErrAuditUnavailable
	}
	event.Phase = AuditPhasePreflight
	if err := a.emitter.EmitAuditEvent(ctx, event); err != nil {
		return ErrAuditUnavailable
	}
	if a.store == nil {
		if event.Mutation {
			return ErrAuditUnavailable
		}
		return nil
	}
	if err := a.store.RecordAuditEvent(ctx, event); err != nil && event.Mutation {
		return ErrAuditUnavailable
	}
	return nil
}

func (a *requestAuditor) Result(ctx context.Context, event AuditEvent) {
	if a == nil || a.emitter == nil {
		return
	}
	event.Phase = AuditPhaseResult
	_ = a.emitter.EmitAuditEvent(ctx, event)
	if a.store != nil {
		_ = a.store.RecordAuditEvent(ctx, event)
	}
}

type jsonAuditEmitter struct {
	mu     sync.Mutex
	writer io.Writer
}

// NewJSONAuditEmitter creates a concurrency-safe newline-delimited JSON emitter.
func NewJSONAuditEmitter(writer io.Writer) AuditEmitter {
	return &jsonAuditEmitter{writer: writer}
}

func (e *jsonAuditEmitter) EmitAuditEvent(_ context.Context, event AuditEvent) error {
	if e == nil || e.writer == nil {
		return ErrAuditUnavailable
	}
	event.Event = "broker_request"
	e.mu.Lock()
	defer e.mu.Unlock()
	return json.NewEncoder(e.writer).Encode(event)
}

var _ RequestAuditor = (*requestAuditor)(nil)
var _ AuditEmitter = (*jsonAuditEmitter)(nil)
