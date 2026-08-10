package broker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	ErrRateLimited        = errors.New("capability request rate exceeded")
	ErrConcurrencyLimited = errors.New("capability concurrency exceeded")
)

// RequestClass selects the independent per-capability budget for a request.
type RequestClass bool

const (
	// RequestRead selects the read request budget.
	RequestRead RequestClass = false
	// RequestMutation selects the mutation request budget.
	RequestMutation RequestClass = true
)

// RequestLimiter bounds authentication work before admitting an authenticated
// request against its per-capability budget.
type RequestLimiter interface {
	// AcquireAuthentication bounds concurrent work before a token is trusted.
	AcquireAuthentication(context.Context) (func(), error)
	// Acquire admits one authenticated capability request.
	Acquire(context.Context, string, RequestClass) (func(), error)
}

// LocalLimitOptions configures one Broker replica's per-capability limits.
type LocalLimitOptions struct {
	ReadsPerMinute     int
	MutationsPerMinute int
	Concurrent         int
}

type localRequestLimiter struct {
	mu             sync.Mutex
	options        LocalLimitOptions
	authentication chan struct{}
	limits         map[string]*capabilityLimits
}

type capabilityLimits struct {
	reads     *rate.Limiter
	mutations *rate.Limiter
	active    chan struct{}
}

// NewLocalRequestLimiter constructs independent local budgets for each capability.
func NewLocalRequestLimiter(options LocalLimitOptions) (RequestLimiter, error) {
	if options.ReadsPerMinute <= 0 || options.MutationsPerMinute <= 0 || options.Concurrent <= 0 {
		return nil, fmt.Errorf("local request limits must be positive")
	}
	authenticationConcurrency := max(64, options.Concurrent)
	return &localRequestLimiter{
		options: options, authentication: make(chan struct{}, authenticationConcurrency),
		limits: make(map[string]*capabilityLimits),
	}, nil
}

// AcquireAuthentication reserves one replica-local authentication slot.
func (l *localRequestLimiter) AcquireAuthentication(ctx context.Context) (func(), error) {
	if l == nil {
		return nil, ErrConcurrencyLimited
	}
	select {
	case l.authentication <- struct{}{}:
		return func() { <-l.authentication }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrConcurrencyLimited
	}
}

// Acquire reserves one per-capability request slot and budget token.
func (l *localRequestLimiter) Acquire(ctx context.Context, capabilityID string, class RequestClass) (func(), error) {
	if l == nil || capabilityID == "" {
		return nil, ErrRateLimited
	}
	limits := l.forCapability(capabilityID)
	select {
	case limits.active <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrConcurrencyLimited
	}
	release := func() { <-limits.active }
	selected := limits.reads
	if class == RequestMutation {
		selected = limits.mutations
	}
	if !selected.Allow() {
		release()
		return nil, ErrRateLimited
	}
	return release, nil
}

func (l *localRequestLimiter) forCapability(capabilityID string) *capabilityLimits {
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing := l.limits[capabilityID]; existing != nil {
		return existing
	}
	created := &capabilityLimits{
		reads:     rate.NewLimiter(rate.Every(time.Minute/time.Duration(l.options.ReadsPerMinute)), l.options.ReadsPerMinute),
		mutations: rate.NewLimiter(rate.Every(time.Minute/time.Duration(l.options.MutationsPerMinute)), l.options.MutationsPerMinute),
		active:    make(chan struct{}, l.options.Concurrent),
	}
	l.limits[capabilityID] = created
	return created
}

var _ RequestLimiter = (*localRequestLimiter)(nil)
