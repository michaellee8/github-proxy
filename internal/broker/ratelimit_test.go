package broker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalRequestLimiterKeepsSeparateReadAndMutationBudgets(t *testing.T) {
	limiter, err := NewLocalRequestLimiter(LocalLimitOptions{ReadsPerMinute: 1, MutationsPerMinute: 1, Concurrent: 2})
	require.NoError(t, err)

	release, err := limiter.Acquire(context.Background(), "cap-1", RequestRead)
	require.NoError(t, err)
	release()
	_, err = limiter.Acquire(context.Background(), "cap-1", RequestRead)
	require.ErrorIs(t, err, ErrRateLimited)

	release, err = limiter.Acquire(context.Background(), "cap-1", RequestMutation)
	require.NoError(t, err)
	release()
	_, err = limiter.Acquire(context.Background(), "cap-1", RequestMutation)
	require.ErrorIs(t, err, ErrRateLimited)
}

func TestLocalRequestLimiterRejectsRequestsBeyondConcurrencyLimit(t *testing.T) {
	limiter, err := NewLocalRequestLimiter(LocalLimitOptions{ReadsPerMinute: 10, MutationsPerMinute: 10, Concurrent: 1})
	require.NoError(t, err)

	release, err := limiter.Acquire(context.Background(), "cap-1", RequestRead)
	require.NoError(t, err)
	defer release()

	_, err = limiter.Acquire(context.Background(), "cap-1", RequestRead)
	require.ErrorIs(t, err, ErrConcurrencyLimited)
}

func TestLocalRequestLimiterScopesLimitsByCapability(t *testing.T) {
	limiter, err := NewLocalRequestLimiter(LocalLimitOptions{ReadsPerMinute: 1, MutationsPerMinute: 1, Concurrent: 1})
	require.NoError(t, err)

	release, err := limiter.Acquire(context.Background(), "cap-1", RequestRead)
	require.NoError(t, err)
	release()

	release, err = limiter.Acquire(context.Background(), "cap-2", RequestRead)
	require.NoError(t, err)
	release()
}
