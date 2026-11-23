package cache

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// purgeRecorder plays a store holding `pending` soft-deleted rows.
type purgeRecorder struct {
	*memMetadata
	err     error
	cutoffs []time.Time
	limits  []int
	pending int64
	mu      sync.Mutex
}

func (p *purgeRecorder) PurgeDeletedPackages(_ context.Context, before time.Time, limit int) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cutoffs = append(p.cutoffs, before)
	p.limits = append(p.limits, limit)
	if p.err != nil {
		return 0, p.err
	}
	n := min(p.pending, int64(limit))
	p.pending -= n
	return n, nil
}

func newPurgeHarness(t *testing.T, retention time.Duration, pending int64) (*idleHarness, *purgeRecorder) {
	t.Helper()
	h := &idleHarness{clock: newFakeClock(), store: newMemStorage()}
	rec := &purgeRecorder{memMetadata: newMemMetadata(h.clock), pending: pending}
	h.meta = rec.memMetadata
	mgr, err := New(h.store, rec, nil, nil, Config{Now: h.clock.Now, CleanupInterval: 24 * time.Hour, DeletedRetention: retention})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	h.mgr = mgr
	return h, rec
}

func TestCleanupPurgesDeletedRowsPastRetention(t *testing.T) {
	h, rec := newPurgeHarness(t, 30*day, 3*int64(cleanupBatchSize)+7)

	h.mgr.cleanup(context.Background())

	require.Zero(t, rec.pending, "batches continue until the store runs dry")
	require.Len(t, rec.limits, 4, "three full batches and a short one")
	for _, limit := range rec.limits {
		require.Equal(t, cleanupBatchSize, limit, "every batch is bounded")
	}
	require.Equal(t, h.clock.Now().Add(-30*day), rec.cutoffs[0], "the cutoff is now minus the retention")
}

func TestCleanupPurgeIsBoundedPerPass(t *testing.T) {
	_, rec := newPurgeHarness(t, 30*day, int64(maxPurgeBatches+50)*int64(cleanupBatchSize))
	h := &Manager{config: Config{DeletedRetention: day, Now: time.Now}, metadata: rec}

	got := h.purgeDeleted(context.Background(), time.Now())

	require.EqualValues(t, maxPurgeBatches*cleanupBatchSize, got)
	require.EqualValues(t, 50*cleanupBatchSize, rec.pending, "the next pass continues where this one stopped")
}

func TestCleanupSkipsPurgeWhenRetentionIsZero(t *testing.T) {
	h, rec := newPurgeHarness(t, 0, 10)

	h.mgr.cleanup(context.Background())

	require.Empty(t, rec.limits, "zero keeps every row")
	require.EqualValues(t, 10, rec.pending)
}

func TestCleanupPurgeFailureDoesNotStopCleanup(t *testing.T) {
	h, rec := newPurgeHarness(t, 30*day, 10)
	rec.err = errors.New("db down")
	h.get(t, "lodash", "metadata")
	h.clock.Advance(2 * day)

	h.mgr.cleanup(context.Background())

	require.Len(t, rec.limits, 1, "one failed attempt, no retry loop")
	require.False(t, h.exists("lodash", "metadata"), "expired metadata is still removed")
}
