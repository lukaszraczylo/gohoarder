package cache

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// evictMeta adds the LRU list and a switchable delete failure to memMetadata.
type evictMeta struct {
	*memMetadata
	listGate   chan struct{}
	listing    chan struct{}
	failDelete atomic.Bool
}

func (m *evictMeta) ListPackages(_ context.Context, opts *metadata.ListOptions) ([]*metadata.Package, error) {
	if m.listing != nil {
		select {
		case m.listing <- struct{}{}:
		default:
		}
		<-m.listGate
	}
	return m.list(opts.Limit,
		func(*metadata.Package) bool { return true },
		func(a, b *metadata.Package) bool { return a.LastAccessed.Before(b.LastAccessed) }), nil
}

func (m *evictMeta) DeletePackage(ctx context.Context, registry, name, version string) error {
	if m.failDelete.Load() {
		return errors.New("db down")
	}
	return m.memMetadata.DeletePackage(ctx, registry, name, version)
}

func seedPackages(t *testing.T, m *memMetadata, store *memStorage, n int, size int64) {
	t.Helper()
	for i := 0; i < n; i++ {
		name := "pkg" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + time.Duration(i).String()
		key := "npm/" + name + "/1.0.0"
		require.NoError(t, store.Put(context.Background(), key, strings.NewReader("d"), nil))
		require.NoError(t, m.SavePackage(context.Background(), &metadata.Package{
			Registry: "npm", Name: name, Version: "1.0.0", StorageKey: key, Size: size,
			LastAccessed: m.clock.Now().Add(time.Duration(i) * time.Second),
		}))
	}
}

// evict must return when no package can be deleted instead of re-listing the same rows forever.
func TestEvictTerminatesWhenDeletesFail(t *testing.T) {
	clock := newFakeClock()
	store := newMemStorage()
	meta := &evictMeta{memMetadata: newMemMetadata(clock)}
	seedPackages(t, meta.memMetadata, store, 250, 1)
	meta.failDelete.Store(true)

	mgr, err := New(store, meta, nil, nil, Config{Now: clock.Now, CleanupInterval: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	done := make(chan error, 1)
	go func() { done <- mgr.evict(context.Background(), 1000) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("evict did not terminate with failing deletes")
	}
}

// A store that overlaps a running eviction must wait for it, not fail as over quota.
func TestEvictWaitsForRunningEviction(t *testing.T) {
	clock := newFakeClock()
	store := newMemStorage()
	meta := &evictMeta{memMetadata: newMemMetadata(clock), listGate: make(chan struct{}), listing: make(chan struct{}, 1)}
	seedPackages(t, meta.memMetadata, store, 3, 10)

	mgr, err := New(store, meta, nil, nil, Config{Now: clock.Now, CleanupInterval: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(1)
	go func() { defer wg.Done(); errs[0] = mgr.evict(context.Background(), 10) }()
	<-meta.listing // first eviction is inside its list query

	wg.Add(1)
	go func() { defer wg.Done(); errs[1] = mgr.evict(context.Background(), 10) }()
	time.Sleep(100 * time.Millisecond)
	close(meta.listGate)
	wg.Wait()

	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
}
