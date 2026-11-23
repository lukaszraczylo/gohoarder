package cache

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// racyStorage deletes the blob and the row when the second Get opens it, as a purge would.
type racyStorage struct {
	*memStorage
	meta  *memMetadata
	gets  atomic.Int32
	armed atomic.Bool
}

func (s *racyStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if s.armed.Load() && s.gets.Add(1) == 2 {
		_ = s.Delete(ctx, key)
		_ = s.meta.DeletePackage(ctx, "npm", "left-pad", "1.0.0")
	}
	return s.memStorage.Get(ctx, key)
}

// A purge between the cache-hit probe and the caller's open must not fail the request.
func TestGetRecoversFromPurgeBetweenProbeAndOpen(t *testing.T) {
	clock := newFakeClock()
	meta := newMemMetadata(clock)
	store := &racyStorage{memStorage: newMemStorage(), meta: meta}

	mgr, err := New(store, meta, nil, nil, Config{Now: clock.Now, CleanupInterval: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	fetch := func(context.Context) (*FetchResult, error) {
		return &FetchResult{Data: io.NopCloser(strings.NewReader("payload")), UpstreamURL: "https://upstream/x"}, nil
	}
	entry, err := mgr.Get(context.Background(), "npm", "left-pad", "1.0.0", fetch)
	require.NoError(t, err)
	_ = entry.Data.Close()

	store.armed.Store(true)
	entry, err = mgr.Get(context.Background(), "npm", "left-pad", "1.0.0", fetch)
	require.NoError(t, err)
	body, err := io.ReadAll(entry.Data)
	require.NoError(t, err)
	_ = entry.Data.Close()
	require.Equal(t, "payload", string(body))
}
