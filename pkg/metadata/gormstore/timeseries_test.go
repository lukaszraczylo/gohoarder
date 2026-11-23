package gormstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func sumPoints(ts *metadata.TimeSeriesStats) int64 {
	var total int64
	for _, p := range ts.DataPoints {
		total += p.Value
	}
	return total
}

func newTimeSeriesStore(t *testing.T) *GORMStoreV2 {
	t.Helper()
	store, err := NewV2(Config{
		Driver:       "sqlite",
		DSN:          fmt.Sprintf("file:ts_%d?mode=memory&cache=shared", time.Now().UnixNano()),
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     "silent",
	})
	require.NoError(t, err)
	return store
}

func recordDownloads(t *testing.T, store *GORMStoreV2, n int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.3.0", StorageKey: "npm/left-pad/1.3.0",
		Size: 10, CachedAt: now, LastAccessed: now,
	}))
	for i := 0; i < n; i++ {
		require.NoError(t, store.UpdateDownloadCount(ctx, "npm", "left-pad", "1.3.0"))
	}
}

func TestTimeSeriesIncludesFreshDownloads(t *testing.T) {
	for _, period := range []string{"1h", "1day", "7day", "30day"} {
		t.Run(period+"/before aggregation", func(t *testing.T) {
			store := newTimeSeriesStore(t)
			recordDownloads(t, store, 3)
			ts, err := store.GetTimeSeriesStats(context.Background(), period, "")
			require.NoError(t, err)
			require.Equal(t, int64(3), sumPoints(ts))
		})
		t.Run(period+"/after aggregation", func(t *testing.T) {
			store := newTimeSeriesStore(t)
			recordDownloads(t, store, 3)
			require.NoError(t, store.AggregateDownloadData(context.Background()))
			require.NoError(t, store.AggregateDownloadData(context.Background()))
			ts, err := store.GetTimeSeriesStats(context.Background(), period, "npm")
			require.NoError(t, err)
			require.Equal(t, int64(3), sumPoints(ts))
		})
	}
}

func TestTimeSeriesReadsAggregatedBuckets(t *testing.T) {
	ctx := context.Background()
	store := newTimeSeriesStore(t)
	recordDownloads(t, store, 2)
	// Move the events into completed hours so the worker aggregates them.
	require.NoError(t, store.db.Exec("UPDATE download_events SET downloaded_at = ?", time.Now().UTC().Add(-3*time.Hour)).Error)
	require.NoError(t, store.AggregateDownloadData(ctx))

	var raw int64
	require.NoError(t, store.db.Table("download_events").Count(&raw).Error)
	require.Zero(t, raw, "aggregation must consume the events it counted")

	for _, period := range []string{"1day", "7day"} {
		ts, err := store.GetTimeSeriesStats(ctx, period, "")
		require.NoError(t, err)
		require.Equal(t, int64(2), sumPoints(ts), period)
	}
}
