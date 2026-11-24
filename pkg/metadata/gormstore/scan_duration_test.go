package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func saveScan(t *testing.T, store *GORMStoreV2, name string, at time.Time, ms int) {
	t.Helper()
	trendingPackage(t, store, "npm", name, "1.0.0")
	require.NoError(t, store.SaveScanResult(context.Background(), &metadata.ScanResult{
		Registry: "npm", PackageName: name, PackageVersion: "1.0.0", Scanner: "test",
		ScannedAt: at, Status: metadata.ScanStatusClean, DurationMs: ms,
	}))
}

func TestAverageScanDurationUsesTheLatestRecordedScans(t *testing.T) {
	store := trendingStore(t)
	ctx := context.Background()

	avg, err := store.AverageScanDuration(ctx, 10)
	require.NoError(t, err)
	require.Zero(t, avg, "no scans yet")

	saveScan(t, store, "old", trendingNow.Add(-3*time.Hour), 9000)
	saveScan(t, store, "a", trendingNow.Add(-2*time.Hour), 1000)
	saveScan(t, store, "b", trendingNow.Add(-time.Hour), 3000)
	saveScan(t, store, "unrecorded", trendingNow, 0)

	avg, err = store.AverageScanDuration(ctx, 2)
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, avg, "the two latest recorded scans, the zero ignored")

	avg, err = store.AverageScanDuration(ctx, 10)
	require.NoError(t, err)
	require.InDelta(t, float64(13000)/3, float64(avg.Milliseconds()), 1, "mean of 9000, 1000 and 3000")
}
