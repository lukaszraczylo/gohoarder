//go:build pgintegration

package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// The missed-day repair on the production dialect: hourly rows are written directly so the
// test needs no download_events partition for a past month.
func TestPostgresDailyRollupCoversMissedDay(t *testing.T) {
	ctx := context.Background()
	store, _ := newPostgresStore(t)
	day := time.Now().UTC().Truncate(24 * time.Hour).Add(-10 * 24 * time.Hour)

	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.3.0", StorageKey: "npm/left-pad/1.3.0",
		Size: 10, CachedAt: day, LastAccessed: day,
	}))
	registryID, err := store.getRegistryID("npm")
	require.NoError(t, err)
	var packageID int64
	require.NoError(t, store.db.Table("packages").Select("id").Where("name = ?", "left-pad").Scan(&packageID).Error)
	for _, hour := range []int{5, 6, 7} {
		require.NoError(t, store.db.Exec(
			`INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
			 VALUES (?, ?, ?, 1, 1, 0, NOW(), NOW())`, registryID, packageID, day.Add(time.Duration(hour)*time.Hour)).Error)
	}

	for d := 2; d <= 9; d++ {
		at := day.Add(time.Duration(d)*24*time.Hour + 30*time.Minute)
		store.aggregationWorker.now = func() time.Time { return at }
		require.NoError(t, store.aggregationWorker.AggregateDaily())
	}

	store.now = func() time.Time { return day.Add(9*24*time.Hour + time.Hour) }
	ts, err := store.GetTimeSeriesStats(ctx, "30day", "")
	require.NoError(t, err)
	require.EqualValues(t, 3, sumPoints(ts))
}
