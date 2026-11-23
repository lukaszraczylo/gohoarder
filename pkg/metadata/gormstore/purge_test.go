package gormstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func checkPurgeDeletedPackages(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("gone-%d", i)
		seedAt(t, store, name, "1.0.0", 10, daysAgo(60))
		scanAt(t, store, name, "1.0.0", daysAgo(59), "high")
		require.NoError(t, store.db.Create(&PackageMetadataModel{PackageID: packageID(t, store, name)}).Error)
	}
	seedAt(t, store, "live", "1.0.0", 10, daysAgo(60))
	scanAt(t, store, "live", "1.0.0", daysAgo(59), "high")
	seedAt(t, store, "recent", "1.0.0", 10, daysAgo(60))
	softDeleteAt(t, store, "recent", "1.0.0", daysAgo(5))
	for i := 0; i < 5; i++ {
		softDeleteAt(t, store, fmt.Sprintf("gone-%d", i), "1.0.0", daysAgo(40-i))
	}

	// History survives the purge: snapshots and download rows hold their own counts.
	days, err := BackfillStatsSnapshots(ctx, store.db, time.Now())
	require.NoError(t, err)
	require.Positive(t, days)
	snapshotsBefore := trendByDay(t, store, daysAgo(100))
	require.NoError(t, store.db.Create(&DownloadStatsDailyModel{
		TimeBucket: daysAgo(45), RegistryID: 1, PackageID: ptr(packageIDUnscoped(t, store, "gone-0")), DownloadCount: 9,
	}).Error)

	cutoff := today().AddDate(0, 0, -30)
	n, err := store.PurgeDeletedPackages(ctx, cutoff, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, n, "bounded by the batch limit")
	require.EqualValues(t, 3, countRows(t, store, "gone-%", true), "oldest deletions go first")

	n, err = store.PurgeDeletedPackages(ctx, cutoff, 100)
	require.NoError(t, err)
	require.EqualValues(t, 3, n)
	n, err = store.PurgeDeletedPackages(ctx, cutoff, 100)
	require.NoError(t, err)
	require.Zero(t, n, "nothing left past the retention")

	require.Zero(t, countRows(t, store, "gone-%", true))
	require.EqualValues(t, 1, countRows(t, store, "recent", true), "a deletion inside the retention stays")
	require.EqualValues(t, 1, countRows(t, store, "live", false), "an active package is never purged")

	var children int64
	for _, table := range []string{"scan_results", "package_vulnerabilities", "package_metadata"} {
		var rows int64
		require.NoError(t, store.db.Table(table).Count(&rows).Error)
		children += rows
	}
	require.EqualValues(t, 1, children, "only the live package keeps its scan row; vulnerability and metadata rows left with their packages")

	var scans int64
	require.NoError(t, store.db.Model(&ScanResultModel{}).Count(&scans).Error)
	require.EqualValues(t, 1, scans)

	require.Equal(t, snapshotsBefore, trendByDay(t, store, daysAgo(100)), "snapshots are untouched")
	var daily int64
	require.NoError(t, store.db.Model(&DownloadStatsDailyModel{}).Count(&daily).Error)
	require.EqualValues(t, 1, daily, "download history is untouched")

	again, err := BackfillStatsSnapshots(ctx, store.db, time.Now())
	require.NoError(t, err)
	require.Zero(t, again, "the backfill never rewrites history after a purge")
}

func packageID(t *testing.T, store *GORMStoreV2, name string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, store.db.Model(&PackageModel{}).Where("name = ?", name).Pluck("id", &id).Error)
	return id
}

func packageIDUnscoped(t *testing.T, store *GORMStoreV2, name string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, store.db.Unscoped().Model(&PackageModel{}).Where("name = ?", name).Pluck("id", &id).Error)
	return id
}

func countRows(t *testing.T, store *GORMStoreV2, namePattern string, deleted bool) int64 {
	t.Helper()
	q := store.db.Unscoped().Model(&PackageModel{}).Where("name LIKE ?", namePattern)
	if deleted {
		q = q.Where("deleted_at IS NOT NULL")
	} else {
		q = q.Where("deleted_at IS NULL")
	}
	var n int64
	require.NoError(t, q.Count(&n).Error)
	return n
}

func TestBackfillStatsSnapshots(t *testing.T) { checkBackfillStatsSnapshots(t, newTimeSeriesStore(t)) }
func TestBackfillWithoutScans(t *testing.T)   { checkBackfillWithoutScans(t, newTimeSeriesStore(t)) }
func TestSnapshotStats(t *testing.T)          { checkSnapshotStats(t, newTimeSeriesStore(t)) }
func TestTrendWindow(t *testing.T)            { checkTrendWindow(t, newTimeSeriesStore(t)) }
func TestTrendStatementsAreConstant(t *testing.T) {
	checkTrendStatementsAreConstant(t, newTimeSeriesStore(t))
}
func TestPurgeDeletedPackages(t *testing.T) { checkPurgeDeletedPackages(t, newTimeSeriesStore(t)) }
