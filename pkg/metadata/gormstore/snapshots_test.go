package gormstore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/internal/dbcount"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func today() time.Time { return time.Now().UTC().Truncate(day) }

// daysAgo is noon UTC, n days before today.
func daysAgo(n int) time.Time { return today().AddDate(0, 0, -n).Add(12 * time.Hour) }

func seedAt(t *testing.T, store *GORMStoreV2, name, version string, size int64, cachedAt time.Time) {
	t.Helper()
	require.NoError(t, store.SavePackage(context.Background(), &metadata.Package{
		Registry: "npm", Name: name, Version: version, StorageKey: fmt.Sprintf("npm/%s/%s", name, version),
		Size: size, CachedAt: cachedAt, LastAccessed: cachedAt,
	}))
}

func scanAt(t *testing.T, store *GORMStoreV2, name, version string, at time.Time, severities ...string) {
	t.Helper()
	res := &metadata.ScanResult{
		Registry: "npm", PackageName: name, PackageVersion: version, Scanner: "test", ScannedAt: at,
		Status: metadata.ScanStatusClean,
	}
	for i, sev := range severities {
		res.Status = metadata.ScanStatusVulnerable
		res.Vulnerabilities = append(res.Vulnerabilities, metadata.Vulnerability{ID: fmt.Sprintf("CVE-%d", i), Severity: sev})
	}
	res.VulnerabilityCount = len(severities)
	require.NoError(t, store.SaveScanResult(context.Background(), res))
}

// softDeleteAt deletes the package and backdates the deletion.
func softDeleteAt(t *testing.T, store *GORMStoreV2, name, version string, at time.Time) {
	t.Helper()
	require.NoError(t, store.DeletePackage(context.Background(), "npm", name, version))
	require.NoError(t, store.db.Unscoped().Model(&PackageModel{}).
		Where("name = ? AND version = ?", name, version).Update("deleted_at", at).Error)
}

func trendByDay(t *testing.T, store *GORMStoreV2, since time.Time) map[string]*metadata.StatsSnapshot {
	t.Helper()
	pts, err := store.GetStatsTrend(context.Background(), since)
	require.NoError(t, err)
	out := map[string]*metadata.StatsSnapshot{}
	for _, p := range pts {
		out[p.Date] = p
	}
	return out
}

func vulns(p *metadata.StatsSnapshot) [5]int64 {
	get := func(v *int64) int64 {
		if v == nil {
			return -1
		}
		return *v
	}
	return [5]int64{get(p.VulnerablePackages), get(p.Critical), get(p.High), get(p.Moderate), get(p.Low)}
}

// checkBackfillStatsSnapshots seeds a five-day history and proves the reconstruction day by day.
func checkBackfillStatsSnapshots(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()

	seedAt(t, store, "a", "1.0.0", 10, daysAgo(5))
	seedAt(t, store, "b", "1.0.0", 20, daysAgo(4))
	seedAt(t, store, "a", "list", 5, daysAgo(5))                  // metadata page: never counted
	seedAt(t, store, "mod/@v/v1.mod", "v1", 7, daysAgo(5))        // Go .mod file: never counted
	seedAt(t, store, "early", "1.0.0", 40, daysAgo(2))            // cached and deleted the same day
	scanAt(t, store, "b", "1.0.0", daysAgo(4), "high")            // first scan: vulnerability history starts here
	scanAt(t, store, "a", "1.0.0", daysAgo(3), "critical", "low") // critical wins over low
	scanAt(t, store, "a", "1.0.0", daysAgo(1))                    // clean rescan
	softDeleteAt(t, store, "b", "1.0.0", daysAgo(2))
	softDeleteAt(t, store, "early", "1.0.0", daysAgo(2).Add(time.Hour))

	days, err := BackfillStatsSnapshots(ctx, store.db, time.Now())
	require.NoError(t, err)
	require.Equal(t, 5, days, "day -5 to day -1; today belongs to the live snapshot")

	got := trendByDay(t, store, daysAgo(10))
	require.Len(t, got, 5)
	day := func(n int) *metadata.StatsSnapshot {
		p, ok := got[dayString(daysAgo(n))]
		require.True(t, ok, "day -%d", n)
		return p
	}

	require.EqualValues(t, 1, day(5).TotalPackages)
	require.EqualValues(t, 10, day(5).TotalSize)
	require.Equal(t, [5]int64{-1, -1, -1, -1, -1}, vulns(day(5)), "no scan existed yet: unknown, not zero")

	require.EqualValues(t, 2, day(4).TotalPackages)
	require.EqualValues(t, 30, day(4).TotalSize)
	require.Equal(t, [5]int64{1, 0, 1, 0, 0}, vulns(day(4)))

	require.EqualValues(t, 2, day(3).TotalPackages)
	require.Equal(t, [5]int64{2, 1, 1, 0, 0}, vulns(day(3)))

	require.EqualValues(t, 1, day(2).TotalPackages, "b was deleted on day -2; early lived and died within it")
	require.EqualValues(t, 10, day(2).TotalSize)
	require.Equal(t, [5]int64{1, 1, 0, 0, 0}, vulns(day(2)))

	require.EqualValues(t, 1, day(1).TotalPackages)
	require.Equal(t, [5]int64{0, 0, 0, 0, 0}, vulns(day(1)), "the clean rescan clears the vulnerability")
	require.Nil(t, day(1).Blocked, "the policy of a past day is not reconstructable")

	again, err := BackfillStatsSnapshots(ctx, store.db, time.Now())
	require.NoError(t, err)
	require.Zero(t, again, "a second run is a no-op")
	require.Len(t, trendByDay(t, store, daysAgo(10)), 5)
}

// checkBackfillWithoutScans proves that without scan history only package counts are written.
func checkBackfillWithoutScans(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	days, err := BackfillStatsSnapshots(ctx, store.db, time.Now())
	require.NoError(t, err)
	require.Zero(t, days, "no packages, no history")

	seedAt(t, store, "a", "1.0.0", 10, daysAgo(2))
	days, err = BackfillStatsSnapshots(ctx, store.db, time.Now())
	require.NoError(t, err)
	require.Equal(t, 2, days)
	for _, p := range trendByDay(t, store, daysAgo(10)) {
		require.EqualValues(t, 1, p.TotalPackages)
		require.Equal(t, [5]int64{-1, -1, -1, -1, -1}, vulns(p))
	}
}

func checkSnapshotStats(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	seedAt(t, store, "a", "1.0.0", 10, daysAgo(1))
	seedAt(t, store, "b", "1.0.0", 20, daysAgo(1))
	seedAt(t, store, "c", "1.0.0", 30, daysAgo(1))
	scanAt(t, store, "a", "1.0.0", daysAgo(1), "critical")
	scanAt(t, store, "b", "1.0.0", daysAgo(1), "moderate")

	// An in-memory database has no running worker; this one is the test's own.
	worker := store.aggregationWorker
	store.SetBlockedCounter(func(context.Context) (int64, error) { return 1, nil })
	require.NoError(t, worker.SnapshotStats(ctx))
	require.NoError(t, worker.SnapshotStats(ctx), "the same day twice writes one row")

	rows := trendByDay(t, store, today())
	require.Len(t, rows, 1)
	snap := rows[dayString(time.Now())]
	require.NotNil(t, snap)
	require.EqualValues(t, 3, snap.TotalPackages)
	require.EqualValues(t, 60, snap.TotalSize)
	require.Equal(t, [5]int64{2, 1, 0, 1, 0}, vulns(snap))
	require.EqualValues(t, 1, *snap.Blocked)

	// The next run of the day replaces the counts.
	scanAt(t, store, "a", "1.0.0", daysAgo(0).Add(-time.Hour), "high")
	store.SetBlockedCounter(nil)
	require.NoError(t, worker.SnapshotStats(ctx))
	snap = trendByDay(t, store, today())[dayString(time.Now())]
	require.Equal(t, [5]int64{2, 0, 1, 1, 0}, vulns(snap))
	require.EqualValues(t, 1, *snap.Blocked, "a run without a blocking policy keeps the earlier count")

	store.SetBlockedCounter(func(context.Context) (int64, error) { return 0, errors.New("scanner down") })
	require.NoError(t, worker.SnapshotStats(ctx), "a failed blocked count must not lose the snapshot")
}

func checkTrendWindow(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	for i := 0; i < 5; i++ {
		require.NoError(t, store.db.Create(&StatsSnapshotModel{Day: dayString(daysAgo(i)), TotalPackages: int64(i)}).Error)
	}
	pts, err := store.GetStatsTrend(context.Background(), daysAgo(2))
	require.NoError(t, err)
	require.Len(t, pts, 3)
	require.Equal(t, dayString(daysAgo(2)), pts[0].Date, "oldest first, from the since day inclusive")
	require.Equal(t, dayString(daysAgo(0)), pts[2].Date)
	require.Nil(t, pts[0].VulnerablePackages)

	none, err := store.GetStatsTrend(context.Background(), today().AddDate(0, 0, 1))
	require.NoError(t, err)
	require.Empty(t, none)
}

// attachCounter counts the statements of the store and of its worker, which holds its own handle.
func attachCounter(store *GORMStoreV2) *dbcount.Counter {
	var counter *dbcount.Counter
	store.WrapDB(func(db *gorm.DB) *gorm.DB {
		counted, c := dbcount.Attach(db)
		counter = c
		return counted
	})
	store.aggregationWorker.db = store.db
	return counter
}

func checkTrendStatementsAreConstant(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	counter := attachCounter(store)

	measure := func() map[string]int {
		out := map[string]int{}
		counter.Reset()
		_, err := store.GetStatsTrend(ctx, daysAgo(365))
		require.NoError(t, err)
		out["trend"] = counter.Count()
		counter.Reset()
		require.NoError(t, store.aggregationWorker.SnapshotStats(ctx))
		out["snapshot"] = counter.Count()
		require.NoError(t, store.db.Exec("DELETE FROM stats_snapshots").Error)
		counter.Reset()
		_, err = BackfillStatsSnapshots(ctx, store.db, time.Now().AddDate(0, 0, 400))
		require.NoError(t, err)
		out["backfill"] = counter.Count()
		return out
	}

	seedScanned(t, store, 0, 10)
	small := measure()
	seedScanned(t, store, 10, 90)
	large := measure()
	t.Logf("statements for 10 packages %v, for 100 packages %v", small, large)
	require.Equal(t, small, large)
	require.Equal(t, 1, large["trend"])
	require.Equal(t, 2, large["snapshot"], "one aggregate read, one upsert")
	require.LessOrEqual(t, large["backfill"], 4, "count, packages, scans, one insert batch")
	require.Positive(t, large["backfill"])
}

func TestStatsSnapshotMigration(t *testing.T) {
	store := newTimeSeriesStore(t)
	seedAt(t, store, "a", "1.0.0", 10, daysAgo(2))
	require.NoError(t, store.db.Migrator().DropTable(&StatsSnapshotModel{}))
	for _, migration := range GetMigrations() {
		if migration.ID != "202611250001" {
			continue
		}
		require.NoError(t, migration.Migrate(store.db))
		require.NoError(t, migration.Migrate(store.db), "rerun must be a no-op")
		require.Len(t, trendByDay(t, store, daysAgo(10)), 2, "the migration seeds the history")
		return
	}
	t.Fatal("migration 202611250001 is not registered")
}
