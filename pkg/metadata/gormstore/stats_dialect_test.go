package gormstore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// statsScenario drives the same hourly passes on any dialect and returns the
// observable totals, so SQLite and PostgreSQL can be held to one expectation.
type statsScenario struct {
	packageRows, registryRows int64
	packageCount, registryCnt int64
	chartTotal                int64
}

func runHourlyScenario(t *testing.T, store *GORMStoreV2) statsScenario {
	t.Helper()
	hour := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)

	seedEventsAt(t, store, hour.Add(10*time.Minute), hour.Add(20*time.Minute))
	tick(t, store, hour.Add(2*time.Hour), false)
	tick(t, store, hour.Add(2*time.Hour+5*time.Minute), false) // nothing new: must change nothing

	seedEventsAt(t, store, hour.Add(50*time.Minute)) // a late download for the same bucket
	tick(t, store, hour.Add(3*time.Hour), false)

	var s statsScenario
	db := store.db.Table("download_stats_hourly")
	require.NoError(t, db.Where("package_id IS NOT NULL").Count(&s.packageRows).Error)
	require.NoError(t, store.db.Table("download_stats_hourly").Where("package_id IS NULL").Count(&s.registryRows).Error)
	require.NoError(t, store.db.Table("download_stats_hourly").Where("package_id IS NOT NULL").Select("COALESCE(SUM(download_count),0)").Scan(&s.packageCount).Error)
	require.NoError(t, store.db.Table("download_stats_hourly").Where("package_id IS NULL").Select("COALESCE(SUM(download_count),0)").Scan(&s.registryCnt).Error)
	s.chartTotal = totalAt(t, store, hour.Add(3*time.Hour+10*time.Minute), "24hour")
	return s
}

func wantHourlyScenario() statsScenario {
	return statsScenario{packageRows: 1, registryRows: 1, packageCount: 3, registryCnt: 3, chartTotal: 3}
}

// SQLite carried no unique index, so INSERT OR REPLACE inserted a new row every pass.
func TestSQLiteHourlyTotalsMatchPostgresSemantics(t *testing.T) {
	store := newTimeSeriesStore(t)
	require.Equal(t, wantHourlyScenario(), runHourlyScenario(t, store))
}

func TestSQLiteDailyRollupIsIdempotent(t *testing.T) {
	store := newTimeSeriesStore(t)
	day := time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC)
	seedEventsAt(t, store, day.Add(5*time.Hour), day.Add(6*time.Hour))
	tick(t, store, day.Add(24*time.Hour+30*time.Minute), false)
	for i := 0; i < 3; i++ {
		store.aggregationWorker.now = func() time.Time { return day.Add(25 * time.Hour) }
		require.NoError(t, store.aggregationWorker.AggregateDaily())
	}

	var rows, total int64
	require.NoError(t, store.db.Table("download_stats_daily").Where("package_id IS NOT NULL").Count(&rows).Error)
	require.NoError(t, store.db.Table("download_stats_daily").Where("package_id IS NOT NULL").Select("COALESCE(SUM(download_count),0)").Scan(&total).Error)
	require.EqualValues(t, 1, rows)
	require.EqualValues(t, 2, total)
}

// Databases written by the old code hold duplicate rows; the migration merges them.
func TestSQLiteStatsDedupeMigration(t *testing.T) {
	store := newTimeSeriesStore(t)
	for _, name := range []string{"idx_stats_hourly_upsert", "idx_stats_daily_upsert"} {
		require.NoError(t, store.db.Exec("DROP INDEX IF EXISTS "+name).Error)
	}
	bucket := "2026-03-10 05:00:00"
	insert := func(table string, pkg any, n int) {
		require.NoError(t, store.db.Exec(
			"INSERT INTO "+table+" (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at) VALUES (1, ?, ?, ?, 1, 0, datetime('now'), datetime('now'))",
			pkg, bucket, n).Error)
	}
	// Package rows from separate passes hold disjoint events: they add up.
	insert("download_stats_hourly", 7, 2)
	insert("download_stats_hourly", 7, 3)
	// Registry rows are derived copies: one survives.
	insert("download_stats_hourly", nil, 5)
	insert("download_stats_hourly", nil, 5)
	insert("download_stats_daily", nil, 5)
	insert("download_stats_daily", nil, 5)

	require.NoError(t, ensureSQLiteStatsIndexes(store.db))

	count := func(table, where string) (rows, total int64) {
		require.NoError(t, store.db.Table(table).Where(where).Count(&rows).Error)
		require.NoError(t, store.db.Table(table).Where(where).Select("COALESCE(SUM(download_count),0)").Scan(&total).Error)
		return
	}
	rows, total := count("download_stats_hourly", "package_id = 7")
	require.EqualValues(t, 1, rows)
	require.EqualValues(t, 5, total)
	rows, total = count("download_stats_hourly", "package_id IS NULL")
	require.EqualValues(t, 1, rows)
	require.EqualValues(t, 5, total)
	rows, _ = count("download_stats_daily", "package_id IS NULL")
	require.EqualValues(t, 1, rows)

	require.Error(t, store.db.Exec(
		"INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at) VALUES (1, NULL, ?, 1, 1, 0, datetime('now'), datetime('now'))", bucket).Error,
		"unique index must reject a duplicate registry row")
}
