//go:build pgintegration

package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newPostgresStore(t *testing.T) (*GORMStoreV2, string) {
	t.Helper()
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	store, err := NewV2(Config{Driver: "postgres", DSN: connStr, LogLevel: "silent"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store, connStr
}

func TestPostgresPartitionsBothTables(t *testing.T) {
	store, connStr := newPostgresStore(t)

	second, err := NewV2(Config{Driver: "postgres", DSN: connStr, LogLevel: "silent"})
	require.NoError(t, err, "a second start must accept the converted tables")
	defer func() { _ = second.Close() }()

	for _, table := range []string{"download_events", "audit_log"} {
		var partitioned bool
		require.NoError(t, store.db.Raw(
			"SELECT EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid = ?::regclass)", table,
		).Scan(&partitioned).Error)
		require.True(t, partitioned, table)

		var parts int64
		require.NoError(t, store.db.Raw(
			"SELECT COUNT(*) FROM pg_inherits WHERE inhparent = ?::regclass", table,
		).Scan(&parts).Error)
		require.Positive(t, parts, table)
	}
}

func TestPostgresHourlyAggregationUpserts(t *testing.T) {
	store, _ := newPostgresStore(t)

	old := time.Now().UTC().Add(-3 * time.Hour)
	for i := 0; i < 2; i++ {
		require.NoError(t, store.db.Exec(
			"INSERT INTO download_events (package_id, registry_id, downloaded_at, ip_address, authenticated) VALUES (1, 1, ?, '10.0.0.1', false)",
			old,
		).Error)
	}

	require.NoError(t, store.aggregationWorker.AggregateHourly())

	var count int64
	require.NoError(t, store.db.Raw("SELECT COALESCE(SUM(download_count), 0) FROM download_stats_hourly WHERE package_id = 1").Scan(&count).Error)
	require.Equal(t, int64(2), count)

	var registryTotal int64
	require.NoError(t, store.db.Raw("SELECT COALESCE(SUM(download_count), 0) FROM download_stats_hourly WHERE package_id IS NULL").Scan(&registryTotal).Error)
	require.Equal(t, int64(2), registryTotal)
}

func TestPostgresDailyAggregationUpserts(t *testing.T) {
	store, _ := newPostgresStore(t)

	bucket := time.Now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
	require.NoError(t, store.db.Exec(
		"INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at) VALUES (1, NULL, ?, 5, 2, 0, NOW(), NOW())",
		bucket,
	).Error)

	require.NoError(t, store.aggregationWorker.AggregateDaily())

	var count int64
	require.NoError(t, store.db.Raw("SELECT COALESCE(SUM(download_count), 0) FROM download_stats_daily").Scan(&count).Error)
	require.Equal(t, int64(5), count)
}

func TestPostgresDropsEmptyLegacyEventsTable(t *testing.T) {
	store, connStr := newPostgresStore(t)
	require.NoError(t, store.db.Exec("CREATE TABLE download_events_old (id BIGINT)").Error)

	second, err := NewV2(Config{Driver: "postgres", DSN: connStr, LogLevel: "silent"})
	require.NoError(t, err)
	defer func() { _ = second.Close() }()
	require.False(t, second.db.Migrator().HasTable("download_events_old"))

	require.NoError(t, second.db.Exec("CREATE TABLE download_events_old (id BIGINT)").Error)
	require.NoError(t, second.db.Exec("INSERT INTO download_events_old VALUES (1)").Error)
	third, err := NewV2(Config{Driver: "postgres", DSN: connStr, LogLevel: "silent"})
	require.NoError(t, err)
	defer func() { _ = third.Close() }()
	require.True(t, third.db.Migrator().HasTable("download_events_old"), "a table with rows must stay")
}

func TestPostgresAddsReleaseVersionToExistingPackages(t *testing.T) {
	ctx := context.Background()
	store, connStr := newPostgresStore(t)
	require.NoError(t, store.db.Exec("ALTER TABLE packages DROP COLUMN release_version").Error)

	second, err := NewV2(Config{Driver: "postgres", DSN: connStr, LogLevel: "silent"})
	require.NoError(t, err, "start on a schema without the column")
	defer func() { _ = second.Close() }()

	now := time.Now()
	const key = "six-1.17.0.tar.gz"
	require.NoError(t, second.SavePackage(ctx, &metadata.Package{
		Registry: "pypi", Name: "six", Version: key, ReleaseVersion: "1.17.0",
		StorageKey: "pypi/six/" + key, Size: 1, CachedAt: now, LastAccessed: now,
	}))
	got, err := second.GetPackage(ctx, "pypi", "six", key)
	require.NoError(t, err)
	require.Equal(t, "1.17.0", got.ReleaseVersion)
}

func TestPostgresTimeSeriesMergesRawAndAggregated(t *testing.T) {
	ctx := context.Background()
	store, _ := newPostgresStore(t)
	recordDownloads(t, store, 2)
	// Two downloads in a completed hour get aggregated; two more stay raw.
	require.NoError(t, store.db.Exec("UPDATE download_events SET downloaded_at = ?", time.Now().UTC().Add(-3*time.Hour)).Error)
	require.NoError(t, store.AggregateDownloadData(ctx))
	require.NoError(t, store.UpdateDownloadCount(ctx, "npm", "left-pad", "1.3.0"))
	require.NoError(t, store.UpdateDownloadCount(ctx, "npm", "left-pad", "1.3.0"))

	for _, period := range []string{"1h", "1day", "7day", "30day"} {
		ts, err := store.GetTimeSeriesStats(ctx, period, "npm")
		require.NoError(t, err, period)
		want := int64(4)
		if period == "1h" {
			want = 2 // the aggregated hour is outside the window
		}
		require.Equal(t, want, sumPoints(ts), period)
	}
}
