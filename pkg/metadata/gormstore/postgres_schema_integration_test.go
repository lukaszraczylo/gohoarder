//go:build pgintegration

package gormstore

import (
	"context"
	"testing"
	"time"

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
