//go:build pgintegration

package gormstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostgresIdleEviction(t *testing.T) {
	store, _ := newPostgresStore(t)

	reset := func(t *testing.T) {
		t.Helper()
		require.NoError(t, store.db.Exec(
			"TRUNCATE packages, download_events, download_stats_hourly, download_stats_daily RESTART IDENTITY CASCADE").Error)
	}
	for name, check := range map[string]func(*testing.T, *GORMStoreV2){
		"list idle":             checkListIdlePackages,
		"list expired":          checkListExpiredPackages,
		"clear artifact expiry": checkClearArtifactExpiry,
		"delete keeps history":  checkDeleteKeepsDownloadHistory,
	} {
		t.Run(name, func(t *testing.T) {
			reset(t)
			check(t, store)
		})
	}
}

func TestPostgresHistoryTablesHaveNoPackageForeignKey(t *testing.T) {
	store, _ := newPostgresStore(t)

	var referencing []string
	require.NoError(t, store.db.Raw(
		"SELECT conrelid::regclass::text FROM pg_constraint WHERE contype = 'f' AND confrelid = 'packages'::regclass",
	).Scan(&referencing).Error)
	for _, table := range []string{"download_events", "download_stats_hourly", "download_stats_daily"} {
		require.NotContains(t, referencing, table, "%s must not reference packages: a package delete would restrict or cascade over history", table)
	}
}
