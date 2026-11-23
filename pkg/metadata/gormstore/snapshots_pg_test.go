//go:build pgintegration

package gormstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostgresTrendSeverityAndPurge(t *testing.T) {
	store, _ := newPostgresStore(t)

	reset := func(t *testing.T) {
		t.Helper()
		require.NoError(t, store.db.Exec(
			"TRUNCATE packages, stats_snapshots, download_stats_daily RESTART IDENTITY CASCADE").Error)
	}
	for name, check := range map[string]func(*testing.T, *GORMStoreV2){
		"backfill":                     checkBackfillStatsSnapshots,
		"backfill without scans":       checkBackfillWithoutScans,
		"snapshot":                     checkSnapshotStats,
		"trend window":                 checkTrendWindow,
		"trend statements constant":    checkTrendStatementsAreConstant,
		"severity filter":              checkSeverityFilter,
		"severity statements constant": checkSeverityFilterStatementsAreConstant,
	} {
		t.Run(name, func(t *testing.T) {
			reset(t)
			check(t, store)
		})
	}
}

func TestPostgresStatsSnapshotsHaveNoPackageForeignKey(t *testing.T) {
	store, _ := newPostgresStore(t)

	var referencing []string
	require.NoError(t, store.db.Raw(
		"SELECT conrelid::regclass::text FROM pg_constraint WHERE contype = 'f' AND confrelid = 'packages'::regclass",
	).Scan(&referencing).Error)
	require.NotContains(t, referencing, "stats_snapshots", "a package purge must not cascade over history")
}
