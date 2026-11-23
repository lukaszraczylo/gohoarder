//go:build pgintegration

package gormstore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestPostgresDashboardQueries(t *testing.T) {
	store, _ := newPostgresStore(t)

	reset := func(t *testing.T) {
		t.Helper()
		require.NoError(t, store.db.Exec("TRUNCATE packages RESTART IDENTITY CASCADE").Error)
	}
	for name, check := range map[string]func(*testing.T, *GORMStoreV2){
		"groups match the reference":  checkListPackageGroupsMatchesReference,
		"group behaviour":             checkListPackageGroupsBehaviour,
		"statement count is constant": checkDashboardStatementsAreConstant,
		"scan summaries":              checkScanSummaries,
		"registry stats":              checkRegistryStats,
	} {
		t.Run(name, func(t *testing.T) {
			reset(t)
			check(t, store)
		})
	}
}

// With sequential scans disabled the latest-scan lookup must run on the new index.
func TestPostgresLatestScanLookupUsesIndex(t *testing.T) {
	store, _ := newPostgresStore(t)
	seedScanned(t, store, 0, 20)

	var plan []string
	require.NoError(t, store.db.Connection(func(tx *gorm.DB) error {
		if err := tx.Exec("SET enable_seqscan = off").Error; err != nil {
			return err
		}
		return tx.Raw(`EXPLAIN SELECT id, package_id FROM scan_results
			WHERE package_id IN (1, 2, 3)
			AND scanned_at = (SELECT MAX(x.scanned_at) FROM scan_results x WHERE x.package_id = scan_results.package_id AND x.deleted_at IS NULL)
			AND deleted_at IS NULL`).Scan(&plan).Error
	}))
	require.Contains(t, strings.Join(plan, "\n"), scanPackageScannedAtIndex)
}
