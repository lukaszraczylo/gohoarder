//go:build pgintegration

package gormstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostgresPurgeDeletedPackages(t *testing.T) {
	store, _ := newPostgresStore(t)
	require.NoError(t, store.db.Exec("TRUNCATE packages, stats_snapshots, download_stats_daily RESTART IDENTITY CASCADE").Error)

	checkPurgeDeletedPackages(t, store)
}
