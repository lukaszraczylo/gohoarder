//go:build pgintegration

package gormstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The same scenario the SQLite test runs: both dialects must report the same totals.
func TestPostgresHourlyTotalsMatchSQLite(t *testing.T) {
	store, _ := newPostgresStore(t)
	require.Equal(t, wantHourlyScenario(), runHourlyScenario(t, store))
}
