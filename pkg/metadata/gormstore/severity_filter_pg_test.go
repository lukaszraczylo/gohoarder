//go:build pgintegration

package gormstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostgresSeverityFilter(t *testing.T) {
	store, _ := newPostgresStore(t)

	for name, check := range map[string]func(*testing.T, *GORMStoreV2){
		"severity filter":              checkSeverityFilter,
		"severity statements constant": checkSeverityFilterStatementsAreConstant,
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, store.db.Exec("TRUNCATE packages RESTART IDENTITY CASCADE").Error)
			check(t, store)
		})
	}
}
