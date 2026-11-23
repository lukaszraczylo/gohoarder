package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func TestDropEmptyTable(t *testing.T) {
	store := newTimeSeriesStore(t)
	db := store.db

	require.NoError(t, dropEmptyTable(db, "never_existed"), "a missing table is not an error")

	require.NoError(t, db.Exec("CREATE TABLE empty_old (id INTEGER)").Error)
	require.NoError(t, dropEmptyTable(db, "empty_old"))
	require.False(t, db.Migrator().HasTable("empty_old"))

	require.NoError(t, db.Exec("CREATE TABLE full_old (id INTEGER)").Error)
	require.NoError(t, db.Exec("INSERT INTO full_old VALUES (1)").Error)
	require.NoError(t, dropEmptyTable(db, "full_old"))
	require.True(t, db.Migrator().HasTable("full_old"), "a table with rows must stay")
}

func TestReleaseVersionRoundTrips(t *testing.T) {
	ctx := context.Background()
	store := newTimeSeriesStore(t)
	now := time.Now()
	const key = "six-1.17.0-py2.py3-none-any.whl"
	pkg := &metadata.Package{
		Registry: "pypi", Name: "six", Version: key, ReleaseVersion: "1.17.0",
		StorageKey: "pypi/six/" + key, Size: 1, CachedAt: now, LastAccessed: now,
	}
	require.NoError(t, store.SavePackage(ctx, pkg))

	got, err := store.GetPackage(ctx, "pypi", "six", key)
	require.NoError(t, err)
	require.Equal(t, "1.17.0", got.ReleaseVersion)

	pkg.ReleaseVersion = "1.17.1"
	require.NoError(t, store.SavePackage(ctx, pkg))
	got, err = store.GetPackage(ctx, "pypi", "six", key)
	require.NoError(t, err)
	require.Equal(t, "1.17.1", got.ReleaseVersion, "an update must overwrite the release version")
}
