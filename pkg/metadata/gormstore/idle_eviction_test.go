package gormstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func savePkg(t *testing.T, store *GORMStoreV2, name, version string, lastAccessed time.Time, expiresAt *time.Time) {
	t.Helper()
	require.NoError(t, store.SavePackage(context.Background(), &metadata.Package{
		Registry: "npm", Name: name, Version: version,
		StorageKey: fmt.Sprintf("npm/%s/%s", name, version),
		Size:       100, CachedAt: lastAccessed, LastAccessed: lastAccessed, ExpiresAt: expiresAt,
	}))
}

func names(pkgs []*metadata.Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Name
	}
	return out
}

func checkListIdlePackages(t *testing.T, store *GORMStoreV2) {
	ctx := context.Background()
	now := time.Now().UTC()
	savePkg(t, store, "idle-oldest", "1.0.0", now.Add(-10*24*time.Hour), nil)
	savePkg(t, store, "idle-middle", "1.0.0", now.Add(-9*24*time.Hour), nil)
	savePkg(t, store, "idle-newest", "1.0.0", now.Add(-8*24*time.Hour), nil)
	savePkg(t, store, "recent", "1.0.0", now.Add(-24*time.Hour), nil)
	savePkg(t, store, "touched", "1.0.0", now.Add(-12*24*time.Hour), nil)
	require.NoError(t, store.UpdateDownloadCount(ctx, "npm", "touched", "1.0.0"))

	cutoff := now.Add(-7 * 24 * time.Hour)

	batch, err := store.ListIdlePackages(ctx, cutoff, 2)
	require.NoError(t, err)
	require.Equal(t, []string{"idle-oldest", "idle-middle"}, names(batch), "oldest first, capped at the limit")
	require.Equal(t, "npm", batch[0].Registry)
	require.Equal(t, "npm/idle-oldest/1.0.0", batch[0].StorageKey)
	require.Equal(t, int64(100), batch[0].Size)

	for _, p := range batch {
		require.NoError(t, store.DeletePackage(ctx, p.Registry, p.Name, p.Version))
	}
	batch, err = store.ListIdlePackages(ctx, cutoff, 2)
	require.NoError(t, err)
	require.Equal(t, []string{"idle-newest"}, names(batch), "deleted rows leave the result; a touched row is not idle")

	batch, err = store.ListIdlePackages(ctx, cutoff, 0)
	require.NoError(t, err, "a non-positive limit falls back to the default batch size")
	require.Equal(t, []string{"idle-newest"}, names(batch))
}

func checkListExpiredPackages(t *testing.T, store *GORMStoreV2) {
	ctx := context.Background()
	now := time.Now().UTC()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	savePkg(t, store, "stale-meta", "list", now, &past)
	savePkg(t, store, "fresh-meta", "list", now, &future)
	savePkg(t, store, "no-expiry", "1.0.0", now, nil)

	got, err := store.ListExpiredPackages(ctx, now, 10)
	require.NoError(t, err)
	require.Equal(t, []string{"stale-meta"}, names(got))
}

func checkClearArtifactExpiry(t *testing.T, store *GORMStoreV2) {
	ctx := context.Background()
	now := time.Now().UTC()
	exp := now.Add(24 * time.Hour)
	savePkg(t, store, "lodash", "4.17.21", now, &exp)
	savePkg(t, store, "left-pad", "1.3.0", now, &exp)
	savePkg(t, store, "lodash", "list", now, &exp)
	savePkg(t, store, "lodash", "page", now, &exp)
	savePkg(t, store, "lodash", "latest", now, &exp)
	savePkg(t, store, "lodash", "metadata", now, &exp)
	savePkg(t, store, "golang.org/x/text/@v/v0.3.0.mod", "v0.3.0", now, &exp)
	savePkg(t, store, "golang.org/x/text/@v/v0.3.0.info", "v0.3.0", now, &exp)

	cleared, err := store.ClearArtifactExpiry(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), cleared, "only the two artifacts lose their expiry")

	for _, a := range [][2]string{{"lodash", "4.17.21"}, {"left-pad", "1.3.0"}} {
		p, getErr := store.GetPackage(ctx, "npm", a[0], a[1])
		require.NoError(t, getErr)
		require.Nil(t, p.ExpiresAt, a[0])
	}
	for _, m := range [][2]string{
		{"lodash", "list"}, {"lodash", "page"}, {"lodash", "latest"}, {"lodash", "metadata"},
		{"golang.org/x/text/@v/v0.3.0.mod", "v0.3.0"}, {"golang.org/x/text/@v/v0.3.0.info", "v0.3.0"},
	} {
		p, getErr := store.GetPackage(ctx, "npm", m[0], m[1])
		require.NoError(t, getErr)
		require.NotNil(t, p.ExpiresAt, "metadata entry %s@%s keeps its freshness expiry", m[0], m[1])
	}

	again, err := store.ClearArtifactExpiry(ctx)
	require.NoError(t, err)
	require.Zero(t, again, "idempotent")
}

// A deleted package must not change the download totals: history rows carry
// package_id with no foreign key, and the soft delete keeps the package row.
func checkDeleteKeepsDownloadHistory(t *testing.T, store *GORMStoreV2) {
	ctx := context.Background()
	recordDownloads(t, store, 3)
	// Two of the three downloads sit in a completed hour, ready to aggregate.
	require.NoError(t, store.db.Exec(
		"UPDATE download_events SET downloaded_at = ? WHERE id IN (SELECT id FROM (SELECT id FROM download_events ORDER BY id LIMIT 2) AS first_two)",
		time.Now().UTC().Add(-3*time.Hour)).Error)

	total := func(label string) {
		t.Helper()
		for _, period := range []string{"1day", "7day", "30day"} {
			ts, err := store.GetTimeSeriesStats(ctx, period, "")
			require.NoError(t, err)
			require.Equal(t, int64(3), sumPoints(ts), "%s (%s)", label, period)
		}
	}
	total("before delete")

	require.NoError(t, store.DeletePackage(ctx, "npm", "left-pad", "1.3.0"))
	total("after delete")

	// Re-caching the key hard-deletes the stale soft-deleted row.
	now := time.Now()
	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.3.0", StorageKey: "npm/left-pad/1.3.0",
		Size: 10, CachedAt: now, LastAccessed: now,
	}))
	total("after re-cache")

	// Aggregation writes package_id rows for a package that is gone again.
	require.NoError(t, store.DeletePackage(ctx, "npm", "left-pad", "1.3.0"))
	require.NoError(t, store.AggregateDownloadData(ctx))
	total("after delete and aggregation")
}

func TestListIdlePackages(t *testing.T)    { checkListIdlePackages(t, newTimeSeriesStore(t)) }
func TestListExpiredPackages(t *testing.T) { checkListExpiredPackages(t, newTimeSeriesStore(t)) }
func TestClearArtifactExpiry(t *testing.T) { checkClearArtifactExpiry(t, newTimeSeriesStore(t)) }
func TestDeletePackageKeepsDownloadHistory(t *testing.T) {
	checkDeleteKeepsDownloadHistory(t, newTimeSeriesStore(t))
}

func (s *GORMStoreV2TestSuite) Test_V2_ListIdlePackages() { checkListIdlePackages(s.T(), s.store) }
func (s *GORMStoreV2TestSuite) Test_V2_ListExpiredPackages() {
	checkListExpiredPackages(s.T(), s.store)
}
func (s *GORMStoreV2TestSuite) Test_V2_ClearArtifactExpiry() {
	checkClearArtifactExpiry(s.T(), s.store)
}
func (s *GORMStoreV2TestSuite) Test_V2_DeleteKeepsDownloadHistory() {
	checkDeleteKeepsDownloadHistory(s.T(), s.store)
}
