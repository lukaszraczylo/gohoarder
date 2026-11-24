package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

var trendingNow = time.Date(2026, 11, 24, 10, 30, 0, 0, time.UTC)

func trendingStore(t *testing.T) *GORMStoreV2 {
	t.Helper()
	store := newTimeSeriesStore(t)
	store.now = func() time.Time { return trendingNow }
	return store
}

func trendingPackage(t *testing.T, store *GORMStoreV2, registry, name, version string) int64 {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: registry, Name: name, Version: version, StorageKey: registry + "/" + name + "/" + version,
		Size: 10, CachedAt: trendingNow, LastAccessed: trendingNow,
	}))
	var pkg PackageModel
	require.NoError(t, store.db.Where("name = ? AND version = ?", name, version).First(&pkg).Error)
	return pkg.ID
}

func trendingEvents(t *testing.T, store *GORMStoreV2, packageID int64, at time.Time, n int) {
	t.Helper()
	var pkg PackageModel
	require.NoError(t, store.db.First(&pkg, packageID).Error)
	for i := 0; i < n; i++ {
		require.NoError(t, store.db.Create(&DownloadEventModel{PackageID: packageID, RegistryID: pkg.RegistryID, DownloadedAt: at}).Error)
	}
}

func trendingStat(t *testing.T, store *GORMStoreV2, model interface{}, packageID int64, bucket time.Time, n int64) {
	t.Helper()
	var pkg PackageModel
	require.NoError(t, store.db.First(&pkg, packageID).Error)
	switch model.(type) {
	case *DownloadStatsHourlyModel:
		require.NoError(t, store.db.Create(&DownloadStatsHourlyModel{RegistryID: pkg.RegistryID, PackageID: &packageID, TimeBucket: bucket, DownloadCount: n}).Error)
	default:
		require.NoError(t, store.db.Create(&DownloadStatsDailyModel{RegistryID: pkg.RegistryID, PackageID: &packageID, TimeBucket: bucket, DownloadCount: n}).Error)
	}
}

func TestTrendingCombinesEventsHourlyAndPreviousWeek(t *testing.T) {
	store := trendingStore(t)
	ctx := context.Background()
	pad := trendingPackage(t, store, "npm", "left-pad", "1.3.0")

	trendingEvents(t, store, pad, trendingNow.Add(-10*time.Minute), 2)
	trendingStat(t, store, &DownloadStatsHourlyModel{}, pad, trendingNow.Add(-3*24*time.Hour).Truncate(time.Hour), 5)
	trendingStat(t, store, &DownloadStatsDailyModel{}, pad, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC), 4)
	trendingStat(t, store, &DownloadStatsDailyModel{}, pad, time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), 3)

	got, err := store.GetTrendingPackages(ctx, 10)
	require.NoError(t, err)
	require.Equal(t, []*metadata.TrendingPackage{{Registry: "npm", Name: "left-pad", Recent: 7, Previous: 7}}, got)
}

func TestTrendingExcludesDownloadsOutsideBothWindows(t *testing.T) {
	store := trendingStore(t)
	pad := trendingPackage(t, store, "npm", "left-pad", "1.3.0")
	trendingStat(t, store, &DownloadStatsDailyModel{}, pad, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), 50)
	trendingStat(t, store, &DownloadStatsDailyModel{}, pad, time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC), 60)
	trendingEvents(t, store, pad, trendingNow.Add(-time.Minute), 1)

	got, err := store.GetTrendingPackages(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, int64(1), got[0].Recent)
	require.Equal(t, int64(0), got[0].Previous)
}

func TestTrendingKeepsOnlyPackagesDownloadedThisWeek(t *testing.T) {
	store := trendingStore(t)
	old := trendingPackage(t, store, "npm", "old", "1.0.0")
	trendingStat(t, store, &DownloadStatsDailyModel{}, old, time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), 9)

	got, err := store.GetTrendingPackages(context.Background(), 10)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestTrendingCountsGoModuleOnceAndSkipsMetadata(t *testing.T) {
	store := trendingStore(t)
	zip := trendingPackage(t, store, "go", "github.com/google/uuid/@v/v1.6.0.zip", "v1.6.0")
	mod := trendingPackage(t, store, "go", "github.com/google/uuid/@v/v1.6.0.mod", "v1.6.0")
	list := trendingPackage(t, store, "go", "github.com/google/uuid/@v/list", "list")
	other := trendingPackage(t, store, "go", "github.com/google/uuid/@v/v1.5.0.zip", "v1.5.0")
	meta := trendingPackage(t, store, "npm", "left-pad", "metadata")
	for _, id := range []int64{zip, mod, list, meta} {
		trendingEvents(t, store, id, trendingNow.Add(-time.Hour), 3)
	}
	trendingEvents(t, store, other, trendingNow.Add(-time.Hour), 2)

	got, err := store.GetTrendingPackages(context.Background(), 10)
	require.NoError(t, err)
	require.Equal(t, []*metadata.TrendingPackage{{Registry: "go", Name: "github.com/google/uuid", Recent: 5}}, got)
}

func TestTrendingKeysByRegistryAndRanksWithLimit(t *testing.T) {
	store := trendingStore(t)
	npm := trendingPackage(t, store, "npm", "six", "1.0.0")
	pypi := trendingPackage(t, store, "pypi", "six", "six-1.0.tar.gz")
	third := trendingPackage(t, store, "npm", "a", "1.0.0")
	trendingEvents(t, store, npm, trendingNow.Add(-time.Hour), 4)
	trendingEvents(t, store, pypi, trendingNow.Add(-time.Hour), 6)
	trendingEvents(t, store, third, trendingNow.Add(-time.Hour), 1)

	got, err := store.GetTrendingPackages(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, []*metadata.TrendingPackage{
		{Registry: "pypi", Name: "six", Recent: 6},
		{Registry: "npm", Name: "six", Recent: 4},
	}, got)
}

func TestTrendingSurvivesAggregation(t *testing.T) {
	store := newTimeSeriesStore(t)
	recordDownloads(t, store, 3)
	require.NoError(t, store.db.Exec("UPDATE download_events SET downloaded_at = ?", time.Now().Add(-3*time.Hour)).Error)
	require.NoError(t, store.AggregateDownloadData(context.Background()))
	var raw int64
	require.NoError(t, store.db.Table("download_events").Count(&raw).Error)
	require.Zero(t, raw, "events are rolled into hourly rows")

	got, err := store.GetTrendingPackages(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, int64(3), got[0].Recent)
}

func TestDailyTimeIndexExists(t *testing.T) {
	store := trendingStore(t)
	require.True(t, store.db.Migrator().HasIndex(&DownloadStatsDailyModel{}, dailyTimeIndex))
}
