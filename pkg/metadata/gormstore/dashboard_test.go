package gormstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/internal/dbcount"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var dashboardEpoch = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

type seedRow struct {
	registry, name, version, release string
	size                             int64
	downloads                        int
}

// seedDashboard stores rows with distinct, increasing cache times so orderings are unambiguous.
func seedDashboard(t *testing.T, store *GORMStoreV2, rows []seedRow) {
	t.Helper()
	ctx := context.Background()
	for i, r := range rows {
		at := dashboardEpoch.Add(time.Duration(i) * time.Minute)
		require.NoError(t, store.SavePackage(ctx, &metadata.Package{
			Registry: r.registry, Name: r.name, Version: r.version, ReleaseVersion: r.release,
			StorageKey: fmt.Sprintf("%s/%s/%s", r.registry, r.name, r.version),
			Size:       r.size, CachedAt: at, LastAccessed: at,
		}))
		for d := 0; d < r.downloads; d++ {
			require.NoError(t, store.UpdateDownloadCount(ctx, r.registry, r.name, r.version))
		}
	}
}

func dashboardFixture() []seedRow {
	return []seedRow{
		{"npm", "left-pad", "1.0.0", "", 100, 3},
		{"npm", "left-pad", "1.1.0", "", 110, 1},
		{"npm", "left-pad", "list", "", 5, 0}, // metadata page, never a row
		{"npm", "@scope/pkg", "2.0.0", "", 300, 0},
		{"npm", "react", "18.0.0", "", 900, 7},
		{"npm", "a_b", "1.0.0", "", 10, 0},
		{"npm", "axb", "1.0.0", "", 20, 0},
		{"go", "github.com/a/b/@v/v1.0.0.zip", "v1.0.0", "", 500, 2},
		{"go", "github.com/a/b/@v/v1.0.0.mod", "v1.0.0", "", 10, 0},
		{"go", "github.com/a/b/@v/v1.0.0.info", "v1.0.0", "", 5, 0},
		{"go", "github.com/a/b/@v/v1.1.0.zip", "v1.1.0", "", 520, 0},
		{"go", "github.com/c/d/@v/v0.1.0.zip", "v0.1.0", "", 40, 1},
		{"pypi", "six", "six-1.17.0.tar.gz", "1.17.0", 60, 4},
		{"pypi", "six", "six-1.17.0-py2.py3-none-any.whl", "1.17.0", 20, 0},
	}
}

func rowKeys(pkgs []*metadata.Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Registry + "/" + p.Name + "@" + p.Version
	}
	return out
}

// checkListPackageGroupsMatchesReference compares the SQL paging with the in-memory reference for many option sets.
func checkListPackageGroupsMatchesReference(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	seedDashboard(t, store, dashboardFixture())
	all, err := store.ListPackages(ctx, nil)
	require.NoError(t, err)

	var cases []metadata.GroupListOptions
	for _, sortBy := range []string{"", metadata.GroupSortName, metadata.GroupSortCachedAt, metadata.GroupSortDownloads, metadata.GroupSortSize} {
		for _, desc := range []bool{false, true} {
			for _, filter := range []struct{ registry, q string }{
				{"", ""}, {"go", ""}, {"npm", ""}, {"nowhere", ""}, {"", "LEFT"}, {"", "1.17"}, {"", "a_b"}, {"", "github.com/a"}, {"", "no-such"},
			} {
				for _, size := range []int{0, 2, 3} {
					for page := 1; page <= 3; page++ {
						cases = append(cases, metadata.GroupListOptions{
							Registry: filter.registry, Query: filter.q, SortBy: sortBy, SortDesc: desc, Page: page, PageSize: size,
						})
					}
				}
			}
		}
	}
	for _, opts := range cases {
		got, err := store.ListPackageGroups(ctx, opts)
		require.NoError(t, err, "%+v", opts)
		want := metadata.PageGroups(all, opts)
		require.Equal(t, want.TotalGroups, got.TotalGroups, "total groups %+v", opts)
		require.Equal(t, rowKeys(want.Packages), rowKeys(got.Packages), "rows %+v", opts)
	}
}

func checkListPackageGroupsBehaviour(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	seedDashboard(t, store, dashboardFixture())

	t.Run("metadata pages are not rows and Go variants collapse to the largest", func(t *testing.T) {
		page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Registry: "go"})
		require.NoError(t, err)
		require.Equal(t, int64(2), page.TotalGroups)
		require.ElementsMatch(t, []string{
			"go/github.com/a/b@v1.0.0", "go/github.com/a/b@v1.1.0", "go/github.com/c/d@v0.1.0",
		}, rowKeys(page.Packages))
		for _, p := range page.Packages {
			if p.Version == "v1.0.0" && p.Name == "github.com/a/b" {
				require.EqualValues(t, 500, p.Size, "the .zip outranks .mod and .info")
			}
		}
		npm, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Registry: "npm", Query: "left"})
		require.NoError(t, err)
		require.Equal(t, []string{"npm/left-pad@1.1.0", "npm/left-pad@1.0.0"}, rowKeys(npm.Packages), "newest first, no list page")
	})

	t.Run("a page holds whole groups and total_groups counts all groups", func(t *testing.T) {
		page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Page: 1, PageSize: 2})
		require.NoError(t, err)
		require.EqualValues(t, 8, page.TotalGroups)
		groups := map[string]bool{}
		for _, p := range page.Packages {
			groups[p.Registry+"/"+p.Name] = true
		}
		require.Len(t, groups, 2)
		require.Equal(t, "@scope/pkg", page.Packages[0].Name)
	})

	t.Run("search treats LIKE wildcards literally", func(t *testing.T) {
		page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Query: "a_b"})
		require.NoError(t, err)
		require.Equal(t, []string{"npm/a_b@1.0.0"}, rowKeys(page.Packages))
	})

	t.Run("search finds a release version", func(t *testing.T) {
		page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Query: "1.17.0"})
		require.NoError(t, err)
		require.Len(t, page.Packages, 2)
	})

	t.Run("an unknown registry is an empty page, not an error", func(t *testing.T) {
		page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Registry: "nowhere", PageSize: 5})
		require.NoError(t, err)
		require.Zero(t, page.TotalGroups)
		require.Empty(t, page.Packages)
	})

	t.Run("recent groups come first by cached_at", func(t *testing.T) {
		page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{SortBy: metadata.GroupSortCachedAt, SortDesc: true, Page: 1, PageSize: 1})
		require.NoError(t, err)
		require.Equal(t, "six", page.Packages[0].Name)
	})
}

// checkDashboardStatementsAreConstant proves the statement count does not follow the row count.
func checkDashboardStatementsAreConstant(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	var counter *dbcount.Counter
	store.WrapDB(func(db *gorm.DB) *gorm.DB {
		counted, c := dbcount.Attach(db)
		counter = c
		return counted
	})

	measure := func() map[string]int {
		out := map[string]int{}
		counter.Reset()
		_, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{Page: 1, PageSize: 25, Query: "pkg"})
		require.NoError(t, err)
		out["groups"] = counter.Count()
		counter.Reset()
		_, err = store.ListPackageGroups(ctx, metadata.GroupListOptions{})
		require.NoError(t, err)
		out["all"] = counter.Count()
		counter.Reset()
		_, err = store.GetScanSummaries(ctx, nil, false)
		require.NoError(t, err)
		out["summaries"] = counter.Count()
		counter.Reset()
		_, err = store.GetRegistryStats(ctx)
		require.NoError(t, err)
		out["registry stats"] = counter.Count()
		return out
	}

	seedScanned(t, store, 0, 10)
	small := measure()
	seedScanned(t, store, 10, 90)
	large := measure()
	t.Logf("statements for 10 rows %v, for 100 rows %v", small, large)
	require.Equal(t, small, large)
	require.LessOrEqual(t, large["groups"], 3, "count, keys, rows")
	require.LessOrEqual(t, large["summaries"], 2)
}

// seedScanned stores n scanned packages, each with two scans so the latest-scan pick is exercised.
func seedScanned(t *testing.T, store *GORMStoreV2, from, n int) {
	t.Helper()
	ctx := context.Background()
	for i := from; i < from+n; i++ {
		name := fmt.Sprintf("pkg-%03d", i)
		at := dashboardEpoch.Add(time.Duration(i) * time.Minute)
		require.NoError(t, store.SavePackage(ctx, &metadata.Package{
			Registry: "npm", Name: name, Version: "1.0.0", StorageKey: "npm/" + name,
			Size: 10, CachedAt: at, LastAccessed: at,
		}))
		for _, scanner := range []string{"old", "new"} {
			scan := &metadata.ScanResult{
				Registry: "npm", PackageName: name, PackageVersion: "1.0.0", Scanner: scanner,
				Status: metadata.ScanStatusClean, ScannedAt: at,
			}
			if scanner == "new" {
				scan.ScannedAt = at.Add(time.Hour)
			}
			require.NoError(t, store.SaveScanResult(ctx, scan))
		}
	}
}

func checkScanSummaries(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	ctx := context.Background()
	seedDashboard(t, store, []seedRow{
		{"npm", "clean", "1.0.0", "", 1, 0},
		{"npm", "bad", "1.0.0", "", 1, 0},
		{"npm", "broken", "1.0.0", "", 1, 0},
		{"npm", "lost", "1.0.0", "", 1, 0},
		{"npm", "unscanned", "1.0.0", "", 1, 0},
	})
	save := func(name string, res *metadata.ScanResult) {
		res.Registry, res.PackageName, res.PackageVersion = "npm", name, "1.0.0"
		require.NoError(t, store.SaveScanResult(ctx, res))
	}
	save("clean", &metadata.ScanResult{Scanner: "a", Status: metadata.ScanStatusVulnerable, ScannedAt: dashboardEpoch,
		VulnerabilityCount: 1, Vulnerabilities: []metadata.Vulnerability{{ID: "CVE-1", Severity: "low"}}})
	save("clean", &metadata.ScanResult{Scanner: "b", Status: metadata.ScanStatusClean, ScannedAt: dashboardEpoch.Add(time.Hour)})
	save("bad", &metadata.ScanResult{Scanner: "a", Status: metadata.ScanStatusVulnerable, ScannedAt: dashboardEpoch, VulnerabilityCount: 3,
		Vulnerabilities: []metadata.Vulnerability{
			{ID: "CVE-2", Severity: "critical"}, {ID: "CVE-3", Severity: "HIGH"}, {ID: "CVE-4", Severity: "medium"},
		}})
	save("broken", &metadata.ScanResult{Scanner: "a", Status: metadata.ScanStatusError, ScannedAt: dashboardEpoch,
		Details: map[string]interface{}{"infrastructure_error": true}})
	require.NoError(t, store.db.Model(&PackageModel{}).Where("name = ?", "lost").Update("security_scanned", true).Error)

	byName := func(sums []*metadata.ScanSummary) map[string]*metadata.ScanSummary {
		m := map[string]*metadata.ScanSummary{}
		for _, s := range sums {
			m[s.Name] = s
		}
		return m
	}

	all, err := store.GetScanSummaries(ctx, nil, false)
	require.NoError(t, err)
	sums := byName(all)
	require.Len(t, sums, 4, "the unscanned package has no summary")

	require.Equal(t, metadata.ScanStatusClean, sums["clean"].Status, "the later scan wins")
	require.Zero(t, sums["clean"].Total)
	require.Equal(t, "npm", sums["clean"].Registry)

	bad := sums["bad"]
	require.Equal(t, 3, bad.Total)
	require.Equal(t, [4]int{1, 1, 1, 0}, [4]int{bad.Critical, bad.High, bad.Moderate, bad.Low})
	require.Nil(t, bad.Vulnerabilities, "the list is loaded only on request")

	require.Equal(t, metadata.ScanStatusError, sums["broken"].Status)
	require.Equal(t, true, sums["broken"].Details["infrastructure_error"], "failed scans always carry their details")

	require.False(t, sums["lost"].HasScan)

	withList, err := store.GetScanSummaries(ctx, []string{sums["bad"].PackageID, sums["clean"].PackageID}, true)
	require.NoError(t, err)
	require.Len(t, withList, 2)
	require.Len(t, byName(withList)["bad"].Vulnerabilities, 3)
	require.Equal(t, "CVE-2", byName(withList)["bad"].Vulnerabilities[0].ID)

	none, err := store.GetScanSummaries(ctx, []string{}, false)
	require.NoError(t, err)
	require.Empty(t, none)
}

func checkRegistryStats(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	seedDashboard(t, store, dashboardFixture())
	stats, err := store.GetRegistryStats(context.Background())
	require.NoError(t, err)
	got := map[string]metadata.RegistryStat{}
	for _, s := range stats {
		got[s.Registry] = s
	}
	require.Equal(t, metadata.RegistryStat{Registry: "npm", Count: 6, Size: 100 + 110 + 300 + 900 + 10 + 20, Downloads: 3 + 1 + 7}, got["npm"], "the list page is excluded")
	require.Equal(t, metadata.RegistryStat{Registry: "go", Count: 5, Size: 500 + 10 + 5 + 520 + 40, Downloads: 3}, got["go"])
	require.Equal(t, metadata.RegistryStat{Registry: "pypi", Count: 2, Size: 80, Downloads: 4}, got["pypi"])
}

func TestListPackageGroupsMatchesReference(t *testing.T) {
	checkListPackageGroupsMatchesReference(t, newTimeSeriesStore(t))
}
func TestListPackageGroupsBehaviour(t *testing.T) {
	checkListPackageGroupsBehaviour(t, newTimeSeriesStore(t))
}
func TestDashboardStatementsAreConstant(t *testing.T) {
	checkDashboardStatementsAreConstant(t, newTimeSeriesStore(t))
}
func TestScanSummaries(t *testing.T) { checkScanSummaries(t, newTimeSeriesStore(t)) }
func TestRegistryStats(t *testing.T) { checkRegistryStats(t, newTimeSeriesStore(t)) }

// checkScanIndexMigration drops the index and proves the migration restores it, twice over.
func checkScanIndexMigration(t *testing.T, store *GORMStoreV2) {
	t.Helper()
	m := store.db.Migrator()
	require.True(t, m.HasIndex(&ScanResultModel{}, scanPackageScannedAtIndex), "a fresh schema carries the index")
	require.NoError(t, m.DropIndex(&ScanResultModel{}, scanPackageScannedAtIndex))
	require.False(t, m.HasIndex(&ScanResultModel{}, scanPackageScannedAtIndex))

	for _, migration := range GetMigrations() {
		if migration.ID != "202611240001" {
			continue
		}
		require.NoError(t, migration.Migrate(store.db))
		require.NoError(t, migration.Migrate(store.db), "rerun must be a no-op")
		require.True(t, m.HasIndex(&ScanResultModel{}, scanPackageScannedAtIndex))
		return
	}
	t.Fatal("migration 202611240001 is not registered")
}

func TestScanIndexMigration(t *testing.T) { checkScanIndexMigration(t, newTimeSeriesStore(t)) }

func (s *GORMStoreV2TestSuite) Test_V2_ListPackageGroupsMatchesReference() {
	checkListPackageGroupsMatchesReference(s.T(), s.store)
}
func (s *GORMStoreV2TestSuite) Test_V2_ListPackageGroupsBehaviour() {
	checkListPackageGroupsBehaviour(s.T(), s.store)
}
func (s *GORMStoreV2TestSuite) Test_V2_DashboardStatementsAreConstant() {
	checkDashboardStatementsAreConstant(s.T(), s.store)
}
func (s *GORMStoreV2TestSuite) Test_V2_ScanSummaries()      { checkScanSummaries(s.T(), s.store) }
func (s *GORMStoreV2TestSuite) Test_V2_RegistryStats()      { checkRegistryStats(s.T(), s.store) }
func (s *GORMStoreV2TestSuite) Test_V2_ScanIndexMigration() { checkScanIndexMigration(s.T(), s.store) }
