package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCleanName(t *testing.T) {
	require.Equal(t, "github.com/a/b", CleanName("github.com/a/b/@v/v1.0.0.zip"))
	require.Equal(t, "left-pad", CleanName("left-pad"))
	require.Equal(t, "@scope/pkg", CleanName("@scope/pkg"))
}

func TestDedupeVersionsKeepsLargestAndRenames(t *testing.T) {
	rows := []*Package{
		{Registry: "go", Name: "m/@v/v1.zip", Version: "v1", Size: 5},
		{Registry: "go", Name: "m/@v/v1.mod", Version: "v1", Size: 50},
		{Registry: "go", Name: "m/@v/v1.info", Version: "v1", Size: 1},
		{Registry: "npm", Name: "m", Version: "v1", Size: 9},
	}
	got := DedupeVersions(rows)
	require.Len(t, got, 2, "the same name in another registry is a different package")
	require.Equal(t, "m", got[0].Name)
	require.EqualValues(t, 50, got[0].Size)
	require.Equal(t, "m/@v/v1.zip", rows[0].Name, "input rows stay untouched")
}

func TestPageGroupsPagesWholeGroups(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rows := []*Package{
		{Registry: "npm", Name: "b", Version: "1", CachedAt: at.Add(1 * time.Hour)},
		{Registry: "npm", Name: "b", Version: "2", CachedAt: at.Add(5 * time.Hour)},
		{Registry: "npm", Name: "a", Version: "1", CachedAt: at.Add(2 * time.Hour)},
		{Registry: "npm", Name: "c", Version: "list", CachedAt: at},
	}
	page := PageGroups(rows, GroupListOptions{Page: 1, PageSize: 1})
	require.EqualValues(t, 2, page.TotalGroups, "the list page forms no group")
	require.Len(t, page.Packages, 1)
	require.Equal(t, "a", page.Packages[0].Name)

	recent := PageGroups(rows, GroupListOptions{SortBy: GroupSortCachedAt, SortDesc: true, Page: 1, PageSize: 1})
	require.Equal(t, []string{"2", "1"}, []string{recent.Packages[0].Version, recent.Packages[1].Version}, "group b, newest version first")

	require.Empty(t, PageGroups(rows, GroupListOptions{Page: 9, PageSize: 1}).Packages)
	require.Len(t, PageGroups(rows, GroupListOptions{Query: "B"}).Packages, 2)
}
