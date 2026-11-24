package gormstore

import (
	"context"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func TestGroupListSkipsGoMetadataFiles(t *testing.T) {
	store := trendingStore(t)
	for _, name := range []string{"example.com/m/@v/v1.0.0.mod", "example.com/m/@v/v1.0.0.info", "example.com/m/@v/v1.0.0.zip"} {
		trendingPackage(t, store, "go", name, "v1.0.0")
	}
	for _, size := range []int{0, 10} {
		page, err := store.ListPackageGroups(context.Background(), metadata.GroupListOptions{PageSize: size, Page: 1})
		require.NoError(t, err)
		require.Len(t, page.Packages, 1, "page size %d", size)
		require.Equal(t, "example.com/m", page.Packages[0].Name)
	}
}

func TestMetadataSuffixesAreGoOnly(t *testing.T) {
	store := trendingStore(t)
	ctx := context.Background()
	trendingPackage(t, store, "npm", "left.mod", "1.0.0")
	trendingPackage(t, store, "npm", "right.info", "1.0.0")
	trendingPackage(t, store, "pypi", "foo.mod", "foo.mod-1.0.tar.gz")
	trendingPackage(t, store, "go", "example.com/m/@v/v1.0.0.zip", "v1.0.0")
	trendingPackage(t, store, "go", "example.com/m/@v/v1.0.0.mod", "v1.0.0")
	trendingPackage(t, store, "go", "example.com/m/@v/v1.0.0.info", "v1.0.0")

	stats, err := store.GetStats(ctx, "")
	require.NoError(t, err)
	require.EqualValues(t, 4, stats.TotalPackages)

	page, err := store.ListPackageGroups(ctx, metadata.GroupListOptions{})
	require.NoError(t, err)
	require.Len(t, page.Packages, 4)
}
