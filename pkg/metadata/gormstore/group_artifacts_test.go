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
