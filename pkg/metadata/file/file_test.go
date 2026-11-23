package file

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// outsideJSON writes a JSON file outside the store and links it inside dir.
func outsideJSON(t *testing.T, dir, link string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	target := filepath.Join(t.TempDir(), "outside.json")
	require.NoError(t, os.WriteFile(target, data, 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, link)), 0750))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, link)))
	return target
}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Config{Path: dir})
	require.NoError(t, err)
	return s, dir
}

func TestListPackages_IgnoresSymlinkOutsideStore(t *testing.T) {
	s, dir := newStore(t)
	require.NoError(t, s.SavePackage(context.Background(), &metadata.Package{Registry: "npm", Name: "a", Version: "1"}))
	outsideJSON(t, dir, "npm/evil-1.json", &metadata.Package{Registry: "npm", Name: "evil", Version: "1"})

	pkgs, err := s.ListPackages(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	require.Equal(t, "a", pkgs[0].Name)
}

func TestGetStats_IgnoresSymlinkOutsideStore(t *testing.T) {
	s, dir := newStore(t)
	require.NoError(t, s.SavePackage(context.Background(), &metadata.Package{Registry: "npm", Name: "a", Version: "1", Size: 5}))
	outsideJSON(t, dir, "npm/evil-1.json", &metadata.Package{Registry: "npm", Name: "evil", Version: "1", Size: 100})

	stats, err := s.GetStats(context.Background(), "npm")
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.TotalPackages)
	require.EqualValues(t, 5, stats.TotalSize)
}

func TestCleanupExpiredBypasses_RemovesExpiredOnly(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()
	require.NoError(t, s.SaveCVEBypass(ctx, &metadata.CVEBypass{ID: "old", ExpiresAt: time.Now().Add(-time.Hour)}))
	require.NoError(t, s.SaveCVEBypass(ctx, &metadata.CVEBypass{ID: "fresh", ExpiresAt: time.Now().Add(time.Hour)}))

	n, err := s.CleanupExpiredBypasses(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.NoFileExists(t, filepath.Join(dir, "bypasses", "old.json"))
	require.FileExists(t, filepath.Join(dir, "bypasses", "fresh.json"))
}

func TestCleanupExpiredBypasses_MissingDirIsNotAnError(t *testing.T) {
	s, _ := newStore(t)
	n, err := s.CleanupExpiredBypasses(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestCleanupExpiredBypasses_DoesNotFollowSymlinkOutsideStore(t *testing.T) {
	s, dir := newStore(t)
	target := outsideJSON(t, dir, "bypasses/x.json", &metadata.CVEBypass{ID: "x", ExpiresAt: time.Now().Add(-time.Hour)})

	_, err := s.CleanupExpiredBypasses(context.Background())
	require.Error(t, err, "escaping symlink must be refused, not read")
	require.FileExists(t, target)
}
