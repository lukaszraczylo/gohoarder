package file

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func TestListIdlePackages(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t)
	now := time.Now()
	for i, p := range []struct {
		name string
		age  time.Duration
	}{{"old-a", 10 * 24 * time.Hour}, {"old-b", 9 * 24 * time.Hour}, {"fresh", time.Hour}} {
		require.NoError(t, s.SavePackage(ctx, &metadata.Package{
			Registry: "npm", Name: p.name, Version: "1", LastAccessed: now.Add(-p.age), Size: int64(i),
		}))
	}
	require.NoError(t, s.SaveScanResult(ctx, &metadata.ScanResult{Registry: "npm", PackageName: "old-a", PackageVersion: "1"}))

	got, err := s.ListIdlePackages(ctx, now.Add(-7*24*time.Hour), 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "old-a", got[0].Name, "oldest first, scan results are not packages")

	got, err = s.ListIdlePackages(ctx, now.Add(-7*24*time.Hour), 10)
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func TestListExpiredPackagesAndClearArtifactExpiry(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t)
	past := time.Now().Add(-time.Hour)
	for _, v := range []string{"list", "1.0.0"} {
		require.NoError(t, s.SavePackage(ctx, &metadata.Package{Registry: "npm", Name: "x", Version: v, ExpiresAt: &past}))
	}

	cleared, err := s.ClearArtifactExpiry(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), cleared)

	got, err := s.ListExpiredPackages(ctx, time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "list", got[0].Version)
}
