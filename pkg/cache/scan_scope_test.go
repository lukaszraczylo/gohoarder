package cache

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// policyBlocker blocks every package it is asked about.
type policyBlocker struct{ checks atomic.Int32 }

func (s *policyBlocker) ScanPackage(context.Context, string, string, string, string) error {
	return nil
}

func (s *policyBlocker) CheckVulnerabilities(context.Context, string, string, string) (bool, string, error) {
	s.checks.Add(1)
	return true, "blocked by policy", nil
}

// Only Go's .mod and .info files are exempt from scanning; a package of any
// other registry whose name ends in .mod or .info is a real package.
func TestCacheHitScansPackagesNamedLikeGoMetadata(t *testing.T) {
	tests := []struct {
		registry, name, version string
		wantBlocked             bool
	}{
		{"npm", "left.info", "1.0.0", true},
		{"npm", "left.mod", "1.0.0", true},
		{"pypi", "foo.info", "foo.info-1.0.tar.gz", true},
		{"go", "github.com/a/b/@v/v1.0.0.zip", "v1.0.0", true},
		{"go", "github.com/a/b/@v/v1.0.0.mod", "v1.0.0", false},
		{"go", "github.com/a/b/@v/v1.0.0.info", "v1.0.0", false},
		{"npm", "left-pad", "metadata", false},
	}

	for _, tt := range tests {
		t.Run(tt.registry+"/"+tt.name, func(t *testing.T) {
			clock := newFakeClock()
			store := newMemStorage()
			meta := newMemMetadata(clock)
			key := tt.registry + "/" + tt.name + "/" + tt.version
			require.NoError(t, store.Put(context.Background(), key, strings.NewReader("data"), nil))
			require.NoError(t, meta.SavePackage(context.Background(), &metadata.Package{
				Registry: tt.registry, Name: tt.name, Version: tt.version, StorageKey: key, Size: 4, LastAccessed: clock.Now(),
			}))

			scanner := &policyBlocker{}
			mgr, err := New(store, meta, scanner, nil, Config{Now: clock.Now, CleanupInterval: 24 * time.Hour})
			require.NoError(t, err)
			t.Cleanup(func() { _ = mgr.Close() })

			entry, err := mgr.Get(context.Background(), tt.registry, tt.name, tt.version, nil)
			if tt.wantBlocked {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, entry.Data)
			_ = entry.Data.Close()
			require.Zero(t, scanner.checks.Load(), "metadata entries must not be scanned")
		})
	}
}
