package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	hoardererrors "github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rescanStore serves a fixed package list and keeps saved scan results.
type rescanStore struct {
	results  map[string]*metadata.ScanResult
	packages []*metadata.Package
	stubMetadataStore
	rmu sync.Mutex
}

func (s *rescanStore) ListPackages(context.Context, *metadata.ListOptions) ([]*metadata.Package, error) {
	return s.packages, nil
}

func (s *rescanStore) GetScanResult(_ context.Context, registry, name, version string) (*metadata.ScanResult, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if r, ok := s.results[scanKey(registry, name, version)]; ok {
		return r, nil
	}
	return nil, hoardererrors.NotFound("no scan result")
}

func (s *rescanStore) SaveScanResult(ctx context.Context, r *metadata.ScanResult) error {
	s.rmu.Lock()
	s.results[scanKey(r.Registry, r.PackageName, r.PackageVersion)] = r
	s.rmu.Unlock()
	return s.stubMetadataStore.SaveScanResult(ctx, r)
}

// countingScanner records how often each package is scanned.
type countingScanner struct {
	calls map[string]int
	mu    sync.Mutex
}

func (c *countingScanner) Name() string { return "counting" }

func (c *countingScanner) Scan(_ context.Context, registry, name, version, _ string) (*metadata.ScanResult, error) {
	c.mu.Lock()
	c.calls[scanKey(registry, name, version)]++
	c.mu.Unlock()
	return &metadata.ScanResult{
		Registry: registry, PackageName: name, PackageVersion: version,
		Scanner: "counting", ScannedAt: time.Now(), Status: metadata.ScanStatusClean,
	}, nil
}

func (c *countingScanner) Health(context.Context) error { return nil }

func (c *countingScanner) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.calls))
	for k, v := range c.calls {
		out[k] = v
	}
	return out
}

func pkgRow(registry, name, version string, lastAccessed time.Time) *metadata.Package {
	return &metadata.Package{
		Registry: registry, Name: name, Version: version,
		StorageKey: registry + "/" + name + "/" + version, LastAccessed: lastAccessed,
	}
}

func runRescan(t *testing.T, pkgs []*metadata.Package, opts ...RescanOption) map[string]int {
	t.Helper()
	store := &rescanStore{results: map[string]*metadata.ScanResult{}, packages: pkgs}
	mgr := newTestManager(t, store)
	cs := &countingScanner{calls: map[string]int{}}
	mgr.RegisterScanner(cs)
	mgr.SetFileSource(func(context.Context, string, string, string) (string, func(), error) {
		return "/tmp/dummy", func() {}, nil
	})
	NewRescanWorker(mgr, store, time.Hour, opts...).rescanPackages(context.Background())
	return cs.snapshot()
}

func TestRescanSkipsMetadataEntries(t *testing.T) {
	now := time.Now()
	pkgs := []*metadata.Package{
		pkgRow("go", "example.com/m/@v/v1.0.0.mod", "v1.0.0", now),
		pkgRow("go", "example.com/m/@v/v1.0.0.info", "v1.0.0", now),
		pkgRow("go", "example.com/m/@v/v1.0.0.zip", "v1.0.0", now),
		pkgRow("npm", "left-pad", "list", now),
		pkgRow("npm", "left-pad", "1.3.0", now),
		pkgRow("npm", "weird.mod", "1.0.0", now),
	}
	got := runRescan(t, pkgs)
	assert.Equal(t, map[string]int{
		scanKey("go", "example.com/m/@v/v1.0.0.zip", "v1.0.0"): 1,
		scanKey("npm", "left-pad", "1.3.0"):                    1,
		scanKey("npm", "weird.mod", "1.0.0"):                   1,
	}, got)
}

func TestRescanActiveWindow(t *testing.T) {
	now := time.Now()
	pkgs := []*metadata.Package{
		pkgRow("npm", "hot", "1.0.0", now.Add(-time.Hour)),
		pkgRow("npm", "cold", "1.0.0", now.Add(-72*time.Hour)),
		pkgRow("npm", "unknown", "1.0.0", time.Time{}),
	}
	tests := []struct {
		name   string
		want   []string
		window time.Duration
	}{
		{"window off scans everything", []string{"hot", "cold", "unknown"}, 0},
		{"window skips idle only", []string{"hot", "unknown"}, 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRescan(t, pkgs, WithActiveWindow(tt.window))
			want := map[string]int{}
			for _, n := range tt.want {
				want[scanKey("npm", n, "1.0.0")] = 1
			}
			assert.Equal(t, want, got)
		})
	}
}

func TestRescanConcurrencyScansEachOnce(t *testing.T) {
	now := time.Now()
	var pkgs []*metadata.Package
	want := map[string]int{}
	for i := 0; i < 40; i++ {
		name := string(rune('a'+i%26)) + string(rune('a'+i/26))
		pkgs = append(pkgs, pkgRow("npm", name, "1.0.0", now))
		want[scanKey("npm", name, "1.0.0")] = 1
	}
	pkgs = append(pkgs, pkgRow("go", "m/@v/v1.mod", "v1", now))

	for _, n := range []int{-2, 0, 1, 3, 8} {
		got := runRescan(t, pkgs, WithConcurrency(n))
		require.Equal(t, want, got, "concurrency %d", n)
	}
}

func TestRescanConcurrencyFloor(t *testing.T) {
	for _, n := range []int{-1, 0} {
		w := NewRescanWorker(nil, nil, time.Hour, WithConcurrency(n))
		assert.Equal(t, 1, w.concurrency)
	}
	assert.Equal(t, 1, NewRescanWorker(nil, nil, time.Hour).concurrency)
}
