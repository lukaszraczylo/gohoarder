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
	results   map[string]*metadata.ScanResult
	packages  []*metadata.Package
	summaries []*metadata.ScanSummary
	stubMetadataStore
	rmu sync.Mutex
}

func (s *rescanStore) ListPackages(context.Context, *metadata.ListOptions) ([]*metadata.Package, error) {
	return s.packages, nil
}

func (s *rescanStore) GetScanSummaries(context.Context, []string, bool) ([]*metadata.ScanSummary, error) {
	return s.summaries, nil
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

// forcedFixture builds a worker over pkgs whose file source calls gate before each scan.
func forcedFixture(t *testing.T, pkgs []*metadata.Package, summaries []*metadata.ScanSummary, gate func(), opts ...RescanOption) (*RescanWorker, *countingScanner) {
	t.Helper()
	store := &rescanStore{results: map[string]*metadata.ScanResult{}, packages: pkgs, summaries: summaries}
	mgr := newTestManager(t, store)
	cs := &countingScanner{calls: map[string]int{}}
	mgr.RegisterScanner(cs)
	mgr.SetFileSource(func(context.Context, string, string, string) (string, func(), error) {
		if gate != nil {
			gate()
		}
		return "/tmp/dummy", func() {}, nil
	})
	return NewRescanWorker(mgr, store, time.Hour, opts...), cs
}

func waitIdle(t *testing.T, w *RescanWorker) RescanStatus {
	t.Helper()
	require.Eventually(t, func() bool { return !w.Status().Running }, 5*time.Second, 5*time.Millisecond)
	return w.Status()
}

func TestRescanNowIgnoresActiveWindowAndFreshness(t *testing.T) {
	now := time.Now()
	pkgs := []*metadata.Package{
		pkgRow("npm", "cold", "1.0.0", now.Add(-90*24*time.Hour)),
		pkgRow("go", "example.com/m/@v/v1.0.0.zip", "v1.0.0", now),
		pkgRow("go", "example.com/m/@v/v1.0.0.mod", "v1.0.0", now),
	}
	w, cs := forcedFixture(t, pkgs, nil, nil, WithActiveWindow(time.Hour), WithConcurrency(2))
	// A fresh result would make the periodic cycle skip this package.
	w.metadataStore.(*rescanStore).results[scanKey("npm", "cold", "1.0.0")] = &metadata.ScanResult{ScannedAt: now}
	pkgs[0].SecurityScanned = true

	queued, err := w.RescanNow(context.Background(), RescanAll)
	require.NoError(t, err)
	assert.Equal(t, 2, queued)
	st := waitIdle(t, w)

	assert.Equal(t, map[string]int{
		scanKey("npm", "cold", "1.0.0"):                        1,
		scanKey("go", "example.com/m/@v/v1.0.0.zip", "v1.0.0"): 1,
	}, cs.snapshot())
	assert.Equal(t, RescanStatus{StartedAt: st.StartedAt, FinishedAt: st.FinishedAt, Scope: RescanAll, Queued: 2, Done: 2}, st)
	assert.False(t, st.FinishedAt.IsZero())
}

func TestRescanNowVulnerableScopeOnlyTakesPackagesWithFindings(t *testing.T) {
	now := time.Now()
	a, b, c := pkgRow("npm", "a", "1.0.0", now), pkgRow("npm", "b", "1.0.0", now), pkgRow("npm", "c", "1.0.0", now)
	a.ID, b.ID, c.ID = "id-a", "id-b", "id-c"
	summaries := []*metadata.ScanSummary{{PackageID: "id-a", Total: 3}, {PackageID: "id-b", Total: 0}}
	w, cs := forcedFixture(t, []*metadata.Package{a, b, c}, summaries, nil)

	queued, err := w.RescanNow(context.Background(), RescanVulnerable)
	require.NoError(t, err)
	assert.Equal(t, 1, queued)
	waitIdle(t, w)
	assert.Equal(t, map[string]int{scanKey("npm", "a", "1.0.0"): 1}, cs.snapshot())
}

func TestRescanNowRefusesASecondRunWhileActive(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	w, _ := forcedFixture(t, []*metadata.Package{pkgRow("npm", "a", "1.0.0", time.Now())}, nil, func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	})

	_, err := w.RescanNow(context.Background(), RescanAll)
	require.NoError(t, err)
	<-entered
	assert.True(t, w.Status().Running)
	_, err = w.RescanNow(context.Background(), RescanAll)
	assert.ErrorIs(t, err, ErrRescanRunning)

	close(release)
	waitIdle(t, w)
	_, err = w.RescanNow(context.Background(), RescanAll)
	assert.NoError(t, err, "a finished run frees the slot")
	waitIdle(t, w)
}

func TestRescanNowCountsFailures(t *testing.T) {
	pkgs := []*metadata.Package{pkgRow("npm", "ok", "1.0.0", time.Now()), pkgRow("npm", "nokey", "1.0.0", time.Now())}
	pkgs[1].StorageKey = ""
	w, _ := forcedFixture(t, pkgs, nil, nil)

	_, err := w.RescanNow(context.Background(), RescanAll)
	require.NoError(t, err)
	st := waitIdle(t, w)
	assert.Equal(t, int64(2), st.Queued)
	assert.Equal(t, int64(1), st.Done)
	assert.Equal(t, int64(1), st.Failed)
}
