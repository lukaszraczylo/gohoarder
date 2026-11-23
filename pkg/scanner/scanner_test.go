package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	hoardererrors "github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBroadcaster records BroadcastEvent calls for assertions.
type fakeBroadcaster struct {
	events []fakeBroadcastEvent
	mu     sync.Mutex
}

type fakeBroadcastEvent struct {
	Payload any
	Type    string
}

func (f *fakeBroadcaster) BroadcastEvent(eventType string, payload any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, fakeBroadcastEvent{Type: eventType, Payload: payload})
}

func (f *fakeBroadcaster) snapshot() []fakeBroadcastEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeBroadcastEvent, len(f.events))
	copy(out, f.events)
	return out
}

// stubScanner is a minimal Scanner implementation for tests.
type stubScanner struct {
	result *metadata.ScanResult
	err    error
	name   string
}

func (s *stubScanner) Name() string { return s.name }

func (s *stubScanner) Scan(_ context.Context, registry, packageName, version, _ string) (*metadata.ScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	r := *s.result
	r.Registry = registry
	r.PackageName = packageName
	r.PackageVersion = version
	return &r, nil
}

func (s *stubScanner) Health(context.Context) error { return nil }

// stubMetadataStore is a minimal MetadataStore — only SaveScanResult is exercised.
type stubMetadataStore struct {
	saveErr      error
	savedResults []*metadata.ScanResult
	mu           sync.Mutex
}

func (m *stubMetadataStore) SaveScanResult(_ context.Context, r *metadata.ScanResult) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.mu.Lock()
	m.savedResults = append(m.savedResults, r)
	m.mu.Unlock()
	return nil
}

// All other MetadataStore methods are unused by ScanPackage — stub to satisfy interface.
func (m *stubMetadataStore) SavePackage(context.Context, *metadata.Package) error { return nil }
func (m *stubMetadataStore) GetPackage(context.Context, string, string, string) (*metadata.Package, error) {
	return nil, hoardererrors.NotFound("not implemented")
}
func (m *stubMetadataStore) DeletePackage(context.Context, string, string, string) error { return nil }
func (m *stubMetadataStore) ListPackages(context.Context, *metadata.ListOptions) ([]*metadata.Package, error) {
	return nil, nil
}
func (m *stubMetadataStore) UpdateDownloadCount(context.Context, string, string, string) error {
	return nil
}
func (m *stubMetadataStore) GetStats(context.Context, string) (*metadata.Stats, error) {
	return nil, nil
}
func (m *stubMetadataStore) GetScanResult(context.Context, string, string, string) (*metadata.ScanResult, error) {
	return nil, nil
}
func (m *stubMetadataStore) Count(context.Context) (int, error) { return 0, nil }
func (m *stubMetadataStore) Health(context.Context) error       { return nil }
func (m *stubMetadataStore) Close() error                       { return nil }
func (m *stubMetadataStore) SaveCVEBypass(context.Context, *metadata.CVEBypass) error {
	return nil
}
func (m *stubMetadataStore) GetActiveCVEBypasses(context.Context) ([]*metadata.CVEBypass, error) {
	return nil, nil
}
func (m *stubMetadataStore) ListCVEBypasses(context.Context, *metadata.BypassListOptions) ([]*metadata.CVEBypass, error) {
	return nil, nil
}
func (m *stubMetadataStore) DeleteCVEBypass(context.Context, string) error { return nil }
func (m *stubMetadataStore) CleanupExpiredBypasses(context.Context) (int, error) {
	return 0, nil
}
func (m *stubMetadataStore) GetTimeSeriesStats(context.Context, string, string) (*metadata.TimeSeriesStats, error) {
	return nil, nil
}
func (m *stubMetadataStore) AggregateDownloadData(context.Context) error { return nil }
func (m *stubMetadataStore) ListIdlePackages(context.Context, time.Time, int) ([]*metadata.Package, error) {
	return nil, nil
}
func (m *stubMetadataStore) ListExpiredPackages(context.Context, time.Time, int) ([]*metadata.Package, error) {
	return nil, nil
}
func (m *stubMetadataStore) ClearArtifactExpiry(context.Context) (int64, error) { return 0, nil }
func (m *stubMetadataStore) SaveAPIKey(context.Context, *metadata.APIKey) error {
	return metadata.ErrNotImplemented
}
func (m *stubMetadataStore) GetAPIKey(context.Context, string) (*metadata.APIKey, error) {
	return nil, metadata.ErrNotImplemented
}
func (m *stubMetadataStore) ListAPIKeys(context.Context) ([]*metadata.APIKey, error) {
	return nil, metadata.ErrNotImplemented
}
func (m *stubMetadataStore) DeleteAPIKey(context.Context, string) error {
	return metadata.ErrNotImplemented
}
func (m *stubMetadataStore) UpdateAPIKeyLastUsed(context.Context, string, time.Time) error {
	return nil
}

func newTestManager(t *testing.T, store metadata.MetadataStore) *Manager {
	t.Helper()
	// Enabled=true but all built-in scanners disabled — we'll register
	// our own stub via RegisterScanner.
	cfg := config.SecurityConfig{Enabled: true}
	mgr, err := New(cfg, store)
	require.NoError(t, err)
	return mgr
}

// TestBroadcaster_ScanCompleteSuccess verifies EventScanComplete fires
// after a successful scan with the expected payload shape.
func TestBroadcaster_ScanCompleteSuccess(t *testing.T) {
	store := &stubMetadataStore{}
	mgr := newTestManager(t, store)

	result := &metadata.ScanResult{
		ID:                 "r1",
		Scanner:            "stub",
		ScannedAt:          time.Now(),
		Status:             metadata.ScanStatusClean,
		VulnerabilityCount: 0,
		Vulnerabilities:    []metadata.Vulnerability{},
	}
	mgr.RegisterScanner(&stubScanner{name: "stub", result: result})

	bc := &fakeBroadcaster{}
	mgr.SetBroadcaster(bc)

	err := mgr.ScanPackage(context.Background(), "npm", "react", "18.2.0", "/tmp/dummy")
	require.NoError(t, err)

	events := bc.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(websocket.EventScanComplete), events[0].Type)

	payload, ok := events[0].Payload.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "npm", payload["registry"])
	assert.Equal(t, "react", payload["name"])
	assert.Equal(t, "18.2.0", payload["version"])
	assert.Equal(t, string(metadata.ScanStatusClean), payload["status"])
	assert.Equal(t, 0, payload["vulnerability_count"])
}

// TestBroadcaster_ScanCompleteAllScannersFailed verifies that the
// synthetic-error path still fires EventScanComplete with status=error.
func TestBroadcaster_ScanCompleteAllScannersFailed(t *testing.T) {
	store := &stubMetadataStore{}
	mgr := newTestManager(t, store)

	mgr.RegisterScanner(&stubScanner{name: "broken", err: errors.New("scanner exploded")})

	bc := &fakeBroadcaster{}
	mgr.SetBroadcaster(bc)

	err := mgr.ScanPackage(context.Background(), "pypi", "requests", "2.31.0", "/tmp/dummy")
	require.NoError(t, err)

	events := bc.snapshot()
	require.Len(t, events, 1)
	assert.Equal(t, string(websocket.EventScanComplete), events[0].Type)

	payload := events[0].Payload.(map[string]interface{})
	assert.Equal(t, "pypi", payload["registry"])
	assert.Equal(t, "requests", payload["name"])
	assert.Equal(t, "2.31.0", payload["version"])
	assert.Equal(t, string(metadata.ScanStatusError), payload["status"])
}

// TestBroadcaster_NoEmitOnSaveError verifies no event is emitted when
// the metadata store fails to persist the scan result.
func TestBroadcaster_NoEmitOnSaveError(t *testing.T) {
	store := &stubMetadataStore{saveErr: errors.New("db down")}
	mgr := newTestManager(t, store)

	result := &metadata.ScanResult{
		ID:              "r2",
		Scanner:         "stub",
		ScannedAt:       time.Now(),
		Status:          metadata.ScanStatusClean,
		Vulnerabilities: []metadata.Vulnerability{},
	}
	mgr.RegisterScanner(&stubScanner{name: "stub", result: result})

	bc := &fakeBroadcaster{}
	mgr.SetBroadcaster(bc)

	err := mgr.ScanPackage(context.Background(), "npm", "x", "1", "/tmp/dummy")
	require.Error(t, err)
	assert.Empty(t, bc.snapshot(), "no event should fire when SaveScanResult fails")
}

// TestBroadcaster_DisabledNoEmit verifies disabled scanner manager
// silently no-ops and emits nothing.
func TestBroadcaster_DisabledNoEmit(t *testing.T) {
	store := &stubMetadataStore{}
	cfg := config.SecurityConfig{Enabled: false}
	mgr, err := New(cfg, store)
	require.NoError(t, err)

	bc := &fakeBroadcaster{}
	mgr.SetBroadcaster(bc)

	err = mgr.ScanPackage(context.Background(), "npm", "x", "1", "/tmp/dummy")
	require.NoError(t, err)
	assert.Empty(t, bc.snapshot())
}

// TestBroadcaster_NilBroadcasterSafe ensures nil broadcaster is safe.
func TestBroadcaster_NilBroadcasterSafe(t *testing.T) {
	store := &stubMetadataStore{}
	mgr := newTestManager(t, store)
	mgr.RegisterScanner(&stubScanner{name: "stub", result: &metadata.ScanResult{
		ID: "r", Scanner: "stub", ScannedAt: time.Now(), Status: metadata.ScanStatusClean,
	}})

	// No SetBroadcaster.
	err := mgr.ScanPackage(context.Background(), "npm", "x", "1", "/tmp/dummy")
	require.NoError(t, err)
}

// stubBypassStore returns a package bypass and a clean scan result for a
// Go cache-key package, to exercise FIX-H4 bypass-name normalization.
type stubBypassStore struct {
	*stubMetadataStore
	scan     *metadata.ScanResult
	bypasses []*metadata.CVEBypass
}

func (m *stubBypassStore) GetActiveCVEBypasses(context.Context) ([]*metadata.CVEBypass, error) {
	return m.bypasses, nil
}

func (m *stubBypassStore) GetScanResult(context.Context, string, string, string) (*metadata.ScanResult, error) {
	return m.scan, nil
}

// TestCheckVulnerabilities_GoPackageBypassNaturalTarget verifies a package
// bypass targeting the natural Go module path matches a package stored under
// its cache-key name (modulePath/@v/version.zip).
func TestCheckVulnerabilities_GoPackageBypassNaturalTarget(t *testing.T) {
	store := &stubBypassStore{
		stubMetadataStore: &stubMetadataStore{},
		bypasses: []*metadata.CVEBypass{
			{
				ID:     "b1",
				Type:   metadata.BypassTypePackage,
				Target: "go/github.com/foo/bar@v1.2.3",
				Active: true,
			},
		},
		scan: &metadata.ScanResult{
			ID: "r", Scanner: "stub", ScannedAt: time.Now(), Status: metadata.ScanStatusClean,
		},
	}
	mgr := newTestManager(t, store)

	// The package is stored under the cache-key name; the version is passed
	// separately. The bypass target uses the natural module path.
	blocked, reason, err := mgr.CheckVulnerabilities(
		context.Background(), "go", "github.com/foo/bar/@v/v1.2.3.zip", "v1.2.3")
	require.NoError(t, err)
	assert.False(t, blocked, "package bypass should unblock the Go package")
	assert.Equal(t, "", reason)
}

// TestCheckVulnerabilities_GoPackageBypassNotFound verifies a package bypass
// targeting a different module does NOT unblock the Go package. Its stored
// scan result is clean, so CheckVulnerabilities returns not-blocked anyway;
// to make the package-block path observable we use a scan result with a
// high-severity vulnerability and zero thresholds (block any non-zero).
func TestCheckVulnerabilities_GoPackageBypassNotFound(t *testing.T) {
	store := &stubBypassStore{
		stubMetadataStore: &stubMetadataStore{},
		bypasses: []*metadata.CVEBypass{
			{
				ID:     "b1",
				Type:   metadata.BypassTypePackage,
				Target: "go/github.com/other/mod@v1.0.0",
				Active: true,
			},
		},
		scan: &metadata.ScanResult{
			ID: "r", Scanner: "stub", ScannedAt: time.Now(), Status: metadata.ScanStatusVulnerable,
			Vulnerabilities: []metadata.Vulnerability{
				{ID: "CVE-1", Severity: "HIGH"},
			},
		},
	}
	mgr := newTestManager(t, store)

	blocked, _, err := mgr.CheckVulnerabilities(
		context.Background(), "go", "github.com/foo/bar/@v/v1.2.3.zip", "v1.2.3")
	require.NoError(t, err)
	assert.True(t, blocked, "a non-matching bypass should not unblock the package")
}

// resultStore returns a fixed scan result from GetScanResult and records saves.
type resultStore struct {
	*stubMetadataStore
	scan *metadata.ScanResult
}

func (m *resultStore) GetScanResult(context.Context, string, string, string) (*metadata.ScanResult, error) {
	return m.scan, nil
}

func (m *resultStore) saved() []*metadata.ScanResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*metadata.ScanResult(nil), m.savedResults...)
}

func TestScanPackage_InfrastructureErrorIsMarked(t *testing.T) {
	store := &stubMetadataStore{}
	mgr := newTestManager(t, store)
	mgr.RegisterScanner(&stubScanner{name: "osv", err: fmt.Errorf("OSV API request failed: %w", context.DeadlineExceeded)})

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	require.Len(t, store.savedResults, 1)
	assert.Equal(t, metadata.ScanStatusError, store.savedResults[0].Status)
	assert.Equal(t, true, store.savedResults[0].Details[DetailInfrastructureError])
}

func TestScanPackage_NonInfrastructureErrorIsNotMarked(t *testing.T) {
	store := &stubMetadataStore{}
	mgr := newTestManager(t, store)
	mgr.RegisterScanner(&stubScanner{name: "broken", err: errors.New("scanner exploded")})

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	require.Len(t, store.savedResults, 1)
	assert.NotEqual(t, true, store.savedResults[0].Details[DetailInfrastructureError])
}

func infraErrorScan() *metadata.ScanResult {
	return &metadata.ScanResult{
		ID: "r", Scanner: "all", ScannedAt: time.Now(), Status: metadata.ScanStatusError,
		Details: map[string]interface{}{DetailInfrastructureError: true},
	}
}

func TestCheckVulnerabilities_InfrastructureErrorServesByDefault(t *testing.T) {
	store := &resultStore{stubMetadataStore: &stubMetadataStore{}, scan: infraErrorScan()}
	mgr := newTestManager(t, store)

	blocked, reason, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	require.NoError(t, err)
	assert.False(t, blocked, "infrastructure scan error must not block, got reason %q", reason)
}

func TestCheckVulnerabilities_InfrastructureErrorBlocksWhenFailClosed(t *testing.T) {
	store := &resultStore{stubMetadataStore: &stubMetadataStore{}, scan: infraErrorScan()}
	mgr, err := New(config.SecurityConfig{Enabled: true, FailClosed: true}, store)
	require.NoError(t, err)

	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	require.NoError(t, err)
	assert.True(t, blocked)
}

func TestCheckVulnerabilities_PlainScanErrorStillBlocks(t *testing.T) {
	scan := infraErrorScan()
	scan.Details = map[string]interface{}{}
	store := &resultStore{stubMetadataStore: &stubMetadataStore{}, scan: scan}
	mgr := newTestManager(t, store)

	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	require.NoError(t, err)
	assert.True(t, blocked)
}

// flakyScanner fails with an infrastructure error until failures is exhausted.
type flakyScanner struct {
	failures int
	calls    int
	mu       sync.Mutex
}

func (f *flakyScanner) Name() string { return "osv" }
func (f *flakyScanner) Scan(_ context.Context, registry, name, version, _ string) (*metadata.ScanResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failures {
		return nil, fmt.Errorf("OSV API request failed: %w", context.DeadlineExceeded)
	}
	return &metadata.ScanResult{
		ID: "ok", Registry: registry, PackageName: name, PackageVersion: version,
		Scanner: "osv", ScannedAt: time.Now(), Status: metadata.ScanStatusClean,
	}, nil
}
func (f *flakyScanner) Health(context.Context) error { return nil }

func TestScanPackage_InfrastructureErrorIsRetried(t *testing.T) {
	store := &stubMetadataStore{}
	mgr, err := New(config.SecurityConfig{Enabled: true, ScanRetryInterval: 10 * time.Millisecond}, store)
	require.NoError(t, err)
	t.Cleanup(mgr.Stop)
	mgr.RegisterScanner(&flakyScanner{failures: 1})

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	require.Eventually(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		n := len(store.savedResults)
		return n == 2 && store.savedResults[1].Status == metadata.ScanStatusClean
	}, 2*time.Second, 10*time.Millisecond, "retry must save a clean result after the infrastructure error")
}

func TestScanner_DisabledReportsNotEnabled(t *testing.T) {
	mgr, err := New(config.SecurityConfig{Enabled: false}, &stubMetadataStore{})
	require.NoError(t, err)
	assert.False(t, mgr.Enabled())
	assert.True(t, newTestManager(t, &stubMetadataStore{}).Enabled())
}

// releasePackageStore returns a PyPI-style package whose cache key is a file name.
type releasePackageStore struct {
	*stubBypassStore
}

func (m *releasePackageStore) GetPackage(_ context.Context, _, _, version string) (*metadata.Package, error) {
	return &metadata.Package{Name: "six", Version: version, ReleaseVersion: "1.17.0"}, nil
}

func TestCheckVulnerabilities_PackageBypassMatchesReleaseVersion(t *testing.T) {
	const file = "six-1.17.0-py2.py3-none-any.whl"
	cases := []struct {
		name    string
		target  string
		blocked bool
	}{
		{"release version target", "pypi/six@1.17.0", false},
		{"file name target", "pypi/six@" + file, false},
		{"other release", "pypi/six@1.16.0", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &releasePackageStore{&stubBypassStore{
				stubMetadataStore: &stubMetadataStore{},
				bypasses:          []*metadata.CVEBypass{{ID: "b1", Type: metadata.BypassTypePackage, Target: tc.target, Active: true}},
				scan: &metadata.ScanResult{
					ID: "r", Scanner: "stub", ScannedAt: time.Now(), Status: metadata.ScanStatusVulnerable,
					Vulnerabilities: []metadata.Vulnerability{{ID: "CVE-1", Severity: "HIGH"}},
				},
			}}
			mgr := newTestManager(t, store)
			blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "pypi", "six", file)
			require.NoError(t, err)
			assert.Equal(t, tc.blocked, blocked)
		})
	}
}
