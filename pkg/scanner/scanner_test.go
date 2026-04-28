package scanner

import (
	"context"
	"errors"
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
