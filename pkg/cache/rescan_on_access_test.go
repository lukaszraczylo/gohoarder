package cache

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hoardererrors "github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const rescanInterval = 24 * time.Hour

// rescanScanner blocks a scan until release closes and blocks the package once scanned.
type rescanScanner struct {
	release     chan struct{}
	scanCtx     atomic.Pointer[context.Context]
	scans       atomic.Int32
	blockOnScan atomic.Bool
}

func (s *rescanScanner) ScanPackage(ctx context.Context, _, _, _, _ string) error {
	s.scans.Add(1)
	s.scanCtx.Store(&ctx)
	if s.release != nil {
		<-s.release
	}
	s.blockOnScan.Store(true)
	return nil
}

func (s *rescanScanner) CheckVulnerabilities(context.Context, string, string, string) (bool, string, error) {
	if s.scans.Load() > 0 && s.release == nil {
		return s.blockOnScan.Load(), "critical vulnerability", nil
	}
	return false, "", nil
}

func newHitManager(t *testing.T, sc ScannerInterface, cfg Config, registry, name, version string, prev *metadata.ScanResult) (*Manager, *MockMetadataStore) {
	t.Helper()
	st := &MockStorageBackend{}
	md := &MockMetadataStore{}
	key := registry + "/" + name + "/" + version

	md.On("GetPackage", mock.Anything, registry, name, version).
		Return(&metadata.Package{Registry: registry, Name: name, Version: version, StorageKey: key}, nil)
	st.On("Get", mock.Anything, key).Return(io.NopCloser(strings.NewReader("data")), nil)
	md.On("UpdateDownloadCount", mock.Anything, registry, name, version).Return(nil)
	if prev == nil {
		md.On("GetScanResult", mock.Anything, registry, name, version).Return(nil, hoardererrors.NotFound("none")).Maybe()
	} else {
		md.On("GetScanResult", mock.Anything, registry, name, version).Return(prev, nil).Maybe()
	}
	st.On("Close").Return(nil)
	md.On("Close").Return(nil)

	m, err := New(st, md, sc, nil, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })
	return m, md
}

func scanAged(age time.Duration) *metadata.ScanResult {
	return &metadata.ScanResult{ScannedAt: time.Now().Add(-age), Status: metadata.ScanStatusClean}
}

func errorCode(err error) string {
	var appErr *hoardererrors.Error
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return ""
}

func TestGetHit_RescanOnAccess(t *testing.T) {
	tests := []struct {
		prev      *metadata.ScanResult
		name      string
		wantCode  string
		rescan    time.Duration
		wantScans int32
		hang      bool
		failClose bool
	}{
		{name: "stale clean result, fresh scan finds critical: blocked before serve", prev: scanAged(48 * time.Hour), rescan: rescanInterval, wantScans: 1, wantCode: hoardererrors.ErrCodeSecurityViolation},
		{name: "missing result is scanned before serving", prev: nil, rescan: rescanInterval, wantScans: 1, wantCode: hoardererrors.ErrCodeSecurityViolation},
		{name: "fresh result is not rescanned", prev: scanAged(time.Hour), rescan: rescanInterval, wantScans: 0},
		{name: "rescan_on_access off keeps the old hit path", prev: scanAged(48 * time.Hour), rescan: 0, wantScans: 0},
		{name: "timeout with previous result serves", prev: scanAged(48 * time.Hour), rescan: rescanInterval, wantScans: 1, hang: true},
		{name: "timeout with previous result serves under fail-closed", prev: scanAged(48 * time.Hour), rescan: rescanInterval, wantScans: 1, hang: true, failClose: true},
		{name: "timeout without result serves when fail-open", prev: nil, rescan: rescanInterval, wantScans: 1, hang: true},
		{name: "timeout without result is 503 when fail-closed", prev: nil, rescan: rescanInterval, wantScans: 1, hang: true, failClose: true, wantCode: hoardererrors.ErrCodeServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &rescanScanner{}
			if tt.hang {
				sc.release = make(chan struct{})
				t.Cleanup(func() { close(sc.release) })
			}
			m, _ := newHitManager(t, sc, Config{RescanAfter: tt.rescan, ScanWaitTimeout: 150 * time.Millisecond, FailClosed: tt.failClose},
				"npm", "lodash", "4.17.21", tt.prev)

			entry, err := m.Get(context.Background(), "npm", "lodash", "4.17.21", nil)

			if tt.wantCode != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, errorCode(err))
			} else {
				require.NoError(t, err)
				require.NotNil(t, entry)
				_ = entry.Data.Close()
			}
			assert.Equal(t, tt.wantScans, sc.scans.Load())
		})
	}
}

func TestGetHit_RescanOffDoesNotReadScanResult(t *testing.T) {
	sc := &rescanScanner{}
	m, md := newHitManager(t, sc, Config{}, "npm", "lodash", "4.17.21", scanAged(48*time.Hour))
	entry, err := m.Get(context.Background(), "npm", "lodash", "4.17.21", nil)
	require.NoError(t, err)
	_ = entry.Data.Close()
	md.AssertNotCalled(t, "GetScanResult", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestGetHit_RescanSkipsGoMetadataRows(t *testing.T) {
	sc := &rescanScanner{}
	m, _ := newHitManager(t, sc, Config{RescanAfter: rescanInterval}, "go", "example.com/m/@v/v1.0.0.mod", "v1.0.0", nil)
	entry, err := m.Get(context.Background(), "go", "example.com/m/@v/v1.0.0.mod", "v1.0.0", nil)
	require.NoError(t, err)
	_ = entry.Data.Close()
	assert.Zero(t, sc.scans.Load())
}

// Concurrent stale hits share one scan, and a client that disconnects does not cancel it.
func TestRefreshStaleScan_SingleflightAndBackgroundContext(t *testing.T) {
	sc := &rescanScanner{release: make(chan struct{})}
	m, _ := newHitManager(t, sc, Config{RescanAfter: rescanInterval, ScanWaitTimeout: 5 * time.Second},
		"npm", "lodash", "4.17.21", scanAged(48*time.Hour))

	const callers = 5
	ctx, cancelClient := context.WithCancel(context.Background())
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.refreshStaleScan(ctx, "npm", "lodash", "4.17.21")
		}()
	}

	require.Eventually(t, func() bool { return sc.scans.Load() >= 1 }, 2*time.Second, 5*time.Millisecond)
	cancelClient()
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.ErrorIs(t, err, context.Canceled)
	}

	scanCtx := sc.scanCtx.Load()
	require.NotNil(t, scanCtx)
	assert.NoError(t, (*scanCtx).Err(), "scan must outlive the client request")
	close(sc.release)
	assert.Equal(t, int32(1), sc.scans.Load(), "concurrent hits must share one scan")
}
