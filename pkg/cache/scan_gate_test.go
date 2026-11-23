package cache

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// stubScanner never records a scan result, like a scanner that is off or hung.
type stubScanner struct {
	enabled bool
}

func (s *stubScanner) Enabled() bool { return s.enabled }
func (s *stubScanner) ScanPackage(context.Context, string, string, string, string) error {
	return nil
}
func (s *stubScanner) CheckVulnerabilities(context.Context, string, string, string) (bool, string, error) {
	return false, "", nil
}

func newMissManager(t *testing.T, sc ScannerInterface, cfg Config) *Manager {
	t.Helper()
	mockStorage := &MockStorageBackend{}
	mockMetadata := &MockMetadataStore{}

	mockMetadata.On("GetPackage", mock.Anything, "npm", "lodash", "4.17.21").Return(nil, errors.New("not found")).Once()
	mockMetadata.On("GetPackage", mock.Anything, "npm", "lodash", "4.17.21").
		Return(&metadata.Package{Registry: "npm", Name: "lodash", Version: "4.17.21", StorageKey: "npm/lodash/4.17.21"}, nil)
	mockStorage.On("GetQuota", mock.Anything).Return(&storage.QuotaInfo{Used: 100, Available: 900, Limit: 1000}, nil)
	mockStorage.On("Put", mock.Anything, "npm/lodash/4.17.21", mock.Anything, mock.Anything).Return(nil)
	mockMetadata.On("SavePackage", mock.Anything, mock.Anything).Return(nil)
	mockStorage.On("Get", mock.Anything, "npm/lodash/4.17.21").Return(io.NopCloser(strings.NewReader("data")), nil)
	mockMetadata.On("UpdateDownloadCount", mock.Anything, "npm", "lodash", "4.17.21").Return(nil)

	mockStorage.On("Close").Return(nil)
	mockMetadata.On("Close").Return(nil)

	manager, err := New(mockStorage, mockMetadata, sc, nil, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func fetchLodash(context.Context) (*FetchResult, error) {
	return &FetchResult{Data: io.NopCloser(strings.NewReader("data")), UpstreamURL: "https://registry.npmjs.org/lodash"}, nil
}

// With scanning disabled the first download must not wait for a scan result.
func TestGet_DisabledScannerServesWithoutWaiting(t *testing.T) {
	manager := newMissManager(t, &stubScanner{enabled: false}, Config{ScanWaitTimeout: 5 * time.Second})

	start := time.Now()
	entry, err := manager.Get(context.Background(), "npm", "lodash", "4.17.21", fetchLodash)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Less(t, time.Since(start), 2*time.Second, "disabled scanner must not delay the first download")
}

// A scan that does not finish in time is an infrastructure problem: serve it
// unless the operator chose fail-closed.
func TestGet_ScanWaitTimeoutServesByDefault(t *testing.T) {
	manager := newMissManager(t, &stubScanner{enabled: true}, Config{ScanWaitTimeout: 200 * time.Millisecond})

	entry, err := manager.Get(context.Background(), "npm", "lodash", "4.17.21", fetchLodash)
	require.NoError(t, err)
	require.NotNil(t, entry)
}

func TestGet_ScanWaitTimeoutRefusesWhenFailClosed(t *testing.T) {
	manager := newMissManager(t, &stubScanner{enabled: true}, Config{ScanWaitTimeout: 200 * time.Millisecond, FailClosed: true})

	_, err := manager.Get(context.Background(), "npm", "lodash", "4.17.21", fetchLodash)
	require.Error(t, err)
}
