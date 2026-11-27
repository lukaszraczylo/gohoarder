package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type diskProbeScanner struct {
	stubScanner
	calls int
}

func (c *diskProbeScanner) Scan(ctx context.Context, registry, packageName, version, path string) (*metadata.ScanResult, error) {
	c.calls++
	return c.stubScanner.Scan(ctx, registry, packageName, version, path)
}

func diskGuardManager(t *testing.T, minFree int64, free uint64, freeErr error) (*Manager, *stubMetadataStore, *diskProbeScanner) {
	t.Helper()
	store := &stubMetadataStore{}
	mgr, err := New(config.SecurityConfig{Enabled: true, MinFreeBytes: minFree, ScanRetryInterval: time.Hour}, store)
	require.NoError(t, err)
	t.Cleanup(mgr.Stop)
	mgr.freeBytes = func(string) (uint64, error) { return free, freeErr }
	s := &diskProbeScanner{stubScanner: *stubResult("trivy", metadata.ScanStatusClean, nil)}
	mgr.RegisterScanner(s)
	return mgr, store, s
}

func TestScanIsDeferredWhenDiskIsLow(t *testing.T) {
	mgr, store, s := diskGuardManager(t, 1<<30, 1<<20, nil)

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	assert.Zero(t, s.calls, "no scanner may run on a full disk")
	require.Len(t, store.savedResults, 1)
	assert.Equal(t, metadata.ScanStatusError, store.savedResults[0].Status)
	assert.Equal(t, true, store.savedResults[0].Details[DetailInfrastructureError], "low disk is retried, not blamed on the package")
}

func TestScanRunsWhenDiskHasRoom(t *testing.T) {
	mgr, store, s := diskGuardManager(t, 1<<30, 2<<30, nil)

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	assert.Equal(t, 1, s.calls)
	require.Len(t, store.savedResults, 1)
	assert.Equal(t, metadata.ScanStatusClean, store.savedResults[0].Status)
}

func TestDiskGuardOffByDefault(t *testing.T) {
	mgr, _, s := diskGuardManager(t, 0, 0, nil)

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	assert.Equal(t, 1, s.calls)
}

func TestDiskGuardMeasurementFailureDoesNotBlockScans(t *testing.T) {
	mgr, _, s := diskGuardManager(t, 1<<30, 0, errors.New("statfs failed"))

	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))

	assert.Equal(t, 1, s.calls)
}
