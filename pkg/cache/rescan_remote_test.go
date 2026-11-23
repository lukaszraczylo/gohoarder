package cache

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/stretchr/testify/require"
)

// listingMetadata adds the full listing the rescan worker walks.
type listingMetadata struct{ scanMetadata }

func (m listingMetadata) ListPackages(context.Context, *metadata.ListOptions) ([]*metadata.Package, error) {
	return m.list(0, func(*metadata.Package) bool { return true }, func(a, b *metadata.Package) bool { return a.Name < b.Name }), nil
}

// bodyScanner reports the bytes it can read at the path it is given.
type bodyScanner struct{ seen chan string }

func (*bodyScanner) Name() string                 { return "body-scanner" }
func (*bodyScanner) Health(context.Context) error { return nil }
func (s *bodyScanner) Scan(_ context.Context, registry, name, version, path string) (*metadata.ScanResult, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		s.seen <- "unreadable"
		return nil, err
	}
	s.seen <- string(body)
	return &metadata.ScanResult{Registry: registry, PackageName: name, PackageVersion: version, Scanner: s.Name(), Status: metadata.ScanStatusClean}, nil
}

// A backend with no local path (S3, SMB) must still be rescanned: the worker reads the blob
// through the cache's file source instead of skipping the package.
func TestRescanWorkerScansRemoteStorage(t *testing.T) {
	clock := newFakeClock()
	store := newMemStorage() // no GetLocalPath, like S3 and SMB
	meta := listingMetadata{scanMetadata{newMemMetadata(clock)}}

	scanMgr, err := scanner.New(config.SecurityConfig{Enabled: true}, meta)
	require.NoError(t, err)
	t.Cleanup(scanMgr.Stop)
	bs := &bodyScanner{seen: make(chan string, 8)}
	scanMgr.RegisterScanner(bs)

	mgr, err := New(store, meta, scanMgr, nil, Config{Now: clock.Now, CleanupInterval: 24 * time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	scanMgr.SetFileSource(mgr.ScanFile)

	ctx := context.Background()
	require.NoError(t, store.Put(ctx, "npm/left-pad/1.3.0", strings.NewReader("tarball-bytes"), nil))
	require.NoError(t, meta.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.3.0", StorageKey: "npm/left-pad/1.3.0",
		CachedAt: clock.Now(), LastAccessed: clock.Now(),
	}))

	worker := scanner.NewRescanWorker(scanMgr, meta, time.Hour)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { worker.Start(runCtx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case got := <-bs.seen:
		require.Equal(t, "tarball-bytes", got)
	case <-time.After(5 * time.Second):
		t.Fatal("rescan never scanned the remote-storage package")
	}
}
