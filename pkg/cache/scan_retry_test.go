package cache

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/stretchr/testify/require"
)

// scanMetadata lets the real scanner.Manager record results against the in-memory store.
type scanMetadata struct {
	*memMetadata
}

func (scanMetadata) SaveScanResult(context.Context, *metadata.ScanResult) error { return nil }
func (scanMetadata) GetScanResult(context.Context, string, string, string) (*metadata.ScanResult, error) {
	return nil, fmt.Errorf("no result")
}

// fileScanner fails on infrastructure once, then succeeds; it records what it could read.
type fileScanner struct {
	seen chan string
	mu   sync.Mutex
	n    int
}

func (*fileScanner) Name() string                 { return "file-scanner" }
func (*fileScanner) Health(context.Context) error { return nil }
func (s *fileScanner) Scan(_ context.Context, registry, name, version, path string) (*metadata.ScanResult, error) {
	s.mu.Lock()
	s.n++
	n := s.n
	s.mu.Unlock()
	body, err := os.ReadFile(path)
	if err != nil {
		s.seen <- "unreadable"
	} else {
		s.seen <- string(body)
	}
	if n == 1 {
		return nil, fmt.Errorf("%w: scanner timed out", scanerr.ErrInfrastructure)
	}
	if err != nil {
		return nil, err
	}
	return &metadata.ScanResult{Registry: registry, PackageName: name, PackageVersion: version, Scanner: "file-scanner", Status: metadata.ScanStatusClean}, nil
}

// On a backend with no local path (S3, SMB) the scan source is a temp file removed after the
// first scan; a retry must read the blob again instead of scanning a path that is gone.
func TestScanRetryOnRemoteStorageReadsBlobAgain(t *testing.T) {
	clock := newFakeClock()
	store := newMemStorage() // no GetLocalPath, like S3 and SMB
	meta := scanMetadata{newMemMetadata(clock)}

	scanMgr, err := scanner.New(config.SecurityConfig{Enabled: true, ScanRetryInterval: 50 * time.Millisecond}, meta)
	require.NoError(t, err)
	t.Cleanup(scanMgr.Stop)
	fs := &fileScanner{seen: make(chan string, 8)}
	scanMgr.RegisterScanner(fs)

	mgr, err := New(store, meta, scanMgr, nil, Config{Now: clock.Now, CleanupInterval: 24 * time.Hour, ScanWaitTimeout: 200 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	scanMgr.SetFileSource(mgr.ScanFile)

	entry, err := mgr.Get(context.Background(), "npm", "left-pad", "1.3.0", func(context.Context) (*FetchResult, error) {
		return &FetchResult{Data: io.NopCloser(strings.NewReader("tarball-bytes"))}, nil
	})
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, entry.Data)
	_ = entry.Data.Close()

	for attempt := 1; attempt <= 2; attempt++ {
		select {
		case got := <-fs.seen:
			require.Equal(t, "tarball-bytes", got, "scan attempt %d must read the blob", attempt)
		case <-time.After(5 * time.Second):
			t.Fatalf("scan attempt %d never ran", attempt)
		}
	}
}
