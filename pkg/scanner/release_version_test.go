package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// versionRecorder remembers the version each scan asked about.
type versionRecorder struct {
	versions []string
	mu       sync.Mutex
}

func (s *versionRecorder) Name() string { return "recorder" }

func (s *versionRecorder) Scan(_ context.Context, registry, name, version, _ string) (*metadata.ScanResult, error) {
	s.mu.Lock()
	s.versions = append(s.versions, version)
	s.mu.Unlock()
	return &metadata.ScanResult{
		ID: "r", Registry: registry, PackageName: name, PackageVersion: version,
		Scanner: "recorder", ScannedAt: time.Now(), Status: metadata.ScanStatusClean,
	}, nil
}

func (s *versionRecorder) Health(context.Context) error { return nil }

type packageStore struct {
	*stubMetadataStore
	pkg *metadata.Package
}

func (s *packageStore) GetPackage(context.Context, string, string, string) (*metadata.Package, error) {
	return s.pkg, nil
}

// PyPI artifacts are cached under their file name; scanners must be asked about the release version.
func TestScanAsksScannersForReleaseVersion(t *testing.T) {
	const wheel = "requests-2.19.0-py3-none-any.whl"
	tests := []struct {
		name string
		pkg  *metadata.Package
		want string
	}{
		{"pypi file", &metadata.Package{Version: wheel, ReleaseVersion: "2.19.0"}, "2.19.0"},
		{"npm tarball has no release version", &metadata.Package{Version: wheel}, wheel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &packageStore{stubMetadataStore: &stubMetadataStore{}, pkg: tt.pkg}
			mgr := newTestManager(t, store)
			rec := &versionRecorder{}
			mgr.RegisterScanner(rec)

			require.NoError(t, mgr.ScanPackage(context.Background(), "pypi", "requests", wheel, "/tmp/x"))
			require.Equal(t, []string{tt.want}, rec.versions)
			require.Len(t, store.savedResults, 1)
			require.Equal(t, wheel, store.savedResults[0].PackageVersion, "the result stays keyed by the cache version")
		})
	}
}
