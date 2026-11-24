package analytics

import (
	"testing"
	"time"
	"unsafe"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine(Config{MaxEvents: 100, FlushInterval: time.Hour})
	t.Cleanup(e.Close)
	return e
}

// The proxy passes names sliced from a request buffer the server reuses.
func TestTrackDownloadKeepsItsOwnCopyOfTheNames(t *testing.T) {
	e := newTestEngine(t)
	shared := []byte("lodash")
	aliased := unsafe.String(&shared[0], len(shared)) // #nosec G103 -- reproduces a string backed by a reused buffer
	e.TrackDownload(PackageDownload{Registry: "npm", Name: aliased, Version: "1.0.0", Timestamp: time.Now()})
	copy(shared, "xxxxxx")

	if _, ok := e.GetPackageStats("npm", "lodash"); !ok {
		t.Errorf("stats lost the package name after the caller reused its buffer: %v", e.GetTopPackages(0))
	}
	for _, p := range e.GetTopPackages(0) {
		if p.Name != "lodash" {
			t.Errorf("name = %q, want lodash", p.Name)
		}
	}
}

func TestUniqueVersionsCountsDistinctVersions(t *testing.T) {
	e := newTestEngine(t)
	for _, v := range []string{"1.0.0", "1.0.0", "1.1.0", "1.0.0"} {
		e.TrackDownload(PackageDownload{Registry: "npm", Name: "left-pad", Version: v, Timestamp: time.Now(), BytesSize: 10})
	}
	stats, ok := e.GetPackageStats("npm", "left-pad")
	if !ok {
		t.Fatal("no stats")
	}
	if stats.TotalDownloads != 4 || stats.UniqueVersions != 2 || stats.BytesServed != 40 {
		t.Errorf("stats = %+v, want 4 downloads, 2 versions, 40 bytes", stats)
	}
}

func TestUnknownPackageHasNoStats(t *testing.T) {
	if _, ok := newTestEngine(t).GetPackageStats("npm", "nope"); ok {
		t.Error("unknown package reported stats")
	}
}
