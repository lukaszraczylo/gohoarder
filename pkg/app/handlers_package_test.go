package app

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

func seedOnePackage(t *testing.T, a *App, registry, name, version string, downloads int) {
	t.Helper()
	now := time.Now()
	if err := a.metadata.SavePackage(context.Background(), &metadata.Package{
		Registry: registry, Name: name, Version: version, StorageKey: registry + "/" + name + "/" + version,
		Size: 2048, ChecksumSHA256: "abc123", CachedAt: now, LastAccessed: now,
	}); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	for i := 0; i < downloads; i++ {
		if err := a.metadata.UpdateDownloadCount(context.Background(), registry, name, version); err != nil {
			t.Fatalf("UpdateDownloadCount: %v", err)
		}
	}
}

func TestGetOnePackageByRegistryNameVersion(t *testing.T) {
	a := newTestApp(t, nil)
	seedOnePackage(t, a, "npm", "left-pad", "1.3.0", 3)
	seedOnePackage(t, a, "npm", "@types/node", "18.0.0", 1)
	seedOnePackage(t, a, "go", "github.com/google/uuid/@v/v1.6.0.zip", "v1.6.0", 2)

	for _, tc := range []struct {
		path, name, version string
	}{
		{"/api/packages/npm/left-pad/1.3.0", "left-pad", "1.3.0"},
		{"/api/packages/npm/@types/node/18.0.0", "@types/node", "18.0.0"},
		{"/api/packages/go/github.com/google/uuid/v1.6.0", "github.com/google/uuid/@v/v1.6.0.zip", "v1.6.0"},
	} {
		out, body := getJSON(t, a, tc.path)
		if out["name"] != tc.name || out["version"] != tc.version || out["checksum_sha256"] != "abc123" {
			t.Errorf("GET %s = %s", tc.path, body)
		}
	}

	out, _ := getJSON(t, a, "/api/packages/npm/left-pad/1.3.0")
	if out["download_count"] != float64(3) {
		t.Errorf("download_count = %v, want the persisted count", out["download_count"])
	}
}

func TestGetOnePackageIsNotFoundWhenMissing(t *testing.T) {
	a := newTestApp(t, nil)
	seedOnePackage(t, a, "npm", "left-pad", "1.3.0", 0)
	for _, path := range []string{
		"/api/packages/npm/left-pad/9.9.9",
		"/api/packages/npm/nope/1.0.0",
		"/api/packages/rubygems/left-pad/1.3.0",
	} {
		if code, _, body := doRequest(t, a, path, nil); code != http.StatusNotFound {
			t.Errorf("GET %s = %d %s, want 404", path, code, body)
		}
	}
}

func TestListStillServesTwoSegmentPaths(t *testing.T) {
	a := newTestApp(t, nil)
	seedOnePackage(t, a, "npm", "left-pad", "1.3.0", 0)
	out, body := getJSON(t, a, "/api/packages")
	if pkgs, _ := out["packages"].([]any); len(pkgs) != 1 {
		t.Errorf("list = %s", body)
	}
}
