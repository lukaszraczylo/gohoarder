package app

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// The list shows Go modules by module path, but rows are stored under cache keys.
func TestGoVulnerabilityDetailsResolveCacheKeyNames(t *testing.T) {
	a := newTestApp(t, nil)
	ctx := context.Background()
	const module, version = "github.com/go-git/go-git/v5", "v5.3.0"
	for _, ext := range []string{"info", "mod", "zip"} {
		name := module + "/@v/" + version + "." + ext
		err := a.metadata.SavePackage(ctx, &metadata.Package{
			Registry: "go", Name: name, Version: version, StorageKey: "go/" + name,
			Size: 10, CachedAt: time.Now(), LastAccessed: time.Now(),
		})
		if err != nil {
			t.Fatalf("SavePackage %s: %v", name, err)
		}
	}
	err := a.metadata.SaveScanResult(ctx, &metadata.ScanResult{
		Registry: "go", PackageName: module + "/@v/" + version + ".zip", PackageVersion: version,
		Scanner: "osv", Status: metadata.ScanStatusVulnerable, ScannedAt: time.Now(),
		Vulnerabilities:    []metadata.Vulnerability{{ID: "GHSA-test", Severity: "critical"}},
		VulnerabilityCount: 1,
	})
	if err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}

	code, _, body := doRequest(t, a, "/api/packages/go/"+module+"/"+version+"/vulnerabilities", nil)
	if code != http.StatusOK {
		t.Fatalf("GET details = %d %s, want 200", code, body)
	}
	var out struct {
		Scanned bool `json:"scanned"`
		Count   int  `json:"vulnerability_count"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if !out.Scanned || out.Count != 1 {
		t.Errorf("details = %s, want the .zip scan with 1 vulnerability", body)
	}
}

func TestGoVulnerabilityDetailsMissingModuleIs404(t *testing.T) {
	a := newTestApp(t, nil)
	code, _, body := doRequest(t, a, "/api/packages/go/example.com/nope/v1.0.0/vulnerabilities", nil)
	if code != http.StatusNotFound {
		t.Errorf("GET missing = %d %s, want 404", code, body)
	}
}
