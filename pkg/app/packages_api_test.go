package app

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

type listResponse struct {
	Packages []struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		Registry        string `json:"registry"`
		Vulnerabilities struct {
			Status    string `json:"status"`
			IsBlocked bool   `json:"isBlocked"`
			Total     int    `json:"total"`
			Counts    struct {
				Critical int `json:"critical"`
			} `json:"counts"`
		} `json:"vulnerabilities"`
	} `json:"packages"`
	Total       int `json:"total"`
	TotalGroups int `json:"total_groups"`
	Page        int `json:"page"`
	PageSize    int `json:"page_size"`
}

func getList(t *testing.T, a *App, target string) listResponse {
	t.Helper()
	code, _, body := doRequest(t, a, target, nil)
	if code != 200 {
		t.Fatalf("GET %s = %d %s", target, code, body)
	}
	var out listResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

func TestListPackagesPagesGroupsAndAttachesScans(t *testing.T) {
	a, _ := newScanningApp(t)
	seedScanned(t, a, 0, 60)

	page := getList(t, a, "/api/packages?page=2&page_size=25")
	if page.TotalGroups != 60 || page.Page != 2 || page.PageSize != 25 {
		t.Fatalf("paging fields = %+v", page)
	}
	if len(page.Packages) != 25 || page.Total != 25 {
		t.Fatalf("page 2 holds %d rows (total %d), want 25", len(page.Packages), page.Total)
	}
	if first := page.Packages[0].Name; first != "pkg-025" {
		t.Errorf("page 2 starts at %q, want pkg-025 (name order)", first)
	}

	last := getList(t, a, "/api/packages?page=3&page_size=25")
	if len(last.Packages) != 10 {
		t.Errorf("last page holds %d rows, want 10", len(last.Packages))
	}

	found := getList(t, a, "/api/packages?q=PKG-005&page_size=10")
	if found.TotalGroups != 1 || len(found.Packages) != 1 {
		t.Fatalf("search pkg-005 = %+v", found)
	}
	v := found.Packages[0].Vulnerabilities
	if v.Status != "vulnerable" || !v.IsBlocked || v.Total != 1 || v.Counts.Critical != 1 {
		t.Errorf("pkg-005 scan block = %+v, want vulnerable, blocked, one critical", v)
	}

	clean := getList(t, a, "/api/packages?q=pkg-006&page_size=10")
	if cv := clean.Packages[0].Vulnerabilities; cv.Status != "clean" || cv.IsBlocked {
		t.Errorf("pkg-006 scan block = %+v, want clean and not blocked", cv)
	}

	if none := getList(t, a, "/api/packages?registry=pypi&page_size=10"); none.TotalGroups != 0 || len(none.Packages) != 0 {
		t.Errorf("pypi filter = %+v, want empty", none)
	}
}

func TestListPackagesRecentFirst(t *testing.T) {
	a, _ := newScanningApp(t)
	seedScanned(t, a, 0, 30)
	recent := getList(t, a, "/api/packages?sort=cached_at&order=desc&page=1&page_size=3")
	got := []string{recent.Packages[0].Name, recent.Packages[1].Name, recent.Packages[2].Name}
	want := []string{"pkg-000", "pkg-001", "pkg-002"} // seedScanned caches pkg-N N minutes ago
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recent = %v, want %v", got, want)
		}
	}
}

// The unpaginated list used to stop at 1000 rows without saying so.
func TestListPackagesUnpaginatedHasNoCap(t *testing.T) {
	a := newTestApp(t, nil)
	ctx := context.Background()
	const rows = 1005
	now := time.Now()
	for i := 0; i < rows; i++ {
		name := fmt.Sprintf("bulk-%04d", i)
		if err := a.metadata.SavePackage(ctx, &metadata.Package{
			Registry: "npm", Name: name, Version: "1.0.0", StorageKey: "npm/" + name, Size: 1, CachedAt: now, LastAccessed: now,
		}); err != nil {
			t.Fatalf("SavePackage: %v", err)
		}
	}
	all := getList(t, a, "/api/packages")
	if len(all.Packages) != rows || all.Total != rows || all.TotalGroups != rows {
		t.Fatalf("unpaginated list = %d rows, total %d, groups %d; want %d", len(all.Packages), all.Total, all.TotalGroups, rows)
	}
	if capped := getList(t, a, "/api/packages?page_size=100000"); capped.PageSize != maxPageSize || len(capped.Packages) != maxPageSize {
		t.Errorf("page_size clamp: size %d, rows %d, want %d", capped.PageSize, len(capped.Packages), maxPageSize)
	}
}

func TestStatsFromAggregates(t *testing.T) {
	a, _ := newScanningApp(t)
	seedScanned(t, a, 0, 60)
	code, _, body := doRequest(t, a, "/api/stats", nil)
	if code != 200 {
		t.Fatalf("GET /api/stats = %d %s", code, body)
	}
	var out struct {
		Stats      map[string]float64            `json:"stats"`
		Registries map[string]map[string]float64 `json:"registries"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Stats["total_packages"] != 60 || out.Stats["scanned_packages"] != 60 || out.Stats["vulnerable_packages"] != 12 {
		t.Errorf("stats = %v", out.Stats)
	}
	if out.Stats["blocked_packages"] != 12 {
		t.Errorf("blocked_packages = %v, want the 12 critical packages", out.Stats["blocked_packages"])
	}
	if npm := out.Registries["npm"]; npm["count"] != 60 || npm["size"] != 6000 {
		t.Errorf("npm registry = %v, want 60 rows and 6000 bytes", npm)
	}
}
