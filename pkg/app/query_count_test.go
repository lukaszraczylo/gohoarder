package app

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/internal/dbcount"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
	"gorm.io/gorm"
)

// seedScanned stores n scanned npm packages, every fifth with a critical finding.
func seedScanned(t *testing.T, a *App, from, n int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	for i := from; i < from+n; i++ {
		name := fmt.Sprintf("pkg-%03d", i)
		err := a.metadata.SavePackage(ctx, &metadata.Package{
			Registry: "npm", Name: name, Version: "1.0.0", StorageKey: "npm/" + name + "/1.0.0",
			Size: 100, CachedAt: now.Add(-time.Duration(i) * time.Minute), LastAccessed: now,
		})
		if err != nil {
			t.Fatalf("SavePackage: %v", err)
		}
		res := &metadata.ScanResult{
			Registry: "npm", PackageName: name, PackageVersion: "1.0.0", Scanner: "test",
			Status: metadata.ScanStatusClean, ScannedAt: now,
		}
		if i%5 == 0 {
			res.Status = metadata.ScanStatusVulnerable
			res.VulnerabilityCount = 1
			res.Vulnerabilities = []metadata.Vulnerability{{ID: fmt.Sprintf("CVE-2026-%04d", i), Severity: "critical"}}
		}
		if err := a.metadata.SaveScanResult(ctx, res); err != nil {
			t.Fatalf("SaveScanResult: %v", err)
		}
	}
}

func newScanningApp(t *testing.T) (*App, *dbcount.Counter) {
	t.Helper()
	a := newTestApp(t, func(c *config.Config) {
		c.Security.Enabled = true
		c.Security.Scanners.Static.Enabled = false
		c.Security.UpdateDBOnStartup = false
	})
	store, ok := a.metadata.(*gormstore.GORMStoreV2)
	if !ok {
		t.Fatalf("metadata store is %T, want *gormstore.GORMStoreV2", a.metadata)
	}
	var counter *dbcount.Counter
	store.WrapDB(func(db *gorm.DB) *gorm.DB {
		counted, c := dbcount.Attach(db)
		counter = c
		return counted
	})
	return a, counter
}

// queriesFor reports how many SQL statements one GET runs.
func queriesFor(t *testing.T, a *App, c *dbcount.Counter, target string) int {
	t.Helper()
	c.Reset()
	if code, _, body := doRequest(t, a, target, nil); code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", target, code, body)
	}
	return c.Count()
}

// The dashboard endpoints must cost the same number of statements for 20 rows and for 120.
func TestDashboardEndpointsQueryCountIsConstant(t *testing.T) {
	a, counter := newScanningApp(t)
	targets := []string{"/api/packages", "/api/packages?page=1&page_size=25", "/api/stats"}

	seedScanned(t, a, 0, 20)
	small := map[string]int{}
	for _, target := range targets {
		small[target] = queriesFor(t, a, counter, target)
	}

	seedScanned(t, a, 20, 100)
	for _, target := range targets {
		large := queriesFor(t, a, counter, target)
		t.Logf("%-40s 20 rows: %3d queries, 120 rows: %3d queries", target, small[target], large)
		if large != small[target] {
			t.Errorf("%s: %d queries for 20 rows but %d for 120 rows; the count must not grow with rows", target, small[target], large)
		}
	}
}
