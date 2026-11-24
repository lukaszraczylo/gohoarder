package app

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

func seedAliased(t *testing.T, a *App) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if err := a.metadata.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "aliased", Version: "1.0.0", StorageKey: "npm/aliased", Size: 10, CachedAt: now, LastAccessed: now,
	}); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if err := a.metadata.SaveScanResult(ctx, &metadata.ScanResult{
		Registry: "npm", PackageName: "aliased", PackageVersion: "1.0.0", Scanner: "osv", Status: metadata.ScanStatusVulnerable, ScannedAt: now,
		VulnerabilityCount: 1,
		Vulnerabilities: []metadata.Vulnerability{{
			ID: "GHSA-xvch-5gv4-984h", Aliases: []string{"CVE-2021-44906"}, Severity: "critical", DetectedBy: []string{"osv"},
		}},
	}); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}
}

func TestDetailsShowAliasesAndHonourABypassOnAnAlias(t *testing.T) {
	a, _ := newScanningApp(t)
	a.config.Security.BlockOnSeverity = "critical"
	seedAliased(t, a)

	held, _ := getJSON(t, a, "/api/packages/npm/aliased/1.0.0/vulnerabilities")
	if jsonAt(held, "decision", "verdict") != VerdictHeld {
		t.Fatalf("verdict before the bypass = %v, want held", jsonAt(held, "decision", "verdict"))
	}
	if got, _ := jsonAt(held, "vulnerabilities", 0, "aliases").([]any); len(got) != 1 || got[0] != "CVE-2021-44906" {
		t.Errorf("aliases = %v, want [CVE-2021-44906]", got)
	}

	if err := a.metadata.SaveCVEBypass(context.Background(), &metadata.CVEBypass{
		Type: metadata.BypassTypeCVE, Target: "cve-2021-44906", Reason: "not reachable", CreatedBy: "alice",
		Active: true, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	waved, _ := getJSON(t, a, "/api/packages/npm/aliased/1.0.0/vulnerabilities")
	if jsonAt(waved, "decision", "verdict") != VerdictBypassed {
		t.Errorf("verdict with a CVE bypass = %v, want bypassed", jsonAt(waved, "decision", "verdict"))
	}
	if jsonAt(waved, "vulnerabilities", 0, "bypassed") != true {
		t.Errorf("finding bypassed = %v, want true", jsonAt(waved, "vulnerabilities", 0, "bypassed"))
	}
	if jsonAt(waved, "vulnerabilities", 0, "bypass", "created_by") != "alice" {
		t.Errorf("bypass = %v", jsonAt(waved, "vulnerabilities", 0, "bypass"))
	}
}
