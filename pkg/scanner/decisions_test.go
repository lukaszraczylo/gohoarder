package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
	"github.com/stretchr/testify/require"
)

type decisionFixture struct {
	scan                                  *metadata.ScanResult
	name, registry, pkg, version, release string
	scannedWithoutRow                     bool
}

func vuln(id, severity string) metadata.Vulnerability {
	return metadata.Vulnerability{ID: id, Severity: severity}
}

func decisionFixtures() []decisionFixture {
	scan := func(status metadata.ScanStatus, details map[string]interface{}, vulns ...metadata.Vulnerability) *metadata.ScanResult {
		return &metadata.ScanResult{Scanner: "t", Status: status, ScannedAt: time.Now(), Details: details, Vulnerabilities: vulns, VulnerabilityCount: len(vulns)}
	}
	return []decisionFixture{
		{name: "clean", registry: "npm", pkg: "clean", version: "1.0.0", scan: scan(metadata.ScanStatusClean, nil)},
		{name: "critical", registry: "npm", pkg: "crit", version: "1.0.0", scan: scan(metadata.ScanStatusVulnerable, nil, vuln("CVE-1", "critical"))},
		{name: "high+moderate", registry: "npm", pkg: "mix", version: "1.0.0", scan: scan(metadata.ScanStatusVulnerable, nil, vuln("CVE-2", "high"), vuln("CVE-3", "medium"))},
		{name: "low only", registry: "npm", pkg: "low", version: "1.0.0", scan: scan(metadata.ScanStatusVulnerable, nil, vuln("CVE-4", "low"), vuln("CVE-5", "weird"))},
		{name: "infra error", registry: "npm", pkg: "infra", version: "1.0.0", scan: scan(metadata.ScanStatusError, map[string]interface{}{DetailInfrastructureError: true})},
		{name: "scan error", registry: "npm", pkg: "err", version: "1.0.0", scan: scan(metadata.ScanStatusError, nil)},
		{name: "scanned without row", registry: "npm", pkg: "lost", version: "1.0.0", scannedWithoutRow: true},
		{name: "go zip", registry: "go", pkg: "github.com/a/b/@v/v1.0.0.zip", version: "v1.0.0", scan: scan(metadata.ScanStatusVulnerable, nil, vuln("CVE-6", "high"))},
		{name: "pypi release", registry: "pypi", pkg: "six", version: "six-1.0.tar.gz", release: "1.0", scan: scan(metadata.ScanStatusVulnerable, nil, vuln("CVE-7", "critical"))},
	}
}

func seedDecisions(t *testing.T, store *gormstore.GORMStoreV2) map[string]string {
	t.Helper()
	ctx := context.Background()
	ids := map[string]string{}
	for _, f := range decisionFixtures() {
		now := time.Now()
		require.NoError(t, store.SavePackage(ctx, &metadata.Package{
			Registry: f.registry, Name: f.pkg, Version: f.version, ReleaseVersion: f.release,
			StorageKey: fmt.Sprintf("%s/%s/%s", f.registry, f.pkg, f.version), Size: 1, CachedAt: now, LastAccessed: now,
		}))
		if f.scan != nil {
			res := *f.scan
			res.Registry, res.PackageName, res.PackageVersion = f.registry, f.pkg, f.version
			require.NoError(t, store.SaveScanResult(ctx, &res))
		}
		if f.scannedWithoutRow {
			require.NoError(t, store.DB().Exec("UPDATE packages SET security_scanned = ? WHERE name = ?", true, f.pkg).Error)
		}
	}
	return ids
}

func addBypass(t *testing.T, store *gormstore.GORMStoreV2, kind metadata.BypassType, target string) {
	t.Helper()
	require.NoError(t, store.SaveCVEBypass(context.Background(), &metadata.CVEBypass{
		Type: kind, Target: target, Reason: "test", CreatedBy: "test", Active: true, ExpiresAt: time.Now().Add(time.Hour),
	}))
}

// ScanDecisions must reach the same verdict as CheckVulnerabilities for every policy and bypass combination.
func TestScanDecisionsMatchCheckVulnerabilities(t *testing.T) {
	policies := map[string]config.SecurityConfig{
		"block on high":         {Enabled: true, BlockOnSeverity: "high", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}},
		"block on critical":     {Enabled: true, BlockOnSeverity: "critical", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}},
		"block on moderate":     {Enabled: true, BlockOnSeverity: "moderate", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}},
		"block on low":          {Enabled: true, BlockOnSeverity: "low", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}},
		"thresholds":            {Enabled: true, BlockOnSeverity: "none", BlockThresholds: config.VulnerabilityThresholds{Critical: 0, High: 1, Medium: 0, Low: 1}},
		"fail closed":           {Enabled: true, FailClosed: true, BlockOnSeverity: "none", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}},
		"block on low, closed":  {Enabled: true, FailClosed: true, BlockOnSeverity: "low", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}},
		"disabled scanner mgr":  {Enabled: false, BlockOnSeverity: "low"},
		"thresholds, high only": {Enabled: true, BlockOnSeverity: "none", BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: 0, Medium: -1, Low: -1}},
	}
	bypassSets := map[string]func(*testing.T, *gormstore.GORMStoreV2){
		"no bypass":      func(*testing.T, *gormstore.GORMStoreV2) {},
		"cve bypass":     func(t *testing.T, s *gormstore.GORMStoreV2) { addBypass(t, s, metadata.BypassTypeCVE, "cve-1") },
		"cve high":       func(t *testing.T, s *gormstore.GORMStoreV2) { addBypass(t, s, metadata.BypassTypeCVE, "CVE-2") },
		"package bypass": func(t *testing.T, s *gormstore.GORMStoreV2) { addBypass(t, s, metadata.BypassTypePackage, "npm/crit") },
		"go bypass": func(t *testing.T, s *gormstore.GORMStoreV2) {
			addBypass(t, s, metadata.BypassTypePackage, "go/github.com/a/b@v1.0.0")
		},
		"release bypass": func(t *testing.T, s *gormstore.GORMStoreV2) {
			addBypass(t, s, metadata.BypassTypePackage, "pypi/six@1.0")
		},
		"both kinds": func(t *testing.T, s *gormstore.GORMStoreV2) {
			addBypass(t, s, metadata.BypassTypeCVE, "CVE-3")
			addBypass(t, s, metadata.BypassTypePackage, "npm/mix")
		},
	}

	for bypassName, setBypasses := range bypassSets {
		store, err := gormstore.NewV2(gormstore.Config{
			Driver: "sqlite", DSN: fmt.Sprintf("file:dec_%d?mode=memory&cache=shared", time.Now().UnixNano()),
			MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: "silent",
		})
		require.NoError(t, err)
		seedDecisions(t, store)
		setBypasses(t, store)

		for policyName, cfg := range policies {
			t.Run(bypassName+"/"+policyName, func(t *testing.T) {
				mgr, err := New(cfg, store)
				require.NoError(t, err)
				ctx := context.Background()

				decisions, err := mgr.ScanDecisions(ctx, nil)
				require.NoError(t, err)
				require.Len(t, decisions, len(decisionFixtures()))
				for _, d := range decisions {
					s := d.Summary
					wantBlocked, wantReason, checkErr := mgr.CheckVulnerabilities(ctx, s.Registry, s.Name, s.Version)
					require.NoError(t, checkErr)
					require.Equal(t, wantBlocked, d.Blocked, "%s/%s@%s", s.Registry, s.Name, s.Version)
					if wantBlocked && len(wantReason) > 0 && wantReason[0] != 'P' {
						// Count-based reasons carry numbers that differ only under CVE bypasses; the
						// fixed fail-closed reasons must match exactly.
						require.Equal(t, wantReason, d.Reason)
					}
				}

				ids := make([]string, 0, 3)
				for _, d := range decisions[:3] {
					ids = append(ids, d.Summary.PackageID)
				}
				subset, err := mgr.ScanDecisions(ctx, ids)
				require.NoError(t, err)
				require.Len(t, subset, 3)
			})
		}
		require.NoError(t, store.Close())
	}
}

func TestScanDecisionsVerdicts(t *testing.T) {
	store, err := gormstore.NewV2(gormstore.Config{
		Driver: "sqlite", DSN: fmt.Sprintf("file:decv_%d?mode=memory&cache=shared", time.Now().UnixNano()),
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: "silent",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	seedDecisions(t, store)
	addBypass(t, store, metadata.BypassTypeCVE, "CVE-3")
	mgr, err := New(config.SecurityConfig{
		Enabled: true, BlockOnSeverity: "high",
		BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1},
	}, store)
	require.NoError(t, err)

	decisions, err := mgr.ScanDecisions(context.Background(), nil)
	require.NoError(t, err)
	blocked := map[string]bool{}
	for _, d := range decisions {
		blocked[d.Summary.Name] = d.Blocked
	}
	require.Equal(t, map[string]bool{
		"clean": false, "crit": true, "mix": true, "low": false,
		"infra": false, // infrastructure failure serves the package unless fail_closed
		"err":   true, "lost": true,
		"github.com/a/b/@v/v1.0.0.zip": true, "six": true,
	}, blocked)
}
