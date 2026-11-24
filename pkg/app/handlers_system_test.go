package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// jsonAt walks decoded JSON along keys (strings) and indexes (ints); a missing step yields nil.
func jsonAt(v any, path ...any) any {
	for _, step := range path {
		switch k := step.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil
			}
			v = m[k]
		case int:
			l, ok := v.([]any)
			if !ok || k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func getJSON(t *testing.T, a *App, target string) (map[string]any, string) {
	t.Helper()
	code, _, body := doRequest(t, a, target, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", target, code, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out, body
}

func disableAllScanners(c *config.Config) {
	sc := &c.Security.Scanners
	sc.Trivy.Enabled, sc.Grype.Enabled, sc.OSV.Enabled, sc.Govulncheck.Enabled = false, false, false, false
	sc.NpmAudit.Enabled, sc.PipAudit.Enabled, sc.GHSA.Enabled = false, false, false
}

func TestSystemReportsEffectivePolicy(t *testing.T) {
	a := newTestApp(t, func(c *config.Config) {
		c.Security.Enabled = true
		c.Security.UpdateDBOnStartup = false
		c.Security.FailClosed = true
		c.Security.BlockOnSeverity = "critical"
		c.Security.RescanInterval = 6 * time.Hour
		c.Security.RescanConcurrency = 0
		c.Security.ScanWaitTimeout = 0
		disableAllScanners(c)
		c.Cache.MaxSizeBytes = 1 << 30
		c.Cache.IdleTTL = 24 * time.Hour
		c.Cache.DefaultTTL = 7 * 24 * time.Hour
	})

	out, _ := getJSON(t, a, "/api/system")
	checks := map[string][2]any{
		"fail_closed":       {jsonAt(out, "security", "fail_closed"), true},
		"block_on_severity": {jsonAt(out, "security", "block_on_severity"), "critical"},
		"rescan interval":   {jsonAt(out, "security", "rescan", "interval"), float64(6 * 3600)},
		"rescan workers":    {jsonAt(out, "security", "rescan", "concurrency"), float64(1)},
		"scan wait":         {jsonAt(out, "security", "scan_wait_timeout"), float64(30)},
		"cache max":         {jsonAt(out, "cache", "max_size"), float64(1 << 30)},
		"cache idle":        {jsonAt(out, "cache", "idle_ttl"), float64(86400)},
		"cache default":     {jsonAt(out, "cache", "default_ttl"), float64(7 * 86400)},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %v, want %v", name, c[0], c[1])
		}
	}
	scanners, _ := jsonAt(out, "security", "scanners").([]any)
	if len(scanners) != 7 {
		t.Fatalf("scanners = %d entries, want all 7", len(scanners))
	}
	for i := range scanners {
		if jsonAt(scanners, i, "enabled") != false || jsonAt(scanners, i, "healthy") != nil {
			t.Errorf("disabled scanner %v reported %v", jsonAt(scanners, i, "name"), scanners[i])
		}
	}
}

// The system view is for display only; no configured secret or path may appear in it.
func TestSystemLeaksNoSecrets(t *testing.T) {
	const secret = "ghp_super-secret-token"
	a := newTestApp(t, func(c *config.Config) {
		c.Security.Enabled = true
		c.Security.UpdateDBOnStartup = false
		disableAllScanners(c)
		c.Security.Scanners.GHSA.Token = secret
		c.Security.Scanners.Trivy.CacheDB = "/srv/private/trivy-db"
	})
	_, body := getJSON(t, a, "/api/system")
	for _, banned := range []string{secret, "/srv/private", "token", "dsn", "password"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(banned)) {
			t.Errorf("/api/system exposes %q: %s", banned, body)
		}
	}
}

func TestSystemUpstreamsKeepOnlySchemeAndHost(t *testing.T) {
	a := newTestApp(t, func(c *config.Config) {
		c.Handlers.NPM.UpstreamRegistry = fmt.Sprintf("https://%s:%s@npm.example.com:8443/private/path?token=abc", "deploy", "s3cret")
		c.Handlers.PyPI.UpstreamURL = "not a url"
	})
	out, body := getJSON(t, a, "/api/system")
	if got := jsonAt(out, "upstreams", "npm"); got != "https://npm.example.com:8443" {
		t.Errorf("npm upstream = %v", got)
	}
	if got := jsonAt(out, "upstreams", "pypi"); got != "" {
		t.Errorf("unparseable upstream = %v, want empty", got)
	}
	for _, banned := range []string{"s3cret", "deploy", "private/path", "abc"} {
		if strings.Contains(body, banned) {
			t.Errorf("/api/system exposes %q: %s", banned, body)
		}
	}
}

func TestSystemRequiresAuthWhenEnabled(t *testing.T) {
	a := newTestApp(t, func(c *config.Config) { c.Auth.Enabled = true })
	code, _, _ := doRequest(t, a, "/api/system", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("GET /api/system without a key = %d, want 401", code)
	}
}

func seedBypassed(t *testing.T, a *App) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	for _, name := range []string{"held", "waved", "plain"} {
		if err := a.metadata.SavePackage(ctx, &metadata.Package{
			Registry: "npm", Name: name, Version: "1.0.0", StorageKey: "npm/" + name, Size: 10, CachedAt: now, LastAccessed: now,
		}); err != nil {
			t.Fatalf("SavePackage: %v", err)
		}
		res := &metadata.ScanResult{Registry: "npm", PackageName: name, PackageVersion: "1.0.0", Scanner: "trivy+osv", Status: metadata.ScanStatusClean, ScannedAt: now}
		if name != "plain" {
			res.Status = metadata.ScanStatusVulnerable
			res.VulnerabilityCount = 2
			res.Vulnerabilities = []metadata.Vulnerability{
				{ID: "CVE-2021-44906", Severity: "critical", DetectedBy: []string{"trivy", "osv"}, FixedIn: "1.2.6"},
				{ID: "CVE-2022-0001", Severity: "low", DetectedBy: []string{"osv"}},
			}
		}
		if err := a.metadata.SaveScanResult(ctx, res); err != nil {
			t.Fatalf("SaveScanResult: %v", err)
		}
	}
	if err := a.metadata.SaveCVEBypass(ctx, &metadata.CVEBypass{
		Type: metadata.BypassTypePackage, Target: "npm/waved@1.0.0", Reason: "vendor patch", CreatedBy: "alice",
		Active: true, ExpiresAt: now.Add(48 * time.Hour),
	}); err != nil {
		t.Fatalf("SaveCVEBypass: %v", err)
	}
}

func newVerdictApp(t *testing.T) *App {
	t.Helper()
	a, _ := newScanningApp(t)
	a.config.Security.BlockOnSeverity = "critical"
	seedBypassed(t, a)
	return a
}

func TestListPackagesCarriesVerdicts(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages")
	pkgs, _ := out["packages"].([]any)
	got := map[string]string{}
	for i := range pkgs {
		name, _ := jsonAt(pkgs, i, "name").(string)
		verdict, _ := jsonAt(pkgs, i, "vulnerabilities", "verdict").(string)
		got[name] = verdict
		if name == "held" && jsonAt(pkgs, i, "vulnerabilities", "reason") == nil {
			t.Errorf("held package has no reason")
		}
		if name == "waved" && jsonAt(pkgs, i, "vulnerabilities", "bypass", "created_by") != "alice" {
			t.Errorf("bypassed package bypass = %v", jsonAt(pkgs, i, "vulnerabilities", "bypass"))
		}
	}
	want := map[string]string{"held": VerdictHeld, "waved": VerdictBypassed, "plain": VerdictCleared}
	for name, verdict := range want {
		if got[name] != verdict {
			t.Errorf("%s verdict = %q, want %q", name, got[name], verdict)
		}
	}
}

func TestStatsCountsBypassedPackages(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/stats")
	if jsonAt(out, "stats", "blocked_packages") != float64(1) || jsonAt(out, "stats", "bypassed_packages") != float64(1) {
		t.Errorf("stats = %v, want 1 held and 1 bypassed", out["stats"])
	}
}

func TestVulnerabilityDetailsExplainVerdictAndScanners(t *testing.T) {
	a := newVerdictApp(t)
	details := func(name string) map[string]any {
		out, _ := getJSON(t, a, "/api/packages/npm/"+name+"/1.0.0/vulnerabilities")
		return out
	}

	held := details("held")
	if jsonAt(held, "decision", "verdict") != VerdictHeld || jsonAt(held, "decision", "blocked") != true || jsonAt(held, "decision", "reason") == "" {
		t.Errorf("held decision = %v", held["decision"])
	}
	scanners, _ := held["scanners"].([]any)
	if len(scanners) != 2 {
		t.Fatalf("scanners = %v, want trivy and osv", scanners)
	}
	findings := map[string]any{}
	for i := range scanners {
		findings[jsonAt(scanners, i, "name").(string)] = jsonAt(scanners, i, "findings")
	}
	if findings["trivy"] != float64(1) || findings["osv"] != float64(2) {
		t.Errorf("findings per scanner = %v, want trivy 1, osv 2", findings)
	}
	if jsonAt(scanners, 0, "severity_counts", "critical") != float64(1) {
		t.Errorf("trivy severity counts = %v", jsonAt(scanners, 0, "severity_counts"))
	}
	if by, _ := jsonAt(held, "vulnerabilities", 0, "detected_by").([]any); len(by) != 2 {
		t.Errorf("detected_by = %v", by)
	}

	waved := details("waved")
	if jsonAt(waved, "decision", "verdict") != VerdictBypassed || jsonAt(waved, "decision", "blocked") != false ||
		jsonAt(waved, "decision", "bypass", "reason") != "vendor patch" {
		t.Errorf("bypassed decision = %v", waved["decision"])
	}

	plain := details("plain")
	if jsonAt(plain, "decision", "verdict") != VerdictCleared || jsonAt(plain, "decision", "bypass") != nil {
		t.Errorf("clean decision = %v", plain["decision"])
	}
}

// Scoped npm names and Go module paths contain slashes; the per-package analytics route must accept them.
func TestPackageAnalyticsAcceptsNamesWithSlashes(t *testing.T) {
	a := newTestApp(t, nil)
	for _, name := range []string{"@types/node", "github.com/google/uuid/@v/v1.6.0.zip", "lodash"} {
		a.analyticsEngine.TrackDownload(analytics.PackageDownload{Registry: "npm", Name: name, Version: "1.0.0", Timestamp: time.Now(), BytesSize: 5})
	}
	for _, name := range []string{"@types/node", "github.com/google/uuid/@v/v1.6.0.zip", "lodash"} {
		out, body := getJSON(t, a, "/api/analytics/package/npm/"+name)
		if jsonAt(out, "package", "TotalDownloads") != float64(1) {
			t.Errorf("analytics for %q = %s, want one download", name, body)
		}
	}
	// A package with no record yet is a normal answer; a 404 would show as a failed request in the browser.
	out, body := getJSON(t, a, "/api/analytics/package/npm/@types/missing")
	if pkg, present := out["package"]; !present || pkg != nil {
		t.Errorf("unknown package = %s, want 200 with a null package", body)
	}
}
