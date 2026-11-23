package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stubResult(name string, status metadata.ScanStatus, details map[string]interface{}, vulns ...metadata.Vulnerability) *stubScanner {
	return &stubScanner{name: name, result: &metadata.ScanResult{
		ID: name, Scanner: name, ScannedAt: time.Now(), Status: status, Details: details,
		Vulnerabilities: vulns, VulnerabilityCount: len(vulns),
	}}
}

func scanWith(t *testing.T, cfg config.SecurityConfig, scanners ...Scanner) *metadata.ScanResult {
	t.Helper()
	store := &stubMetadataStore{}
	mgr, err := New(cfg, store)
	require.NoError(t, err)
	t.Cleanup(mgr.Stop)
	for _, s := range scanners {
		mgr.RegisterScanner(s)
	}
	require.NoError(t, mgr.ScanPackage(context.Background(), "npm", "left-pad", "1.0.0", "/tmp/x"))
	require.Len(t, store.savedResults, 1)
	return store.savedResults[0]
}

func TestScanPackage_ErrorResultPlusCleanReadsClean(t *testing.T) {
	for _, failClosed := range []bool{false, true} {
		saved := scanWith(t, config.SecurityConfig{Enabled: true, FailClosed: failClosed},
			stubResult("npm-audit", metadata.ScanStatusError, map[string]interface{}{"error": "parse"}),
			stubResult("osv", metadata.ScanStatusClean, nil))

		assert.Equal(t, metadata.ScanStatusClean, saved.Status, "fail_closed=%v", failClosed)
		assert.Equal(t, "osv", saved.Scanner, "a failed scanner is not part of the merge")
		assert.NotContains(t, saved.Details, "npm-audit")
	}
}

func TestScanPackage_ErrorResultDoesNotHideFindings(t *testing.T) {
	saved := scanWith(t, config.SecurityConfig{Enabled: true},
		stubResult("npm-audit", metadata.ScanStatusError, nil),
		stubResult("osv", metadata.ScanStatusVulnerable, nil, vuln("CVE-1", "HIGH")))

	assert.Equal(t, metadata.ScanStatusVulnerable, saved.Status)
	assert.Len(t, saved.Vulnerabilities, 1)
}

func TestScanPackage_AllErrorResultsReadError(t *testing.T) {
	saved := scanWith(t, config.SecurityConfig{Enabled: true},
		stubResult("npm-audit", metadata.ScanStatusError, map[string]interface{}{"error": "parse"}),
		stubResult("grype", metadata.ScanStatusError, nil))

	assert.Equal(t, metadata.ScanStatusError, saved.Status)
	assert.NotEqual(t, true, saved.Details[DetailInfrastructureError], "no failure was infrastructure")
}

func TestScanPackage_InfrastructureErrorResultsCountAsInfrastructure(t *testing.T) {
	infra := map[string]interface{}{DetailInfrastructureError: true}

	t.Run("all infrastructure", func(t *testing.T) {
		saved := scanWith(t, config.SecurityConfig{Enabled: true},
			stubResult("npm-audit", metadata.ScanStatusError, infra),
			stubResult("trivy", metadata.ScanStatusError, infra))
		assert.Equal(t, metadata.ScanStatusError, saved.Status)
		assert.Equal(t, true, saved.Details[DetailInfrastructureError])
	})

	t.Run("one other failure makes it a package failure", func(t *testing.T) {
		saved := scanWith(t, config.SecurityConfig{Enabled: true},
			stubResult("npm-audit", metadata.ScanStatusError, infra),
			stubResult("grype", metadata.ScanStatusError, nil))
		assert.NotEqual(t, true, saved.Details[DetailInfrastructureError])
	})
}

func TestScanPackage_ErrorPlusCleanIsServedEvenWhenFailClosed(t *testing.T) {
	cfg := config.SecurityConfig{Enabled: true, FailClosed: true}
	saved := scanWith(t, cfg,
		stubResult("npm-audit", metadata.ScanStatusError, nil),
		stubResult("osv", metadata.ScanStatusClean, nil))

	mgr, err := New(cfg, &resultStore{stubMetadataStore: &stubMetadataStore{}, scan: saved})
	require.NoError(t, err)
	blocked, reason, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	require.NoError(t, err)
	assert.False(t, blocked, "reason %q", reason)
}

func TestScanPackage_BlockingStillAppliesToRealFindings(t *testing.T) {
	cfg := config.SecurityConfig{Enabled: true, BlockOnSeverity: "high",
		BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1}}
	saved := scanWith(t, cfg,
		stubResult("npm-audit", metadata.ScanStatusError, nil),
		stubResult("osv", metadata.ScanStatusVulnerable, nil, vuln("CVE-1", "HIGH")))

	mgr, err := New(cfg, &resultStore{stubMetadataStore: &stubMetadataStore{}, scan: saved})
	require.NoError(t, err)
	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	require.NoError(t, err)
	assert.True(t, blocked)
}

func TestMergeResults_IgnoresErrorResults(t *testing.T) {
	mgr := newTestManager(t, &stubMetadataStore{})
	ok := stubResult("osv", metadata.ScanStatusClean, nil).result
	bad := stubResult("grype", metadata.ScanStatusError, nil).result

	assert.Equal(t, metadata.ScanStatusClean, mgr.mergeResults([]*metadata.ScanResult{bad, ok}, []string{"grype", "osv"}).Status)
	assert.Equal(t, metadata.ScanStatusError, mgr.mergeResults([]*metadata.ScanResult{bad, bad}, []string{"a", "b"}).Status)
}
