package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scanOf(vulns ...metadata.Vulnerability) *metadata.ScanResult {
	return &metadata.ScanResult{Status: metadata.ScanStatusVulnerable, Vulnerabilities: vulns, VulnerabilityCount: len(vulns)}
}

const (
	testCVE  = "CVE-2021-44906"
	testGHSA = "GHSA-xvch-5gv4-984h"
)

func TestMergeResultsDedupesOneAdvisoryUnderDifferentIDs(t *testing.T) {
	mgr := newTestManager(t, &stubMetadataStore{})
	osv := scanOf(metadata.Vulnerability{ID: testGHSA, Aliases: []string{testCVE}, Severity: "MODERATE", References: []string{"https://osv.dev/x"}})
	trivy := scanOf(metadata.Vulnerability{ID: testCVE, Severity: "CRITICAL", FixedIn: "1.2.6", References: []string{"https://nvd.nist.gov/y"}})

	merged := mgr.mergeResults([]*metadata.ScanResult{osv, trivy}, []string{"osv", "trivy"})

	require.Len(t, merged.Vulnerabilities, 1)
	f := merged.Vulnerabilities[0]
	assert.Equal(t, testCVE, f.ID, "the CVE id leads whichever scanner saw it first")
	assert.Equal(t, []string{testGHSA}, f.Aliases)
	assert.Equal(t, []string{"osv", "trivy"}, f.DetectedBy)
	assert.Equal(t, "CRITICAL", f.Severity)
	assert.Equal(t, "1.2.6", f.FixedIn)
	assert.ElementsMatch(t, []string{"https://osv.dev/x", "https://nvd.nist.gov/y"}, f.References)
	assert.Equal(t, 1, merged.VulnerabilityCount)
	assert.Equal(t, 1, merged.Details["severity_counts"].(map[string]int)["CRITICAL"])
}

func TestMergeResultsIsIndependentOfScannerOrder(t *testing.T) {
	mgr := newTestManager(t, &stubMetadataStore{})
	osv := scanOf(metadata.Vulnerability{ID: testGHSA, Aliases: []string{testCVE}, Severity: "HIGH"})
	trivy := scanOf(metadata.Vulnerability{ID: testCVE, Severity: "HIGH"})

	a := mgr.mergeResults([]*metadata.ScanResult{osv, trivy}, []string{"osv", "trivy"}).Vulnerabilities[0]
	b := mgr.mergeResults([]*metadata.ScanResult{trivy, osv}, []string{"trivy", "osv"}).Vulnerabilities[0]

	assert.Equal(t, a.ID, b.ID)
	assert.Equal(t, a.Aliases, b.Aliases)
}

func TestMergeResultsKeepsUnrelatedFindingsApart(t *testing.T) {
	mgr := newTestManager(t, &stubMetadataStore{})
	osv := scanOf(metadata.Vulnerability{ID: testGHSA, Aliases: []string{testCVE}, Severity: "HIGH"})
	other := scanOf(metadata.Vulnerability{ID: "CVE-2022-0001", Severity: "LOW"})

	merged := mgr.mergeResults([]*metadata.ScanResult{osv, other}, []string{"osv", "trivy"})

	require.Len(t, merged.Vulnerabilities, 2)
	assert.Equal(t, 2, merged.VulnerabilityCount)
}

func TestMergeResultsJoinsFindingsLinkedByALaterAlias(t *testing.T) {
	mgr := newTestManager(t, &stubMetadataStore{})
	grype := scanOf(
		metadata.Vulnerability{ID: testGHSA, Severity: "HIGH"},
		metadata.Vulnerability{ID: testCVE, Severity: "HIGH"},
	)
	osv := scanOf(metadata.Vulnerability{ID: "PYSEC-2021-1", Aliases: []string{testGHSA, testCVE}, Severity: "HIGH"})

	merged := mgr.mergeResults([]*metadata.ScanResult{grype, osv}, []string{"grype", "osv"})

	require.Len(t, merged.Vulnerabilities, 1)
	assert.ElementsMatch(t, []string{testGHSA, "PYSEC-2021-1"}, merged.Vulnerabilities[0].Aliases)
	assert.Equal(t, []string{"grype", "osv"}, merged.Vulnerabilities[0].DetectedBy)
}

func TestMergeResultsDoesNotListAScannerTwice(t *testing.T) {
	mgr := newTestManager(t, &stubMetadataStore{})
	res := scanOf(
		metadata.Vulnerability{ID: testCVE, Severity: "HIGH"},
		metadata.Vulnerability{ID: testGHSA, Aliases: []string{testCVE}, Severity: "HIGH"},
	)
	merged := mgr.mergeResults([]*metadata.ScanResult{res}, []string{"osv"})
	require.Len(t, merged.Vulnerabilities, 1)
	assert.Equal(t, []string{"osv"}, merged.Vulnerabilities[0].DetectedBy)
}

// aliasStore saves one scan whose finding is reported under a GHSA id with a CVE alias.
func aliasStore(t *testing.T, vulns ...metadata.Vulnerability) (*gormstore.GORMStoreV2, *Manager) {
	t.Helper()
	store, err := gormstore.NewV2(gormstore.Config{
		Driver: "sqlite", DSN: fmt.Sprintf("file:alias_%d?mode=memory&cache=shared", time.Now().UnixNano()),
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: "silent",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, store.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "minimist", Version: "1.2.5", StorageKey: "npm/minimist/1.2.5", Size: 1, CachedAt: now, LastAccessed: now,
	}))
	require.NoError(t, store.SaveScanResult(ctx, &metadata.ScanResult{
		Registry: "npm", PackageName: "minimist", PackageVersion: "1.2.5", Scanner: "osv", Status: metadata.ScanStatusVulnerable,
		ScannedAt: now, Vulnerabilities: vulns, VulnerabilityCount: len(vulns),
	}))
	mgr, err := New(config.SecurityConfig{
		Enabled: true, BlockOnSeverity: "none",
		BlockThresholds: config.VulnerabilityThresholds{Critical: 0, High: -1, Medium: -1, Low: -1},
	}, store)
	require.NoError(t, err)
	return store, mgr
}

func TestCVEBypassClearsAFindingReportedUnderItsGHSAAlias(t *testing.T) {
	store, mgr := aliasStore(t, metadata.Vulnerability{ID: testGHSA, Aliases: []string{testCVE}, Severity: "CRITICAL"})
	ctx := context.Background()

	blocked, _, err := mgr.CheckVulnerabilities(ctx, "npm", "minimist", "1.2.5")
	require.NoError(t, err)
	require.True(t, blocked, "held before the bypass")

	addBypass(t, store, metadata.BypassTypeCVE, "cve-2021-44906")

	blocked, _, err = mgr.CheckVulnerabilities(ctx, "npm", "minimist", "1.2.5")
	require.NoError(t, err)
	assert.False(t, blocked, "a CVE bypass must clear the GHSA-only finding that carries the CVE alias")

	decisions, err := mgr.ScanDecisions(ctx, nil)
	require.NoError(t, err)
	require.Len(t, decisions, 1)
	assert.False(t, decisions[0].Blocked)
	require.NotNil(t, decisions[0].Bypass, "the decision names the bypass that applied")
}

func TestGHSABypassClearsAFindingReportedUnderItsCVE(t *testing.T) {
	store, mgr := aliasStore(t, metadata.Vulnerability{ID: testCVE, Aliases: []string{testGHSA}, Severity: "CRITICAL"})
	addBypass(t, store, metadata.BypassTypeCVE, testGHSA)

	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "minimist", "1.2.5")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestBypassForAnUnrelatedIDDoesNotMatch(t *testing.T) {
	store, mgr := aliasStore(t, metadata.Vulnerability{ID: testGHSA, Aliases: []string{testCVE}, Severity: "CRITICAL"})
	addBypass(t, store, metadata.BypassTypeCVE, "CVE-2099-0001")

	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "minimist", "1.2.5")
	require.NoError(t, err)
	assert.True(t, blocked)
}

func TestStoredFindingsWithoutAliasesStillLoad(t *testing.T) {
	store, mgr := aliasStore(t, metadata.Vulnerability{ID: testCVE, Severity: "CRITICAL"})
	addBypass(t, store, metadata.BypassTypeCVE, testCVE)

	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "minimist", "1.2.5")
	require.NoError(t, err)
	assert.False(t, blocked, "an old finding with no aliases still matches by its own id")

	decisions, err := mgr.ScanDecisions(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, decisions, 1)
	assert.Empty(t, decisions[0].Summary.Vulnerabilities[0].Aliases)
}
