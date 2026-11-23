package pipaudit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures are real `pip-audit -f json` output from pip-audit 2.10.1 (see FINDINGS GH-25); the
// example proxy credential in the requests 2.19.0 advisory text is replaced by a placeholder.
func fixture(name string) string { return filepath.Join("testdata", name) }

func ids(res *metadata.ScanResult) []string {
	out := make([]string, 0, len(res.Vulnerabilities))
	for _, v := range res.Vulnerabilities {
		out = append(out, v.ID)
	}
	return out
}

// artifactNamed is a stand-in for the cached file: the scanner audits the release by name and version.
func artifactNamed(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	return p
}

func TestScanAuditsTheReleaseFromARequirement(t *testing.T) {
	// pip-audit has no wheel argument: its positional argument is a project directory, and it
	// has no --pyproject flag. A wheel or sdist is audited by name and version.
	for _, file := range []string{"requests-2.19.0-py2.py3-none-any.whl", "requests-2.19.0.tar.gz"} {
		t.Run(file, func(t *testing.T) {
			args := scannertest.Fake(t, "pip-audit", fixture("requests-2.19.0.json"), "WARNING:pip_audit._cli:--no-deps is supported\n", 1)

			res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "pypi", "requests", "2.19.0", artifactNamed(t, file))

			require.NoError(t, err)
			assert.Equal(t, metadata.ScanStatusVulnerable, res.Status)
			assert.ElementsMatch(t, []string{"PYSEC-2018-28", "PYSEC-2023-74", "PYSEC-2026-1872", "PYSEC-2026-1873", "PYSEC-2026-2275"}, ids(res),
				"pip-audit lists an advisory once per alias; the result lists it once")
			assert.Equal(t, 5, res.VulnerabilityCount)

			got := scannertest.Args(t, args)
			assert.Equal(t, []string{"-r"}, got[:1])
			assert.Equal(t, []string{"--no-deps", "--disable-pip", "-f", "json"}, got[2:])
		})
	}
}

func TestScanWritesAPinnedRequirement(t *testing.T) {
	dir := t.TempDir()
	scannertest.Script(t, "pip-audit", `cat "$2" > `+filepath.Join(dir, "req")+`; cat `+mustAbs(t, "six-1.16.0.json"))

	res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "pypi", "six", "1.16.0", artifactNamed(t, "six-1.16.0-py2.py3-none-any.whl"))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
	req, err := os.ReadFile(filepath.Join(dir, "req")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	assert.Equal(t, "six==1.16.0\n", string(req))
}

func mustAbs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(fixture(name))
	require.NoError(t, err)
	return p
}

func TestScanSeverityAndFix(t *testing.T) {
	scannertest.Fake(t, "pip-audit", fixture("requests-2.32.0.json"), "", 1)

	res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "pypi", "requests", "2.32.0", artifactNamed(t, "requests-2.32.0.tar.gz"))

	require.NoError(t, err)
	fixed := map[string]string{}
	for _, v := range res.Vulnerabilities {
		fixed[v.ID] = v.FixedIn
		assert.Equal(t, "MODERATE", v.Severity, "pip-audit reports no severity")
	}
	assert.Equal(t, map[string]string{"PYSEC-2026-1872": "2.32.4", "PYSEC-2026-2275": "2.33.0"}, fixed)
}

func TestScanPackageUnknownToPyPIIsAnError(t *testing.T) {
	// pip-audit exits 0 with a skip_reason; reading that as clean would pass an unaudited package.
	scannertest.Fake(t, "pip-audit", fixture("not-on-pypi.json"), "", 0)

	res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "pypi", "nopkg-zzz", "1.0", artifactNamed(t, "nopkg_zzz-1.0.tar.gz"))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusError, res.Status)
	assert.Contains(t, res.Details["error"], "not found on PyPI")
	assert.Equal(t, false, res.Details[scanerr.DetailInfrastructure])
}

func TestScanFailuresAreErrorResultsWithACause(t *testing.T) {
	cases := []struct {
		name, stderr string
		infra        bool
	}{
		{"network", "ERROR: HTTPSConnectionPool: Max retries exceeded: ConnectionError ECONNREFUSED", true},
		{"other", "ERROR:pip_audit._cli:boom", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scannertest.Fake(t, "pip-audit", "", tc.stderr, 1)

			res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "pypi", "six", "1.16.0", artifactNamed(t, "six-1.16.0.tar.gz"))

			require.NoError(t, err)
			assert.Equal(t, metadata.ScanStatusError, res.Status)
			assert.Equal(t, tc.infra, res.Details[scanerr.DetailInfrastructure])
		})
	}
}

func TestScanRefusesNameAndVersionThatCouldBeOptions(t *testing.T) {
	args := scannertest.Fake(t, "pip-audit", fixture("six-1.16.0.json"), "", 0)

	for _, c := range [][2]string{{"--index-url=http://evil", "1.0"}, {"six", "1.0\n--index-url=x"}, {"", "1.0"}, {"six", ""}} {
		res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "pypi", c[0], c[1], artifactNamed(t, "x.whl"))
		require.NoError(t, err)
		assert.Equal(t, metadata.ScanStatusError, res.Status, "%q %q", c[0], c[1])
	}
	_, statErr := os.Stat(args)
	assert.True(t, os.IsNotExist(statErr), "pip-audit never ran")
}

func TestScanSkipsOtherRegistries(t *testing.T) {
	res, err := New(config.PipAuditConfig{}).Scan(context.Background(), "npm", "p", "1", "/x")
	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
}
