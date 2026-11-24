package grype

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures are real `grype -o json -q` output from grype 0.121.2 (see FINDINGS GH-25).
func fixture(name string) string { return filepath.Join("testdata", name) }

func TestParseFileScanTargetIsAString(t *testing.T) {
	data, err := os.ReadFile(fixture("file-minimist-0.0.8.json"))
	require.NoError(t, err)

	res, err := parse(data)

	require.NoError(t, err)
	assert.Equal(t, "file", res.Source.Type)
}

func TestScanMapsRealOutput(t *testing.T) {
	cases := []struct {
		wantSeverities                        map[string]string
		wantFixedIn                           map[string]string
		name, fixture, registry, pkg, version string
		wantPurl                              string
		wantStatus                            metadata.ScanStatus
	}{
		{
			name: "npm vulnerable", fixture: "purl-minimist-0.0.8.json", registry: "npm", pkg: "minimist", version: "0.0.8",
			wantPurl: "pkg:npm/minimist@0.0.8", wantStatus: metadata.ScanStatusVulnerable,
			wantSeverities: map[string]string{"GHSA-xvch-5gv4-984h": "CRITICAL", "GHSA-vh95-rmgr-6w4m": "MODERATE"},
			wantFixedIn:    map[string]string{"GHSA-xvch-5gv4-984h": "0.2.4"},
		},
		{
			name: "npm clean", fixture: "purl-dayjs-1.11.13.json", registry: "npm", pkg: "dayjs", version: "1.11.13",
			wantPurl: "pkg:npm/dayjs@1.11.13", wantStatus: metadata.ScanStatusClean,
		},
		{
			name: "go vulnerable", fixture: "purl-go-text-0.3.5.json", registry: "go", pkg: "golang.org/x/text/@v/v0.3.5.zip", version: "v0.3.5",
			wantPurl: "pkg:golang/golang.org/x/text@v0.3.5", wantStatus: metadata.ScanStatusVulnerable,
			wantSeverities: map[string]string{"GHSA-69ch-w2m2-3vjp": "HIGH", "GO-2026-6629": "HIGH"},
		},
		{
			name: "pypi vulnerable", fixture: "purl-pypi-requests-2.19.0.json", registry: "pypi", pkg: "requests", version: "2.19.0",
			wantPurl: "pkg:pypi/requests@2.19.0", wantStatus: metadata.ScanStatusVulnerable,
			wantSeverities: map[string]string{"GHSA-x84v-xcm2-53pg": "HIGH", "GHSA-j8r2-6x86-q33q": "MODERATE"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := scannertest.Fake(t, "grype", fixture(tc.fixture), "", 0)

			res, err := New(config.GrypeConfig{}).Scan(context.Background(), tc.registry, tc.pkg, tc.version, "/tmp/artifact")

			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, res.Status)
			assert.Equal(t, tc.wantPurl, scannertest.Args(t, args)[0], "the package is scanned by purl, not by its archive")
			got := map[string]string{}
			fixed := map[string]string{}
			for _, v := range res.Vulnerabilities {
				got[v.ID] = v.Severity
				fixed[v.ID] = v.FixedIn
			}
			for id, sev := range tc.wantSeverities {
				assert.Equal(t, sev, got[id], id)
			}
			for id, f := range tc.wantFixedIn {
				assert.Equal(t, f, fixed[id], id)
			}
			assert.Equal(t, len(res.Vulnerabilities), res.VulnerabilityCount)
		})
	}
}

func TestScanFallsBackToFileForUnknownRegistry(t *testing.T) {
	args := scannertest.Fake(t, "grype", fixture("file-minimist-0.0.8.json"), "", 0)

	res, err := New(config.GrypeConfig{}).Scan(context.Background(), "docker", "x", "1", "/tmp/artifact.tar")

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
	assert.Equal(t, "/tmp/artifact.tar", scannertest.Args(t, args)[0])
}

func TestScanIgnoresStderrNoise(t *testing.T) {
	scannertest.Fake(t, "grype", fixture("purl-dayjs-1.11.13.json"), "[0000] WARN something\n", 0)

	res, err := New(config.GrypeConfig{}).Scan(context.Background(), "npm", "dayjs", "1.11.13", "/tmp/a.tgz")

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
}

func TestScanFailureWithoutOutputIsAnError(t *testing.T) {
	scannertest.Fake(t, "grype", "", "failed to load vulnerability db", 1)

	_, err := New(config.GrypeConfig{}).Scan(context.Background(), "npm", "dayjs", "1.11.13", "/tmp/a.tgz")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load vulnerability db")
}

func TestPurl(t *testing.T) {
	cases := []struct{ registry, name, version, want string }{
		{"npm", "left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"},
		{"npm", "@babel/traverse", "7.0.0", "pkg:npm/%40babel/traverse@7.0.0"},
		{"go", "github.com/!azure/go-x/@v/v1.2.3.zip", "v1.2.3", "pkg:golang/github.com/Azure/go-x@v1.2.3"},
		{"go", "github.com/a/b/v2/@v/v2.0.0+incompatible.zip", "v2.0.0+incompatible", "pkg:golang/github.com/a/b/v2@v2.0.0%2Bincompatible"},
		{"pypi", "Zope.Interface_x", "5.0", "pkg:pypi/zope-interface-x@5.0"},
		{"npm", "", "1", ""},
		{"npm", "x", "", ""},
		{"docker", "x", "1", ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, purl(tc.registry, tc.name, tc.version), "%s %s", tc.registry, tc.name)
	}
}

func TestFindingsCarryTheRelatedCVEAsAnAlias(t *testing.T) {
	data, err := os.ReadFile(fixture("purl-minimist-0.0.8.json"))
	require.NoError(t, err)
	parsed, err := parse(data)
	require.NoError(t, err)

	res := New(config.GrypeConfig{}).convertGrypeResult(parsed, "npm", "minimist", "0.0.8")

	aliases := map[string][]string{}
	for _, v := range res.Vulnerabilities {
		aliases[v.ID] = v.Aliases
	}
	assert.Equal(t, []string{"CVE-2021-44906"}, aliases["GHSA-xvch-5gv4-984h"])
	assert.Equal(t, []string{"CVE-2020-7598"}, aliases["GHSA-vh95-rmgr-6w4m"])
}
