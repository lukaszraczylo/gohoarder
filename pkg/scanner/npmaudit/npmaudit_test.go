package npmaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures are real `npm audit --json` output from npm 11.12.1 (see FINDINGS GH-25).
func fixture(name string) string { return filepath.Join("testdata", name) }

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixture(name))
	require.NoError(t, err)
	return data
}

func severities(res *metadata.ScanResult) map[string]string {
	out := map[string]string{}
	for _, v := range res.Vulnerabilities {
		out[v.ID] = v.Severity
	}
	return out
}

func TestParseKeepsBothViaShapes(t *testing.T) {
	// `via` is an array of package names for a transitive finding and an array of advisory
	// objects for a direct one; mkdirp-0.5.1.json has both, the dev-tree file many of each.
	for _, name := range []string{"dayjs-1.11.13.json", "minimist-0.0.8.json", "mkdirp-0.5.1.json", "request-2.88.2.json", "mkdirp-0.5.1-dev-tree.json"} {
		t.Run(name, func(t *testing.T) {
			_, err := parse(readFixture(t, name))
			require.NoError(t, err)
		})
	}
}

func TestConvertMapsAdvisories(t *testing.T) {
	cases := []struct {
		want    map[string]string
		fixture string
	}{
		{fixture: "dayjs-1.11.13.json", want: map[string]string{}},
		{fixture: "minimist-0.0.8.json", want: map[string]string{"GHSA-vh95-rmgr-6w4m": "MODERATE", "GHSA-xvch-5gv4-984h": "CRITICAL"}},
		// mkdirp has no advisory of its own: its entry only points at minimist.
		{fixture: "mkdirp-0.5.1.json", want: map[string]string{"GHSA-vh95-rmgr-6w4m": "MODERATE", "GHSA-xvch-5gv4-984h": "CRITICAL"}},
		{fixture: "request-2.88.2.json", want: map[string]string{
			"GHSA-fjxv-7rqg-78g4": "CRITICAL", "GHSA-hmw2-7cc7-3qxx": "HIGH", "GHSA-6rw7-vpxm-498p": "MODERATE",
			"GHSA-4mjr-xmp4-gh2g": "MODERATE", "GHSA-p8p7-x288-28g6": "MODERATE", "GHSA-72xf-g2v4-qvf3": "MODERATE",
			"GHSA-w5hq-g745-h8pq": "MODERATE",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			audit, err := parse(readFixture(t, tc.fixture))
			require.NoError(t, err)

			res := New(config.NpmAuditConfig{}).convertResult(audit, "npm", "p", "1")

			assert.Equal(t, tc.want, severities(res))
			assert.Equal(t, len(tc.want), res.VulnerabilityCount)
			if len(tc.want) == 0 {
				assert.Equal(t, metadata.ScanStatusClean, res.Status)
			} else {
				assert.Equal(t, metadata.ScanStatusVulnerable, res.Status)
			}
		})
	}
}

func TestConvertCarriesTitleAndReference(t *testing.T) {
	audit, err := parse(readFixture(t, "minimist-0.0.8.json"))
	require.NoError(t, err)

	res := New(config.NpmAuditConfig{}).convertResult(audit, "npm", "minimist", "0.0.8")

	ids := make([]string, 0)
	for _, v := range res.Vulnerabilities {
		ids = append(ids, v.ID)
		assert.Equal(t, "Prototype Pollution in minimist", v.Title)
		assert.Equal(t, []string{"https://github.com/advisories/" + v.ID}, v.References)
	}
	sort.Strings(ids)
	assert.Equal(t, []string{"GHSA-vh95-rmgr-6w4m", "GHSA-xvch-5gv4-984h"}, ids)
}

// npmScript fakes npm: `install` exits installExit, `audit` prints stdout and exits 1.
func npmScript(t *testing.T, auditFixture string, installExit int, installStderr string) (recDir string) {
	t.Helper()
	recDir = t.TempDir()
	audit := "cat " + fmt.Sprintf("%q", mustAbs(t, auditFixture))
	if auditFixture == "" {
		audit = "printf '%s' 'not json'"
	}
	scannertest.Script(t, "npm", fmt.Sprintf(`
case "$1" in
install) cat package.json > %[1]q/package.json; echo "$@" > %[1]q/install; printf '%%s' %[2]q >&2; exit %[3]d ;;
audit) echo "$@" > %[1]q/audit; %[4]s; exit 1 ;;
esac`, recDir, installStderr, installExit, audit))
	return recDir
}

func mustAbs(t *testing.T, name string) string {
	t.Helper()
	if name == "" {
		return ""
	}
	abs, err := filepath.Abs(fixture(name))
	require.NoError(t, err)
	return abs
}

func artifact(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pkg.tgz")
	require.NoError(t, os.WriteFile(p, []byte("tgz"), 0o600))
	return p
}

func TestScanAuditsThePackageItselfWithoutItsDevTree(t *testing.T) {
	rec := npmScript(t, "minimist-0.0.8.json", 0, "")

	res, err := New(config.NpmAuditConfig{}).Scan(context.Background(), "npm", "minimist", "0.0.8", artifact(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusVulnerable, res.Status)
	assert.Len(t, res.Vulnerabilities, 2)

	pkgJSON, err := os.ReadFile(filepath.Join(rec, "package.json")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	var wrapper struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	require.NoError(t, json.Unmarshal(pkgJSON, &wrapper))
	assert.Equal(t, map[string]string{"minimist": "file:./artifact.tgz"}, wrapper.Dependencies,
		"the tarball is a dependency of a wrapper project, so its own advisories are audited and its devDependencies are never resolved")

	audit, err := os.ReadFile(filepath.Join(rec, "audit")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	assert.Contains(t, string(audit), "--omit=dev")
}

func TestScanCleanPackage(t *testing.T) {
	npmScript(t, "dayjs-1.11.13.json", 0, "")

	res, err := New(config.NpmAuditConfig{}).Scan(context.Background(), "npm", "dayjs", "1.11.13", artifact(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
}

func TestScanFailuresAreErrorResultsWithACause(t *testing.T) {
	cases := []struct {
		name       string
		fixture    string
		installOut string
		installRC  int
		infra      bool
	}{
		{"network down", "", "npm error code ENOTFOUND", 1, true},
		{"unresolvable tree", "", "npm error code ERESOLVE", 1, false},
		{"unparseable audit", "", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			npmScript(t, tc.fixture, tc.installRC, tc.installOut)

			res, err := New(config.NpmAuditConfig{}).Scan(context.Background(), "npm", "p", "1", artifact(t))

			require.NoError(t, err)
			assert.Equal(t, metadata.ScanStatusError, res.Status)
			assert.Equal(t, tc.infra, res.Details[scanerr.DetailInfrastructure])
		})
	}
}

func TestScanAuditErrorDocumentIsAnErrorResult(t *testing.T) {
	doc := filepath.Join(t.TempDir(), "enolock.json")
	require.NoError(t, os.WriteFile(doc, []byte(`{"error":{"code":"ENOLOCK","summary":"This command requires an existing lockfile.","detail":""}}`), 0o600))
	scannertest.Script(t, "npm", fmt.Sprintf(`case "$1" in audit) cat %q; exit 1 ;; esac`, doc))

	res, err := New(config.NpmAuditConfig{}).Scan(context.Background(), "npm", "p", "1", artifact(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusError, res.Status)
	assert.Contains(t, res.Details["error"], "ENOLOCK")
}

func TestScanSkipsOtherRegistries(t *testing.T) {
	res, err := New(config.NpmAuditConfig{}).Scan(context.Background(), "pypi", "p", "1", "/x")
	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
}
