package govulncheck

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The .stream fixtures are real govulncheck 1.9.0 `-json` output, cut down to the config, finding and
// referenced osv messages, and real `go list` output (see FINDINGS GH-25).
func abs(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	require.NoError(t, err)
	return p
}

// module is a zip as the module proxy serves it; the scanner audits the module by path and version.
func module(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.zip")
	f, err := os.Create(p) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	zw := zip.NewWriter(f)
	w, err := zw.Create("example.com/m@v1.0.0/go.mod")
	require.NoError(t, err)
	_, err = w.Write([]byte("module example.com/m\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, f.Close())
	return p
}

// fakeGo fakes `go list`, recording the working directory's go.mod and main.go for the audit.
func fakeGo(t *testing.T, listFixture string, exit int, stderr string) (rec string) {
	t.Helper()
	rec = t.TempDir()
	body := fmt.Sprintf(`
case "$1" in
list) cp go.mod %[1]q/go.mod; echo "$GOFLAGS|$GOTOOLCHAIN" > %[1]q/env; %[2]s; printf '%%s' %[3]q >&2; exit %[4]d ;;
esac`, rec, catOrNothing(listFixture), stderr, exit)
	scannertest.Script(t, "go", body)
	return rec
}

func catOrNothing(path string) string {
	if path == "" {
		return "true"
	}
	return "cat " + fmt.Sprintf("%q", path)
}

// fakeGovulncheck fakes govulncheck: it records main.go and the arguments, prints fixture.
func fakeGovulncheck(t *testing.T, fixture string, exit int, stderr string) (argsFile, mainCopy string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	mainCopy = filepath.Join(dir, "main.go")
	scannertest.Script(t, "govulncheck", fmt.Sprintf(`
cp main.go %[2]q
for a in "$@"; do echo "$a" >> %[1]q; done
%[3]s
printf '%%s' %[4]q >&2
exit %[5]d`, argsFile, mainCopy, catOrNothing(fixture), stderr, exit))
	return argsFile, mainCopy
}

func ids(res *metadata.ScanResult) map[string]string {
	out := map[string]string{}
	for _, v := range res.Vulnerabilities {
		out[v.ID] = v.FixedIn
	}
	return out
}

func TestScanReadsPrettyPrintedFindings(t *testing.T) {
	// govulncheck -json prints indented objects, not one object per line.
	fakeGo(t, abs(t, "golist-gin-v1.6.0.txt"), 0, "")
	fakeGovulncheck(t, abs(t, "gin-v1.6.0.stream"), 0, "")

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "github.com/gin-gonic/gin/@v/v1.6.0.zip", "v1.6.0", module(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusVulnerable, res.Status)
	assert.Equal(t, map[string]string{
		"GO-2021-0052": "v1.7.7",
		"GO-2023-1737": "v1.9.1",
	}, ids(res), "one entry per advisory against gin, with the fixed version; the x/sys findings belong to a dependency")
}

func TestScanIgnoresFindingsInDependencies(t *testing.T) {
	// gin's go.mod requires an old x/sys; a build that uses gin resolves its own x/sys version.
	fakeGo(t, abs(t, "golist-gin-v1.6.0.txt"), 0, "")
	fakeGovulncheck(t, abs(t, "gin-v1.6.0-source-scan.stream"), 0, "")

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "github.com/gin-gonic/gin/@v/v1.6.0.zip", "v1.6.0", module(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
	assert.Empty(t, res.Vulnerabilities)
}

func TestScanAuditsTheModuleItself(t *testing.T) {
	rec := fakeGo(t, abs(t, "golist-x-text-v0.3.5.txt"), 0, "")
	args, mainCopy := fakeGovulncheck(t, abs(t, "x-text-v0.3.5.stream"), 0, "")

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "golang.org/x/text/@v/v0.3.5.zip", "v0.3.5", module(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusVulnerable, res.Status)
	assert.Equal(t, map[string]string{
		"GO-2021-0113": "v0.3.7", "GO-2022-1059": "v0.3.8", "GO-2026-5970": "v0.39.0", "GO-2026-6629": "v0.41.0",
	}, ids(res), "advisories against the scanned module, which a scan of its own source never reports")
	for _, v := range res.Vulnerabilities {
		assert.Equal(t, "HIGH", v.Severity)
		assert.Equal(t, []string{"https://pkg.go.dev/vuln/" + v.ID}, v.References)
	}

	gomod, err := os.ReadFile(filepath.Join(rec, "go.mod")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	assert.Contains(t, string(gomod), "require golang.org/x/text v0.3.5")

	env, err := os.ReadFile(filepath.Join(rec, "env")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	assert.Equal(t, "-mod=mod -modcacherw|local\n", string(env))

	assert.Equal(t, []string{"-json", "-scan", "module"}, scannertest.Args(t, args))

	src, err := os.ReadFile(mainCopy) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	imports := string(src)
	assert.Contains(t, imports, `_ "golang.org/x/text/language"`)
	assert.NotContains(t, imports, "/cmd/gotext\"", "package main cannot be imported")
	assert.NotContains(t, imports, "/internal", "internal packages cannot be imported")
}

func TestScanRemovesTheModulesItDownloaded(t *testing.T) {
	rec := t.TempDir()
	// Like go, the fake leaves the module cache read-only unless GOFLAGS has -modcacherw.
	scannertest.Script(t, "go", fmt.Sprintf(`
[ -n "$GOMODCACHE" ] || exit 1
mkdir -p "$GOMODCACHE/example.com/dep@v1.0.0"
touch "$GOMODCACHE/example.com/dep@v1.0.0/dep.go"
case "$GOFLAGS" in *-modcacherw*) ;; *) chmod 0555 "$GOMODCACHE/example.com/dep@v1.0.0" ;; esac
echo "$GOMODCACHE" > %q/go
echo "github.com/google/uuid uuid 12 0 "`, rec))
	scannertest.Script(t, "govulncheck", fmt.Sprintf(`
echo "$GOMODCACHE" > %q/govulncheck
cat %q`, rec, abs(t, "google-uuid-v1.6.0.stream")))

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "github.com/google/uuid/@v/v1.6.0.zip", "v1.6.0", module(t))

	require.NoError(t, err)
	require.Equal(t, metadata.ScanStatusClean, res.Status)
	listCache, err := os.ReadFile(filepath.Join(rec, "go")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	scanCache, err := os.ReadFile(filepath.Join(rec, "govulncheck")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	assert.Equal(t, string(listCache), string(scanCache), "govulncheck reads the modules go list downloaded")
	assert.NoDirExists(t, strings.TrimSpace(string(listCache)), "the scan keeps no downloaded modules")
}

func TestScanCleanModule(t *testing.T) {
	scannertest.Script(t, "go", `echo "github.com/google/uuid uuid 12 0 "`)
	_, _ = fakeGovulncheck(t, abs(t, "google-uuid-v1.6.0.stream"), 0, "")

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "github.com/google/uuid/@v/v1.6.0.zip", "v1.6.0", module(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
}

func TestScanModuleWithoutImportablePackagesIsSkipped(t *testing.T) {
	scannertest.Script(t, "go", `echo "example.com/m/cmd/tool main 1 0 "`)

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "example.com/m/@v/v1.0.0.zip", "v1.0.0", module(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
	assert.Contains(t, res.Details["skipped"], "no importable package")
}

func TestScanFailuresAreErrorResultsWithACause(t *testing.T) {
	cases := []struct {
		setup func(t *testing.T)
		name  string
		infra bool
	}{
		{name: "module download fails on the network", setup: func(t *testing.T) { fakeGo(t, "", 1, "dial tcp: lookup proxy.golang.org: no such host") }, infra: true},
		{name: "module is not in the proxy", setup: func(t *testing.T) { fakeGo(t, "", 1, "reading example.com/m/@v/v1.0.0.mod: 404 Not Found") }, infra: false},
		{name: "govulncheck prints nothing", setup: func(t *testing.T) {
			fakeGo(t, abs(t, "golist-gin-v1.6.0.txt"), 0, "")
			fakeGovulncheck(t, "", 1, "govulncheck: loading packages: boom")
		}, infra: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)

			res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "example.com/m/@v/v1.0.0.zip", "v1.0.0", module(t))

			require.NoError(t, err)
			assert.Equal(t, metadata.ScanStatusError, res.Status)
			assert.Equal(t, tc.infra, res.Details[scanerr.DetailInfrastructure])
		})
	}
}

func TestScanRefusesModuleCoordinatesThatCouldInjectGoMod(t *testing.T) {
	fakeGo(t, abs(t, "golist-gin-v1.6.0.txt"), 0, "")

	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "go", "example.com/m/@v/v1.0.0\nreplace x => y.zip", "v1.0.0\nreplace a => b", module(t))

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusError, res.Status)
}

func TestScanSkipsOtherRegistries(t *testing.T) {
	res, err := New(config.GovulncheckConfig{}).Scan(context.Background(), "npm", "p", "1", "/x")
	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
}
