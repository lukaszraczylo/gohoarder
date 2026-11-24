package trivy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanTimeoutIsAnInfrastructureErrorResult(t *testing.T) {
	scannertest.Script(t, "trivy", "exec sleep 5")

	res, err := New(config.TrivyConfig{Timeout: 100 * time.Millisecond}).Scan(context.Background(), "pypi", "p", "1", "/x")

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusError, res.Status)
	assert.Equal(t, true, res.Details[scanerr.DetailInfrastructure])
}

type entry struct {
	name, body, link string
	typeflag         byte
}

func tgz(t *testing.T, entries ...entry) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: tf, Mode: 0o644, Linkname: e.link}
		if tf == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		require.NoError(t, tw.WriteHeader(hdr))
		if tf == tar.TypeReg {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	p := filepath.Join(t.TempDir(), "p.tgz")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

func TestNPMScanRunsRootfsOnUnpackedTree(t *testing.T) {
	rec := t.TempDir()
	scannertest.Script(t, "trivy", fmt.Sprintf(`
printf '%%s\n' "$@" > %[1]q/args
for last; do :; done
cp "$last/node_modules/@scope/pkg/package.json" %[1]q/package.json
echo "$last" > %[1]q/root
echo '{"Results":[]}'`, rec))
	archive := tgz(t,
		entry{name: "package/", typeflag: tar.TypeDir},
		entry{name: "package/package.json", body: `{"name":"@scope/pkg"}`},
		entry{name: "package/lib/index.js", body: "x"},
	)

	res, err := New(config.TrivyConfig{}).Scan(context.Background(), "npm", "@scope/pkg", "1.0.0", archive)

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusClean, res.Status)
	args, err := os.ReadFile(filepath.Join(rec, "args")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	root, err := os.ReadFile(filepath.Join(rec, "root")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	assert.Equal(t, []string{"rootfs", "--format", "json", "--quiet", strings.TrimSpace(string(root))}, lines)
	pkg, err := os.ReadFile(filepath.Join(rec, "package.json")) // #nosec G304 -- test temp dir
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"@scope/pkg"}`, string(pkg))
	_, err = os.Stat(strings.TrimSpace(string(root))) // #nosec G304 G703 -- path from the test fake
	assert.True(t, os.IsNotExist(err), "temp tree must be removed")
}

func TestNonNPMScansTheFileWithFS(t *testing.T) {
	argsFile := scannertest.Fake(t, "trivy", "", "", 0)
	_, err := New(config.TrivyConfig{}).Scan(context.Background(), "pypi", "p", "1", "/x/p.whl")
	require.Error(t, err) // empty output is not JSON
	assert.Equal(t, []string{"fs", "--format", "json", "--quiet", "/x/p.whl"}, scannertest.Args(t, argsFile))
}

func TestExtractRejectsUnsafeArchives(t *testing.T) {
	tests := []struct {
		name    string
		entries []entry
	}{
		{"parent traversal", []entry{{name: "package/../../evil", body: "x"}}},
		{"leading traversal", []entry{{name: "../evil", body: "x"}}},
		{"absolute path", []entry{{name: "/etc/evil", body: "x"}}},
		{"symlink to absolute", []entry{{name: "package/l", typeflag: tar.TypeSymlink, link: "/etc/passwd"}}},
		{"symlink out of tree", []entry{{name: "package/l", typeflag: tar.TypeSymlink, link: "../../x"}}},
		{"hardlink out of tree", []entry{{name: "package/l", typeflag: tar.TypeLink, link: "../x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := unpackNPM(tgz(t, tt.entries...), "pkg")
			require.Error(t, err)
			assert.Empty(t, root)
		})
	}
}

func TestExtractSkipsInTreeLinksWithoutCreatingThem(t *testing.T) {
	root, err := unpackNPM(tgz(t,
		entry{name: "package/real.js", body: "x"},
		entry{name: "package/l", typeflag: tar.TypeSymlink, link: "real.js"},
	), "pkg")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(root) }()
	_, err = os.Lstat(filepath.Join(root, "node_modules", "pkg", "l"))
	assert.True(t, os.IsNotExist(err))
	assert.FileExists(t, filepath.Join(root, "node_modules", "pkg", "real.js"))
}

func TestUnpackRejectsUnsafePackageNames(t *testing.T) {
	archive := tgz(t, entry{name: "package/package.json", body: "{}"})
	for _, name := range []string{"", "..", "../x", "/abs", "a/../../b", `a\b`} {
		_, err := unpackNPM(archive, name)
		assert.Error(t, err, name)
	}
}

func TestExtractEnforcesSizeCap(t *testing.T) {
	dest := t.TempDir()
	_, err := writeEntry(filepath.Join(dest, "big"), strings.NewReader(strings.Repeat("a", 11)), 10)
	require.ErrorIs(t, err, errTooLarge)
	n, err := writeEntry(filepath.Join(dest, "ok"), strings.NewReader(strings.Repeat("a", 10)), 10)
	require.NoError(t, err)
	assert.EqualValues(t, 10, n)
}
