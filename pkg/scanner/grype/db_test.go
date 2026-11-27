package grype

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanDisablesDatabaseAutoUpdate(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "env")
	fix, err := filepath.Abs(fixture("purl-minimist-0.0.8.json"))
	require.NoError(t, err)
	scannertest.Script(t, "grype", "printf '%s' \"$GRYPE_DB_AUTO_UPDATE\" > '"+envFile+"'\ncat '"+fix+"'")

	_, err = New(config.GrypeConfig{}).Scan(context.Background(), "npm", "minimist", "0.0.8", "/tmp/artifact")

	require.NoError(t, err)
	got, err := os.ReadFile(envFile) // #nosec G304 -- test temp file
	require.NoError(t, err)
	assert.Equal(t, "false", string(got), "a scan must never download the database itself")
}

func mkdirAged(t *testing.T, path string, age time.Duration) {
	t.Helper()
	require.NoError(t, os.MkdirAll(path, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(path, "archive"), []byte("x"), 0o600))
	when := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(path, when, when))
}

func TestUpdateDatabaseRemovesAbandonedDownloads(t *testing.T) {
	cacheDir, tmpDir := t.TempDir(), t.TempDir()
	t.Setenv("GRYPE_DB_CACHE_DIR", cacheDir)
	t.Setenv("TMPDIR", tmpDir)
	scannertest.Fake(t, "grype", "", "", 0)

	mkdirAged(t, filepath.Join(cacheDir, "grype-db-download111"), 2*time.Hour)
	mkdirAged(t, filepath.Join(cacheDir, "grype-db-download222"), time.Minute)
	mkdirAged(t, filepath.Join(cacheDir, "6"), 48*time.Hour)
	mkdirAged(t, filepath.Join(tmpDir, "getter333"), 2*time.Hour)
	mkdirAged(t, filepath.Join(tmpDir, "getter444"), time.Minute)
	mkdirAged(t, filepath.Join(tmpDir, "npm-audit-555"), 2*time.Hour)

	require.NoError(t, New(config.GrypeConfig{}).UpdateDatabase(context.Background()))

	assert.NoDirExists(t, filepath.Join(cacheDir, "grype-db-download111"))
	assert.NoDirExists(t, filepath.Join(tmpDir, "getter333"))
	assert.DirExists(t, filepath.Join(cacheDir, "grype-db-download222"), "a download in progress stays")
	assert.DirExists(t, filepath.Join(tmpDir, "getter444"), "a download in progress stays")
	assert.DirExists(t, filepath.Join(cacheDir, "6"), "the live database stays")
	assert.DirExists(t, filepath.Join(tmpDir, "npm-audit-555"), "other tools' temp dirs stay")
}

func TestUpdateDatabaseNeverOverlaps(t *testing.T) {
	dir := t.TempDir()
	lock, overlap := filepath.Join(dir, "lock"), filepath.Join(dir, "overlap")
	scannertest.Script(t, "grype",
		"mkdir '"+lock+"' 2>/dev/null || echo x >> '"+overlap+"'\nsleep 0.2\nrmdir '"+lock+"' 2>/dev/null\nexit 0")
	s := New(config.GrypeConfig{})

	done := make(chan error, 4)
	for range 4 {
		go func() { done <- s.UpdateDatabase(context.Background()) }()
	}
	for range 4 {
		require.NoError(t, <-done)
	}

	assert.NoFileExists(t, overlap, "two database downloads ran at once")
}

func TestUpdateDatabaseOutlivesCallerCancel(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "finished")
	scannertest.Script(t, "grype", "sleep 0.3\ntouch '"+marker+"'")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_ = New(config.GrypeConfig{}).UpdateDatabase(ctx)

	assert.FileExists(t, marker, "a cancelled caller must not kill the download half way")
}

func TestRefreshDatabaseRunsOnInterval(t *testing.T) {
	calls := filepath.Join(t.TempDir(), "calls")
	scannertest.Script(t, "grype", "echo \"$1 $2\" >> '"+calls+"'")
	stop := make(chan struct{})
	exited := make(chan struct{})

	go func() {
		New(config.GrypeConfig{}).RefreshDatabase(stop, 20*time.Millisecond, true)
		close(exited)
	}()

	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(calls) // #nosec G304 -- test temp file
		return strings.Count(string(data), "db update\n") >= 3
	}, 5*time.Second, 10*time.Millisecond)
	close(stop)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop did not stop")
	}
}
