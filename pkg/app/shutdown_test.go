package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

func listTree(t *testing.T, dir string) string {
	t.Helper()
	var names []string
	err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(names, "\n")
}

// Shutdown must leave nothing running against the data directory: a late SQLite close deletes
// its -wal/-shm files after Shutdown returned and breaks the removal of the directory.
func TestShutdownLeavesDataDirectoryStable(t *testing.T) {
	for i := 0; i < 40; i++ {
		dir := t.TempDir()
		cfg := config.Default()
		cfg.Storage.Backend = "filesystem"
		cfg.Storage.Path = filepath.Join(dir, "store")
		cfg.Metadata.Backend = "sqlite"
		cfg.Metadata.SQLite.Path = filepath.Join(dir, "meta", "meta.db")
		if err := os.MkdirAll(filepath.Dir(cfg.Metadata.SQLite.Path), 0o750); err != nil {
			t.Fatal(err)
		}
		cfg.Security.Enabled = false
		cfg.Prewarming.Enabled = false
		cfg.Auth.Enabled = false
		a, err := New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		doRequest(t, a, "/api/stats", nil)
		if err := a.Shutdown(); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		before := listTree(t, dir)
		time.Sleep(20 * time.Millisecond)
		if after := listTree(t, dir); before != after {
			t.Fatalf("iteration %d: data directory changed after Shutdown:\nbefore:\n%s\nafter:\n%s", i, before, after)
		}
	}
}
