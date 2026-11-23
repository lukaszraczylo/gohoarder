package gormstore

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// openFileStore opens a store the way the app does for the sqlite backend.
func openFileStore(t *testing.T, walMode bool) *GORMStoreV2 {
	t.Helper()
	store, err := NewV2(Config{
		Driver:   "sqlite",
		DSN:      BuildSQLiteDSN(filepath.Join(t.TempDir(), "meta.db"), walMode),
		LogLevel: "silent",
	})
	if err != nil {
		t.Fatalf("NewV2: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestBuildSQLiteDSN_Pragmas(t *testing.T) {
	for _, walMode := range []bool{true, false} {
		dsn := BuildSQLiteDSN("x.db", walMode)
		wants := []string{"_busy_timeout=", "_txlock=immediate"}
		if walMode {
			wants = append(wants, "_journal_mode=WAL")
		}
		for _, want := range wants {
			if !strings.Contains(dsn, want) {
				t.Errorf("BuildSQLiteDSN(wal=%v) = %q, missing %q", walMode, dsn, want)
			}
		}
	}
}

// Concurrent readers and writers must not surface "database is locked".
func TestSQLite_ConcurrentWritesDoNotLock(t *testing.T) {
	store := openFileStore(t, true)
	ctx := context.Background()

	const packages = 8
	for i := 0; i < packages; i++ {
		now := time.Now()
		if err := store.SavePackage(ctx, &metadata.Package{
			Registry: "npm", Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0",
			StorageKey: fmt.Sprintf("npm/pkg-%d/1.0.0", i), CachedAt: now, LastAccessed: now,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	const workers, iterations = 32, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations*2)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := fmt.Sprintf("pkg-%d", (w+i)%packages)
				if err := store.UpdateDownloadCount(ctx, "npm", name, "1.0.0"); err != nil {
					errs <- fmt.Errorf("UpdateDownloadCount: %w", err)
				}
				now := time.Now()
				if err := store.SavePackage(ctx, &metadata.Package{
					Registry: "npm", Name: name, Version: "1.0.0",
					StorageKey: "npm/" + name + "/1.0.0", CachedAt: now, LastAccessed: now,
				}); err != nil {
					errs <- fmt.Errorf("SavePackage: %w", err)
				}
				if _, err := store.GetPackage(ctx, "npm", name, "1.0.0"); err != nil {
					errs <- fmt.Errorf("GetPackage: %w", err)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	failures := 0
	for err := range errs {
		failures++
		if failures <= 5 {
			t.Errorf("%v", err)
		}
	}
	if failures > 0 {
		t.Fatalf("%d operations failed under concurrency", failures)
	}
}
