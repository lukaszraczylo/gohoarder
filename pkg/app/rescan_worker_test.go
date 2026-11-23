package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// A cached artifact whose scan never completed (lost to a restart) is scanned once the
// workers start, when security.rescan_interval is set.
func TestWorkersStartTheRescanWorker(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer osv.Close()

	a := newTestApp(t, func(c *config.Config) {
		c.Security.Enabled = true
		c.Security.RescanInterval = time.Hour
		c.Security.Scanners.OSV.Enabled = true
		c.Security.Scanners.OSV.APIURL = osv.URL
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const key = "npm/left-pad/1.3.0"
	if err := a.storage.Put(ctx, key, strings.NewReader("tarball"), nil); err != nil {
		t.Fatalf("storage.Put: %v", err)
	}
	now := time.Now()
	err := a.metadata.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.3.0", StorageKey: key,
		Size: 7, CachedAt: now, LastAccessed: now,
	})
	if err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	a.startWorkers(ctx)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := a.metadata.GetScanResult(ctx, "npm", "left-pad", "1.3.0"); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no scan result after the workers started; the rescan worker never ran")
}
