package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
)

// security.scan_wait_timeout bounds how long a first download waits for its scan; with
// fail_closed a slow scan is refused at that bound instead of the 30s default.
func TestScanWaitTimeoutComesFromConfig(t *testing.T) {
	release := make(chan struct{})
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer osv.Close()
	defer close(release)

	a := newTestApp(t, func(c *config.Config) {
		c.Security.Enabled = true
		c.Security.FailClosed = true
		c.Security.ScanWaitTimeout = 150 * time.Millisecond
		c.Security.Scanners.OSV.Enabled = true
		c.Security.Scanners.OSV.APIURL = osv.URL
	})

	fetch := func(context.Context) (*cache.FetchResult, error) {
		return &cache.FetchResult{Data: io.NopCloser(strings.NewReader("tarball"))}, nil
	}
	start := time.Now()
	_, err := a.cache.Get(context.Background(), "npm", "left-pad", "1.3.0", fetch)
	elapsed := time.Since(start)

	var ghErr *errors.Error
	if err == nil || !asError(err, &ghErr) || ghErr.Code != errors.ErrCodeServiceUnavailable {
		t.Fatalf("Get = %v, want a service-unavailable refusal", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("refusal took %s; the configured 150ms wait was not applied", elapsed)
	}
}

func asError(err error, target **errors.Error) bool {
	e, ok := err.(*errors.Error)
	if ok {
		*target = e
	}
	return ok
}
