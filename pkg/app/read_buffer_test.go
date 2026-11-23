package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

const recentPackagesURL = "/api/packages?page=1&page_size=10&sort=cached_at&order=desc"

// Fiber v3 defaults to an 8192-byte read buffer; OIDC session cookies plus a long Referer exceed it.
func TestLargeRequestHeadersAreAccepted(t *testing.T) {
	a := newTestApp(t, nil)
	headers := map[string]string{
		"Cookie":  "session=" + strings.Repeat("a", 5000),
		"Referer": "https://dash.example.com/" + strings.Repeat("r", 5000),
	}
	code, _, body := doRequest(t, a, recentPackagesURL, headers)
	if code != http.StatusOK {
		t.Fatalf("GET with ~10KB of headers = %d %q, want 200", code, body)
	}
}

func TestReadBufferSizeIsConfigurable(t *testing.T) {
	if got := config.Default().Server.ReadBufferSize; got != 16384 {
		t.Fatalf("default server.read_buffer_size = %d, want 16384", got)
	}
	a := newTestApp(t, func(c *config.Config) { c.Server.ReadBufferSize = 4096 })
	req := httptest.NewRequest(http.MethodGet, recentPackagesURL, nil)
	req.Header.Set("Cookie", "session="+strings.Repeat("a", 6000))
	if _, err := a.app.Test(req); err == nil || !strings.Contains(err.Error(), "small read buffer") {
		t.Errorf("6KB header with a 4096 buffer: err = %v, want a small-read-buffer rejection", err)
	}
}
