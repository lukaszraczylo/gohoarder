package pypi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/network"
)

// A PEP 658 sidecar fetched from an allowed host must not follow a redirect off the allowlist.
func TestSidecarRedirectOffAllowlistRefused(t *testing.T) {
	var hit atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte("internal-secret"))
	}))
	defer internal.Close()
	allowed := httptest.NewServer(http.RedirectHandler(strings.Replace(internal.URL, "127.0.0.1", "localhost", 1)+"/example-1.0.0-py3-none-any.whl.metadata", http.StatusFound))
	defer allowed.Close()

	client := network.NewClient(network.Config{Timeout: 5 * time.Second, MaxRetries: 1, AllowPrivateRedirects: true})
	h := &Handler{client: client, allowedHosts: []string{"127.0.0.1"}}

	const path = "/example/example-1.0.0-py3-none-any.whl.metadata"
	q := url.Values{"original_url": {allowed.URL + "/files/example-1.0.0-py3-none-any.whl"}}
	req := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.handlePackageFile(req.Context(), w, req, path)

	if w.Code != http.StatusBadGateway {
		t.Errorf("code=%d want 502 body=%q", w.Code, w.Body.String())
	}
	if hit.Load() != 0 || strings.Contains(w.Body.String(), "internal-secret") {
		t.Errorf("redirect target was fetched (hits=%d)", hit.Load())
	}
}

// pip requests the PEP 658 sidecar as <link>.metadata, which puts the suffix on original_url.
// It must be streamed as a sidecar, never cached as the wheel.
func TestPipSidecarFormIsStreamed(t *testing.T) {
	const meta = "Metadata-Version: 2.1\nName: example\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/example-1.0.0-py3-none-any.whl.metadata") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(meta))
	}))
	defer upstream.Close()

	client := network.NewClient(network.Config{Timeout: 5 * time.Second, MaxRetries: 1, AllowPrivateRedirects: true})
	// No cache: touching it would panic, so a 200 proves the request never reached the wheel path.
	h := &Handler{client: client, allowedHosts: []string{"127.0.0.1"}}

	const path = "/example/example-1.0.0-py3-none-any.whl"
	q := url.Values{"original_url": {upstream.URL + "/files/example-1.0.0-py3-none-any.whl.metadata"}}
	req := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.handlePackageFile(req.Context(), w, req, path)

	if w.Code != http.StatusOK || w.Body.String() != meta {
		t.Errorf("code=%d body=%q, want 200 with the metadata", w.Code, w.Body.String())
	}
}
