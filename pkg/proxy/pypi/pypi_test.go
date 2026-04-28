package pypi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/auth"
)

func TestIsAllowedPyPIHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		allowed []string
		want    bool
	}{
		{"pypi.org allowed", "pypi.org", defaultAllowedPyPIHosts, true},
		{"files.pythonhosted.org allowed", "files.pythonhosted.org", defaultAllowedPyPIHosts, true},
		{"subdomain of pythonhosted.org allowed", "cdn.pythonhosted.org", defaultAllowedPyPIHosts, true},
		{"case insensitive", "PyPI.ORG", defaultAllowedPyPIHosts, true},
		{"with port", "pypi.org:443", defaultAllowedPyPIHosts, true},
		{"AWS metadata blocked", "169.254.169.254", defaultAllowedPyPIHosts, false},
		{"GCP metadata blocked", "metadata.google.internal", defaultAllowedPyPIHosts, false},
		{"localhost blocked", "localhost", defaultAllowedPyPIHosts, false},
		{"loopback blocked", "127.0.0.1", defaultAllowedPyPIHosts, false},
		{"private RFC1918 blocked", "10.0.0.1", defaultAllowedPyPIHosts, false},
		{"attacker domain blocked", "evil.example.com", defaultAllowedPyPIHosts, false},
		{"empty host blocked", "", defaultAllowedPyPIHosts, false},
		{"trailing-substring attack blocked", "evilpythonhosted.org", defaultAllowedPyPIHosts, false},
		{"prefix attack blocked", "pypi.org.evil.com", defaultAllowedPyPIHosts, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllowedPyPIHost(tt.host, tt.allowed)
			if got != tt.want {
				t.Errorf("isAllowedPyPIHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// newHandlerForSSRFTest builds a Handler with only the fields needed to reach
// the SSRF guard. cache is nil intentionally — the guard rejects before any
// cache call.
func newHandlerForSSRFTest() *Handler {
	return &Handler{
		credExtractor: auth.NewCredentialExtractor(),
		credHasher:    auth.NewCredentialHasher(),
		upstream:      "https://pypi.org/simple",
		allowedHosts:  defaultAllowedPyPIHosts,
	}
}

func TestHandlePackageFile_SSRFRejected(t *testing.T) {
	tests := []struct {
		name        string
		originalURL string
	}{
		{"AWS metadata IP", "http://169.254.169.254/"},
		{"GCP metadata host", "http://metadata.google.internal/computeMetadata/v1/"},
		{"localhost", "http://localhost:8080/secret"},
		{"private network", "http://10.0.0.5/"},
		{"file scheme", "file:///etc/passwd"},
		{"gopher scheme", "gopher://internal/"},
		{"unrelated public host", "https://evil.example.com/payload.whl"},
	}

	h := newHandlerForSSRFTest()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/example/example-1.0.0.whl"
			q := url.Values{}
			q.Set("original_url", tt.originalURL)
			req := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
			w := httptest.NewRecorder()

			h.handlePackageFile(req.Context(), w, req, path)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for SSRF target %q, got %d (body=%q)", tt.originalURL, w.Code, w.Body.String())
			}
		})
	}
}

func TestHandlePackageFile_AllowedHostNotRejected(t *testing.T) {
	// Sanity check: an allowlisted host should NOT be rejected at the SSRF
	// guard. We don't have a real cache so the call will fail later with a
	// non-400 status — that's fine, we only assert the SSRF guard didn't
	// fire.
	h := newHandlerForSSRFTest()

	path := "/example/example-1.0.0.whl"
	q := url.Values{}
	q.Set("original_url", "https://files.pythonhosted.org/packages/abc/example-1.0.0.whl")
	req := httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	defer func() {
		// nil cache will panic when reached — recover and treat as "guard
		// did not block", which is the property we care about.
		_ = recover()
	}()

	h.handlePackageFile(req.Context(), w, req, path)

	if w.Code == http.StatusBadRequest {
		t.Errorf("allowlisted host wrongly rejected with 400: %s", w.Body.String())
	}
}

func TestRewritePackagePageURLs_QueryEscape(t *testing.T) {
	// Original URL contains characters that strings.ReplaceAll(&,=) would miss:
	// '?', '#', '+'. Verify url.QueryEscape handles them.
	html := `<a href="https://files.pythonhosted.org/packages/x/y+z/foo-1.0.whl?token=abc#frag">link</a>`
	out := rewritePackagePageURLs(html, "foo", "http://proxy/pypi")

	// '+' must be encoded (otherwise PyPI would interpret as space)
	if !contains(out, "original_url=https%3A%2F%2Ffiles.pythonhosted.org%2Fpackages%2Fx%2Fy%2Bz%2Ffoo-1.0.whl%3Ftoken%3Dabc%23frag") {
		t.Errorf("expected fully URL-encoded original_url, got: %s", out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
