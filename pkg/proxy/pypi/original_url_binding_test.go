package pypi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The cache key is pypi/<name>/<filename>, so original_url must name that same file.
func TestHandlePackageFile_OriginalURLFilenameBound(t *testing.T) {
	const path = "/example/example-1.0.0-py3-none-any.whl"
	tests := []struct {
		name        string
		path        string
		originalURL string
		wantReject  bool
	}{
		{"other file on allowed host", path, "https://files.pythonhosted.org/packages/ab/cd/ef/evil-9.9.9-py3-none-any.whl", true},
		{"other project same version", path, "https://files.pythonhosted.org/packages/ab/cd/ef/other-1.0.0-py3-none-any.whl", true},
		{"sidecar of another file", path + ".metadata", "https://files.pythonhosted.org/packages/ab/cd/ef/evil-9.9.9-py3-none-any.whl", true},
		{"same file", path, "https://files.pythonhosted.org/packages/ab/cd/ef/example-1.0.0-py3-none-any.whl", false},
		{"same file with query", path, "https://files.pythonhosted.org/packages/ab/cd/ef/example-1.0.0-py3-none-any.whl?x=1", false},
		{"sidecar of same file", path + ".metadata", "https://files.pythonhosted.org/packages/ab/cd/ef/example-1.0.0-py3-none-any.whl", false},
	}

	h := newHandlerForSSRFTest()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{}
			q.Set("original_url", tt.originalURL)
			req := httptest.NewRequest(http.MethodGet, tt.path+"?"+q.Encode(), nil)
			w := httptest.NewRecorder()

			// A nil cache panics once the guards pass; that means "not rejected".
			func() {
				defer func() { _ = recover() }()
				h.handlePackageFile(req.Context(), w, req, tt.path)
			}()

			rejected := w.Code == http.StatusBadRequest
			if rejected != tt.wantReject {
				t.Errorf("rejected=%v want %v (code=%d body=%q)", rejected, tt.wantReject, w.Code, w.Body.String())
			}
		})
	}
}
