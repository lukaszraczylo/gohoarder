package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func spaApp(t *testing.T) *fiber.App {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>shell</html>"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.js"), []byte("js"), 0o600))
	app := fiber.New()
	app.Use("/", spaStatic(dir))
	return app
}

func TestSPAStaticFallback(t *testing.T) {
	app := spaApp(t)
	tests := []struct {
		name   string
		method string
		path   string
		want   int
		html   bool
	}{
		{"asset", http.MethodGet, "/app.js", http.StatusOK, false},
		{"client route", http.MethodGet, "/packages", http.StatusOK, true},
		{"deep client route", http.MethodGet, "/package/go/github.com/a/b/v1.0.0", http.StatusOK, true},
		{"unknown api path", http.MethodGet, "/api/nope", http.StatusNotFound, true},
		{"missing asset", http.MethodGet, "/missing.js", http.StatusNotFound, false},
		{"post is not a page", http.MethodPost, "/packages", http.StatusNotFound, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.html {
				req.Header.Set(fiber.HeaderAccept, "text/html,application/xhtml+xml")
			}
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}
