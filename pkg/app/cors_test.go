package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const dashboardOrigin = "https://gohoarder.example.com"

func seedPackage(t *testing.T, a *App) {
	t.Helper()
	entry, err := a.cache.Get(context.Background(), "npm", "left-pad", "1.3.0", func(context.Context) (*cache.FetchResult, error) {
		return &cache.FetchResult{Data: io.NopCloser(strings.NewReader("tarball"))}, nil
	})
	require.NoError(t, err)
	_ = entry.Data.Close()
}

func apiCall(t *testing.T, a *App, method, target string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func corsApp(t *testing.T, origins ...string) *App {
	return newTestApp(t, func(c *config.Config) { c.Server.AllowedOrigins = origins })
}

const deletePath = "/api/packages/npm/left-pad/1.3.0"

func TestAPIDeleteFromDisallowedOriginForbidden(t *testing.T) {
	a := corsApp(t, dashboardOrigin)
	seedPackage(t, a)

	for _, h := range []map[string]string{
		{"Origin": "https://evil.example.net"},
		{"Origin": "null"},
		{"Referer": "https://evil.example.net/page"},
		{"Origin": "https://evil.example.net", "Referer": dashboardOrigin + "/x"},
	} {
		resp := apiCall(t, a, http.MethodDelete, deletePath, h)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "%v", h)
	}
	resp := apiCall(t, a, http.MethodGet, "/api/packages/npm", nil)
	assert.NotEqual(t, http.StatusForbidden, resp.StatusCode)
	_, err := a.metadata.GetPackage(context.Background(), "npm", "left-pad", "1.3.0")
	assert.NoError(t, err, "a refused request must not delete")
}

func TestAPIDeleteFromAllowedOriginWorks(t *testing.T) {
	for name, h := range map[string]map[string]string{
		"origin":   {"Origin": dashboardOrigin},
		"referer":  {"Referer": dashboardOrigin + "/packages"},
		"no-fetch": nil, // curl and server-to-server callers send neither header
	} {
		t.Run(name, func(t *testing.T) {
			a := corsApp(t, dashboardOrigin)
			seedPackage(t, a)
			resp := apiCall(t, a, http.MethodDelete, deletePath, h)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			_, err := a.metadata.GetPackage(context.Background(), "npm", "left-pad", "1.3.0")
			assert.Error(t, err, "package must be gone")
		})
	}
}

func TestAPIPostFromDisallowedOriginForbidden(t *testing.T) {
	a := corsApp(t, dashboardOrigin)
	resp := apiCall(t, a, http.MethodPost, "/api/admin/prewarming/trigger", map[string]string{"Origin": "https://evil.example.net"})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAPIGetStaysPublicWithoutWildcardCORS(t *testing.T) {
	a := corsApp(t, dashboardOrigin)

	resp := apiCall(t, a, http.MethodGet, "/api/stats", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))

	resp = apiCall(t, a, http.MethodGet, "/api/stats", map[string]string{"Origin": dashboardOrigin})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, dashboardOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Values("Vary"), "Origin")

	// Served, but a browser at a foreign origin cannot read it.
	resp = apiCall(t, a, http.MethodGet, "/api/stats", map[string]string{"Origin": "https://evil.example.net"})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestAPIPreflightAnswersOnlyAllowedOrigins(t *testing.T) {
	a := corsApp(t, dashboardOrigin)
	preflight := func(origin string) *http.Response {
		return apiCall(t, a, http.MethodOptions, deletePath, map[string]string{
			"Origin": origin, "Access-Control-Request-Method": "DELETE",
		})
	}

	ok := preflight(dashboardOrigin)
	assert.Equal(t, http.StatusNoContent, ok.StatusCode)
	assert.Equal(t, dashboardOrigin, ok.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, ok.Header.Get("Access-Control-Allow-Methods"), "DELETE")

	bad := preflight("https://evil.example.net")
	assert.Equal(t, http.StatusForbidden, bad.StatusCode)
	assert.Empty(t, bad.Header.Get("Access-Control-Allow-Origin"))
}

// With nothing configured, only the host the request was sent to counts as same-origin.
func TestAPISameOriginRuleWhenNoOriginsConfigured(t *testing.T) {
	a := corsApp(t)
	seedPackage(t, a)

	resp := apiCall(t, a, http.MethodDelete, deletePath, map[string]string{"Origin": "https://evil.example.net"})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp = apiCall(t, a, http.MethodDelete, deletePath, map[string]string{"Origin": "http://example.com"}) // httptest.NewRequest Host
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIOriginMatchingUsesAllowlistRules(t *testing.T) {
	a := corsApp(t, "https://*.example.org")
	resp := apiCall(t, a, http.MethodDelete, deletePath, map[string]string{"Origin": "https://ui.example.org"})
	assert.NotEqual(t, http.StatusForbidden, resp.StatusCode)
	resp = apiCall(t, a, http.MethodDelete, deletePath, map[string]string{"Origin": "https://example.org.evil.net"})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
