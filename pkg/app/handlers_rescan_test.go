package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

func rescanApp(t *testing.T) (*App, *fiber.App) {
	t.Helper()
	a := newTestApp(t, func(c *config.Config) {
		c.Security.Enabled = true
		c.Security.UpdateDBOnStartup = false
		c.Security.RescanInterval = 0
		disableAllScanners(c)
	})
	f := fiber.New()
	f.Post("/api/admin/rescan", a.handleRescanTrigger)
	f.Get("/api/admin/rescan/status", a.handleRescanStatus)
	return a, f
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func postRescan(t *testing.T, f *fiber.App, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/rescan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, decodeBody(t, resp)
}

func rescanStatus(t *testing.T, f *fiber.App) map[string]any {
	t.Helper()
	resp, err := f.Test(httptest.NewRequest(http.MethodGet, "/api/admin/rescan/status", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return decodeBody(t, resp)
}

func saveRescanPackage(t *testing.T, a *App, name, version string) {
	t.Helper()
	now := time.Now()
	require.NoError(t, a.metadata.SavePackage(context.Background(), &metadata.Package{
		Registry: "npm", Name: name, Version: version, StorageKey: "npm/" + name + "/" + version, Size: 1, CachedAt: now, LastAccessed: now,
	}))
}

func TestRescanTriggerQueuesAndReportsProgress(t *testing.T) {
	a, f := rescanApp(t)
	saveRescanPackage(t, a, "left-pad", "1.3.0")
	saveRescanPackage(t, a, "left-pad", "metadata")

	code, body := postRescan(t, f, `{"scope":"all"}`)
	require.Equal(t, http.StatusAccepted, code)
	require.EqualValues(t, 1, body["queued"], "the metadata row is not queued")
	require.Equal(t, "all", body["scope"])

	require.Eventually(t, func() bool { return rescanStatus(t, f)["running"] == false }, 5*time.Second, 10*time.Millisecond)
	st := rescanStatus(t, f)
	require.EqualValues(t, 1, st["queued"])
	require.EqualValues(t, 1, st["done"].(float64)+st["failed"].(float64), "the one artifact is processed")
	require.NotEmpty(t, st["finished_at"])
}

func TestRescanTriggerRefusesASecondRunWhileActive(t *testing.T) {
	a, f := rescanApp(t)
	saveRescanPackage(t, a, "left-pad", "1.3.0")
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	a.scanManager.SetFileSource(func(context.Context, string, string, string) (string, func(), error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return "", func() {}, context.Canceled
	})

	code, _ := postRescan(t, f, `{"scope":"all"}`)
	require.Equal(t, http.StatusAccepted, code)
	<-entered
	require.Equal(t, true, rescanStatus(t, f)["running"])

	code, body := postRescan(t, f, `{"scope":"vulnerable"}`)
	require.Equal(t, http.StatusConflict, code)
	require.NotEmpty(t, body["error"])

	close(release)
	require.Eventually(t, func() bool { return rescanStatus(t, f)["running"] == false }, 5*time.Second, 10*time.Millisecond)
}

func TestRescanTriggerRejectsBadInput(t *testing.T) {
	_, f := rescanApp(t)
	for _, body := range []string{``, `{}`, `{"scope":"everything"}`, `not json`} {
		code, _ := postRescan(t, f, body)
		require.Equal(t, http.StatusBadRequest, code, body)
	}
}

func TestRescanTriggerNeedsScanningOn(t *testing.T) {
	a := newTestApp(t, func(c *config.Config) { c.Security.Enabled = false })
	f := fiber.New()
	f.Post("/api/admin/rescan", a.handleRescanTrigger)
	f.Get("/api/admin/rescan/status", a.handleRescanStatus)

	code, _ := postRescan(t, f, `{"scope":"all"}`)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, false, rescanStatus(t, f)["enabled"])
}

func TestRescanRoutesNeedAdmin(t *testing.T) {
	a, _ := rescanApp(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/admin/rescan"},
		{http.MethodGet, "/api/admin/rescan/status"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"scope":"all"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.app.Test(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, tc.path)
	}
}
