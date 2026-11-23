package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

func doDelete(t *testing.T, a *App, target string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	resp, err := a.app.Test(req, fiber.TestConfig{Timeout: 40 * time.Second})
	if err != nil {
		t.Fatalf("DELETE %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestDeleteMissingPackageIs404(t *testing.T) {
	a := newTestApp(t, nil)
	for _, target := range []string{
		"/api/packages/npm/nope/1.0.0",
		"/api/packages/pypi/nope/1.0.0",
		"/api/packages/go/example.com/nope/v1.0.0",
	} {
		code, body := doDelete(t, a, target)
		if code != http.StatusNotFound {
			t.Errorf("DELETE %s = %d %s, want 404", target, code, body)
		}
		var out map[string]string
		if err := json.Unmarshal([]byte(body), &out); err != nil || out["error"] == "" {
			t.Errorf("DELETE %s body %q is not a JSON error", target, body)
		}
	}
}

func TestDeleteExistingPackageIs200(t *testing.T) {
	a := newTestApp(t, nil)
	ctx := context.Background()
	err := a.metadata.SavePackage(ctx, &metadata.Package{
		Registry: "npm", Name: "left-pad", Version: "1.0.0", StorageKey: "npm/left-pad/1.0.0",
		Size: 10, CachedAt: time.Now(), LastAccessed: time.Now(),
	})
	if err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	code, body := doDelete(t, a, "/api/packages/npm/left-pad/1.0.0")
	if code != http.StatusOK || !strings.Contains(body, `"deleted":true`) {
		t.Fatalf("DELETE existing = %d %s, want 200 deleted", code, body)
	}
	if code, body := doDelete(t, a, "/api/packages/npm/left-pad/1.0.0"); code != http.StatusNotFound {
		t.Errorf("second DELETE = %d %s, want 404", code, body)
	}
}
