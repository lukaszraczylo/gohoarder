package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
)

// The env-bootstrapped admin key must work on the boot that creates it, not only after a restart.
func TestBootstrapAdminKeyWorksOnFirstBoot(t *testing.T) {
	const key = "bootstrap-admin-key-for-test"
	t.Setenv(auth.BootstrapAdminEnvVar, key)
	a := newTestApp(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/prewarming/status", nil)
	req.Header.Set("X-API-Key", key)
	resp, err := a.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin route with the bootstrap key = %d, want 200", resp.StatusCode)
	}
}
