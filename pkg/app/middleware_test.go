package app

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/stretchr/testify/require"
)

// mwTestSetup builds a fiber app wired with the given middleware on /protected.
// The handler echoes the resolved auth_key locals so tests can assert that
// downstream handlers see them. Returns the app plus a freshly issued raw key
// for the supplied role.
func mwTestSetup(t *testing.T, role auth.Role, mw fiber.Handler) (*fiber.App, *auth.Manager, string, *auth.APIKey) {
	t.Helper()
	mgr := auth.New()
	apiKey, raw, err := mgr.GenerateAPIKey("test-"+string(role), role, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", mw)
	app.Get("/protected", func(c *fiber.Ctx) error {
		got, _ := c.Locals(LocalAuthKey).(*auth.APIKey)
		gotRole, _ := c.Locals(LocalAuthRole).(string)
		body := fiber.Map{"ok": true, "have_key": got != nil}
		if got != nil {
			body["key_id"] = got.ID
			body["role"] = gotRole
		}
		return c.Status(fiber.StatusOK).JSON(body)
	})
	return app, mgr, raw, apiKey
}

func decodeErrorBody(t *testing.T, body io.Reader) errors.Error {
	t.Helper()
	var e errors.Error
	require.NoError(t, json.NewDecoder(body).Decode(&e))
	return e
}

func TestRequireAuth_NoHeader_Returns401(t *testing.T) {
	app, _, _, _ := mwTestSetup(t, auth.RoleReadOnly, RequireAuth(auth.New()))
	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	body := decodeErrorBody(t, resp.Body)
	require.Equal(t, errors.ErrCodeUnauthorized, body.Code)
}

func TestRequireAuth_BadKey_Returns401(t *testing.T) {
	mgr := auth.New()
	_, _, err := mgr.GenerateAPIKey("real", auth.RoleReadOnly, nil)
	require.NoError(t, err)

	app, _, _, _ := mwTestSetup(t, auth.RoleReadOnly, RequireAuth(mgr))
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-key")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	body := decodeErrorBody(t, resp.Body)
	require.Equal(t, errors.ErrCodeInvalidAPIKey, body.Code)
}

func TestRequireAuth_BadHeaderShape_Returns401(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
	}{
		{"non-bearer scheme", "Authorization", "Basic abcdef"},
		{"bearer no token", "Authorization", "Bearer "},
		{"empty x-api-key", "X-API-Key", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mgr := auth.New()
			app := fiber.New(fiber.Config{DisableStartupMessage: true})
			app.Use("/protected", RequireAuth(mgr))
			app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })
			req := httptest.NewRequest("GET", "/protected", nil)
			if tc.value != "" {
				req.Header.Set(tc.header, tc.value)
			}
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		})
	}
}

func TestRequireAuth_ValidBearer_Returns200_AndPopulatesLocals(t *testing.T) {
	mgr := auth.New()
	apiKey, raw, err := mgr.GenerateAPIKey("good", auth.RoleReadWrite, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequireAuth(mgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		k, _ := c.Locals(LocalAuthKey).(*auth.APIKey)
		require.NotNil(t, k)
		require.Equal(t, apiKey.ID, k.ID)
		require.Equal(t, string(auth.RoleReadWrite), c.Locals(LocalAuthRole))
		return c.Status(200).JSON(fiber.Map{"key_id": k.ID})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, apiKey.ID, body["key_id"])
}

func TestRequireAuth_ValidXAPIKey_Returns200(t *testing.T) {
	mgr := auth.New()
	_, raw, err := mgr.GenerateAPIKey("good", auth.RoleReadOnly, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequireAuth(mgr))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("X-API-Key", raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}

func TestRequireAuth_ExpiredKey_Returns401(t *testing.T) {
	mgr := auth.New()
	d := -1 * time.Hour
	_, raw, err := mgr.GenerateAPIKey("expired", auth.RoleReadOnly, &d)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequireAuth(mgr))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestRequireRole_Match_Returns200(t *testing.T) {
	mgr := auth.New()
	_, raw, err := mgr.GenerateAPIKey("admin", auth.RoleAdmin, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequireRole(mgr, string(auth.RoleAdmin), string(auth.RoleReadWrite)))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}

func TestRequireRole_Mismatch_Returns403(t *testing.T) {
	mgr := auth.New()
	_, raw, err := mgr.GenerateAPIKey("ro", auth.RoleReadOnly, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequireRole(mgr, string(auth.RoleAdmin)))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	body := decodeErrorBody(t, resp.Body)
	require.Equal(t, errors.ErrCodeForbidden, body.Code)
}

func TestRequireRole_NoHeader_Returns401(t *testing.T) {
	mgr := auth.New()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequireRole(mgr, string(auth.RoleAdmin)))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}

func TestRequirePermission_Match_Returns200(t *testing.T) {
	mgr := auth.New()
	_, raw, err := mgr.GenerateAPIKey("rw", auth.RoleReadWrite, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequirePermission(mgr, string(auth.PermissionWritePackage)))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}

func TestRequirePermission_Mismatch_Returns403(t *testing.T) {
	mgr := auth.New()
	_, raw, err := mgr.GenerateAPIKey("ro", auth.RoleReadOnly, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", RequirePermission(mgr, string(auth.PermissionDeletePackage)))
	app.Get("/protected", func(c *fiber.Ctx) error { return c.SendStatus(200) })

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}

func TestOptionalAuth_NoHeader_Continues(t *testing.T) {
	mgr := auth.New()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", OptionalAuth(mgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		require.Nil(t, c.Locals(LocalAuthKey))
		return c.SendStatus(200)
	})
	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}

func TestOptionalAuth_BadKey_ContinuesAnonymously(t *testing.T) {
	mgr := auth.New()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", OptionalAuth(mgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		// Bad key should NOT populate locals.
		require.Nil(t, c.Locals(LocalAuthKey))
		return c.SendStatus(200)
	})
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-real")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}

func TestOptionalAuth_GoodKey_PopulatesLocals(t *testing.T) {
	mgr := auth.New()
	apiKey, raw, err := mgr.GenerateAPIKey("good", auth.RoleAdmin, nil)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use("/protected", OptionalAuth(mgr))
	app.Get("/protected", func(c *fiber.Ctx) error {
		k, _ := c.Locals(LocalAuthKey).(*auth.APIKey)
		require.NotNil(t, k)
		require.Equal(t, apiKey.ID, k.ID)
		return c.SendStatus(200)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
}
