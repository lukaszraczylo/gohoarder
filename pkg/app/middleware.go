package app

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/rs/zerolog/log"
)

// Locals keys used by the auth middleware. Exported so other handlers in the
// app package (and the integrator) can fetch the resolved key/role without
// guessing at string literals.
const (
	LocalAuthKey  = "auth_key"
	LocalAuthRole = "auth_role"
)

// extractAPIKey pulls the raw API key from either the Authorization bearer
// header or the X-API-Key header. Returns ("", false) when neither is set or
// the Authorization header has the wrong shape.
func extractAPIKey(c *fiber.Ctx) (string, bool) {
	if h := strings.TrimSpace(c.Get("Authorization")); h != "" {
		// Expect: "Bearer <token>". Be tolerant of casing on the scheme.
		parts := strings.SplitN(h, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			token := strings.TrimSpace(parts[1])
			if token != "" {
				return token, true
			}
		}
	}
	if h := strings.TrimSpace(c.Get("X-API-Key")); h != "" {
		return h, true
	}
	return "", false
}

// writeAuthError sends a structured error response matching the project's
// errors envelope (errors.Error JSON shape). Uses the HTTPStatusCode map so
// callers don't need to remember which status maps to which code.
func writeAuthError(c *fiber.Ctx, code, message string) error {
	status, ok := errors.HTTPStatusCode[code]
	if !ok {
		status = fiber.StatusInternalServerError
	}
	return c.Status(status).JSON(errors.New(code, message))
}

// requestIDFromCtx returns the request ID set by an upstream middleware or
// the X-Request-ID header. Empty string when neither is available — callers
// should treat empty as "no correlation id".
func requestIDFromCtx(c *fiber.Ctx) string {
	if v := c.Locals("request_id"); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return c.Get("X-Request-ID")
}

// validateAndAttach is the shared core of all auth middlewares: pull the key,
// validate via the manager, and on success store it in Locals. Returns the
// resolved key plus a boolean indicating whether a key was present at all
// (false when no header). The error is non-nil only when validation failed
// (i.e. a key was present but invalid/expired).
func validateAndAttach(c *fiber.Ctx, authMgr *auth.Manager) (key *auth.APIKey, present bool, err error) {
	rawKey, ok := extractAPIKey(c)
	if !ok {
		return nil, false, nil
	}
	apiKey, err := authMgr.ValidateAPIKey(c.Context(), rawKey)
	if err != nil {
		return nil, true, err
	}
	c.Locals(LocalAuthKey, apiKey)
	c.Locals(LocalAuthRole, string(apiKey.Role))
	return apiKey, true, nil
}

// RequireAuth returns a fiber.Handler that rejects requests without a valid
// API key. On success the resolved *auth.APIKey is stored in c.Locals under
// LocalAuthKey.
func RequireAuth(authMgr *auth.Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key, present, err := validateAndAttach(c, authMgr)
		if !present {
			log.Debug().
				Str("path", c.Path()).
				Str("method", c.Method()).
				Str("request_id", requestIDFromCtx(c)).
				Msg("auth: missing API key")
			return writeAuthError(c, errors.ErrCodeUnauthorized, "missing API key; provide Authorization: Bearer <key> or X-API-Key header")
		}
		if err != nil {
			log.Warn().
				Err(err).
				Str("path", c.Path()).
				Str("method", c.Method()).
				Str("request_id", requestIDFromCtx(c)).
				Msg("auth: invalid API key")
			return writeAuthError(c, errors.ErrCodeInvalidAPIKey, "invalid or expired API key")
		}
		log.Debug().
			Str("key_id", key.ID).
			Str("role", string(key.Role)).
			Str("request_id", requestIDFromCtx(c)).
			Msg("auth: key validated")
		return c.Next()
	}
}

// RequireRole returns a fiber.Handler that authenticates the caller and then
// requires the resolved key's role to be present in the supplied list (any-of
// semantics). An empty roles list behaves like RequireAuth.
func RequireRole(authMgr *auth.Manager, roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key, present, err := validateAndAttach(c, authMgr)
		if !present {
			return writeAuthError(c, errors.ErrCodeUnauthorized, "missing API key; provide Authorization: Bearer <key> or X-API-Key header")
		}
		if err != nil {
			return writeAuthError(c, errors.ErrCodeInvalidAPIKey, "invalid or expired API key")
		}
		if len(roles) == 0 {
			return c.Next()
		}
		actual := string(key.Role)
		for _, r := range roles {
			if r == actual {
				return c.Next()
			}
		}
		log.Warn().
			Str("key_id", key.ID).
			Str("role", actual).
			Strs("required_roles", roles).
			Str("request_id", requestIDFromCtx(c)).
			Msg("auth: role mismatch")
		return writeAuthError(c, errors.ErrCodeForbidden, "insufficient role for this resource")
	}
}

// RequirePermission returns a fiber.Handler that authenticates the caller and
// then requires the resolved key to hold at least one of the supplied
// permissions. An empty perms list behaves like RequireAuth.
func RequirePermission(authMgr *auth.Manager, perms ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		key, present, err := validateAndAttach(c, authMgr)
		if !present {
			return writeAuthError(c, errors.ErrCodeUnauthorized, "missing API key; provide Authorization: Bearer <key> or X-API-Key header")
		}
		if err != nil {
			return writeAuthError(c, errors.ErrCodeInvalidAPIKey, "invalid or expired API key")
		}
		if len(perms) == 0 {
			return c.Next()
		}
		for _, p := range perms {
			if key.HasPermission(auth.Permission(p)) {
				return c.Next()
			}
		}
		log.Warn().
			Str("key_id", key.ID).
			Str("role", string(key.Role)).
			Strs("required_perms", perms).
			Str("request_id", requestIDFromCtx(c)).
			Msg("auth: permission denied")
		return writeAuthError(c, errors.ErrCodeForbidden, "insufficient permissions for this resource")
	}
}

// OptionalAuth returns a fiber.Handler that attempts to validate any provided
// API key but never rejects the request. Handy for endpoints whose behavior
// changes when the caller is authenticated (e.g. per-key rate limits) but
// which still serve anonymous traffic. Locals are populated on success.
func OptionalAuth(authMgr *auth.Manager) fiber.Handler {
	return func(c *fiber.Ctx) error {
		_, present, err := validateAndAttach(c, authMgr)
		if present && err != nil {
			// Key was provided but invalid — log for observability, continue
			// anonymously rather than 401-ing.
			log.Debug().
				Err(err).
				Str("path", c.Path()).
				Str("request_id", requestIDFromCtx(c)).
				Msg("auth: optional auth ignored invalid key")
		}
		return c.Next()
	}
}
