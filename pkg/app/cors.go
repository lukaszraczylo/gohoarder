package app

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
)

const (
	headerOrigin         = "Origin"
	corsAllowedMethods   = "GET, POST, PATCH, DELETE, OPTIONS"
	corsAllowedHeaders   = "Content-Type, Authorization, X-API-Key"
	corsPreflightMaxAge  = "600"
	headerACRMethod      = "Access-Control-Request-Method"
	headerACAllowOrigin  = "Access-Control-Allow-Origin"
	headerACAllowMethods = "Access-Control-Allow-Methods"
	headerACAllowHeaders = "Access-Control-Allow-Headers"
	headerACMaxAge       = "Access-Control-Max-Age"
)

// apiOriginGuard enforces server.allowed_origins on /api. A browser at another origin cannot
// read responses (no CORS grant) and cannot change state (403), whatever the handlers set.
// With nothing configured only the request's own host counts as same-origin.
// Requests with neither Origin nor Referer come from non-browser clients and pass.
func apiOriginGuard(allowed []string) fiber.Handler {
	check := buildCheckOrigin(allowed)
	originAllowed := func(c fiber.Ctx, origin string) bool {
		r := &http.Request{Header: http.Header{headerOrigin: {origin}}, Host: c.Host()}
		return check(r)
	}

	return func(c fiber.Ctx) error {
		origin := c.Get(headerOrigin)
		method := c.Method()

		if method == http.MethodOptions && origin != "" && c.Get(headerACRMethod) != "" {
			if !originAllowed(c, origin) {
				return c.SendStatus(fiber.StatusForbidden)
			}
			setCORSGrant(c, origin)
			c.Set(headerACMaxAge, corsPreflightMaxAge)
			return c.SendStatus(fiber.StatusNoContent)
		}

		if !isSafeMethod(method) {
			source := origin
			if source == "" {
				source = refererOrigin(c.Get(fiber.HeaderReferer))
			}
			if source != "" && !originAllowed(c, source) {
				log.Warn().Str("method", method).Str("path", c.Path()).Str("origin", source).Msg("Rejecting cross-origin state-changing request")
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "cross-origin request not allowed"})
			}
		}

		err := c.Next()

		// Drop any grant a handler or upstream set; the allowlist decides.
		c.Response().Header.Del(headerACAllowOrigin)
		c.Response().Header.Del(headerACAllowMethods)
		c.Response().Header.Del(headerACAllowHeaders)
		c.Vary(headerOrigin)
		if origin != "" && originAllowed(c, origin) {
			setCORSGrant(c, origin)
		}
		return err
	}
}

func setCORSGrant(c fiber.Ctx, origin string) {
	c.Set(headerACAllowOrigin, origin)
	c.Set(headerACAllowMethods, corsAllowedMethods)
	c.Set(headerACAllowHeaders, corsAllowedHeaders)
	c.Vary(headerOrigin)
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// refererOrigin returns scheme://host of a Referer, or "" when it is absent or malformed.
func refererOrigin(referer string) string {
	if strings.TrimSpace(referer) == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "null" // present but unusable: never matches the allowlist
	}
	return u.Scheme + "://" + u.Host
}
