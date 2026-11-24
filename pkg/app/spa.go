package app

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

// A page load sends Accept: text/html; a missing asset does not, and version segments such as v1.0.0 have dots.
// Paths that belong to the server; an unknown one stays a 404 instead of the SPA shell.
var nonSPAPrefixes = []string{"/api/", "/go/", "/npm/", "/pypi/", "/ws"}

// spaStatic serves dir and falls back to index.html for client-side routes, so reload and shared links work.
func spaStatic(dir string) fiber.Handler {
	return static.New(dir, static.Config{
		NotFoundHandler: func(c fiber.Ctx) error {
			p := c.Path()
			if (c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead) || !strings.Contains(c.Get(fiber.HeaderAccept), "text/html") {
				return fiber.ErrNotFound
			}
			for _, prefix := range nonSPAPrefixes {
				if strings.HasPrefix(p, prefix) {
					return fiber.ErrNotFound
				}
			}
			index, err := os.ReadFile(filepath.Join(dir, "index.html")) // #nosec G304 -- fixed file under the configured frontend dir
			if err != nil {
				return fiber.ErrNotFound
			}
			c.Status(fiber.StatusOK).Type("html")
			return c.Send(index)
		},
	})
}
