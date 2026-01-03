package app

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

// handlePrewarmingStatus returns the status of the pre-warming worker
func (a *App) handlePrewarmingStatus(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	status := a.prewarmWorker.GetStatus()

	return c.Status(fiber.StatusOK).JSON(status)
}

// handlePrewarmingTrigger manually triggers a pre-warming cycle
func (a *App) handlePrewarmingTrigger(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	ctx := c.Context()
	a.prewarmWorker.TriggerPrewarm(ctx)

	log.Info().Msg("Pre-warming manually triggered via API")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Pre-warming cycle triggered successfully",
	})
}

// PrewarmPackageRequest represents a request to pre-warm a specific package
type PrewarmPackageRequest struct {
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Version  string `json:"version"`
}

// handlePrewarmingPackage pre-warms a specific package
func (a *App) handlePrewarmingPackage(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	var req PrewarmPackageRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid JSON in request body",
		})
	}

	// Validate request
	if req.Registry == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "registry is required",
		})
	}
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name is required",
		})
	}
	if req.Version == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "version is required",
		})
	}

	ctx := c.Context()
	err := a.prewarmWorker.PrewarmPackage(ctx, req.Registry, req.Name, req.Version)
	if err != nil {
		log.Error().
			Err(err).
			Str("registry", req.Registry).
			Str("name", req.Name).
			Str("version", req.Version).
			Msg("Failed to pre-warm package")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to pre-warm package",
		})
	}

	log.Info().
		Str("registry", req.Registry).
		Str("name", req.Name).
		Str("version", req.Version).
		Msg("Package pre-warmed via API")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Package pre-warmed successfully",
		"package": fiber.Map{
			"registry": req.Registry,
			"name":     req.Name,
			"version":  req.Version,
		},
	})
}
