package app

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

// handleAnalyticsTopPackages returns the most downloaded packages
func (a *App) handleAnalyticsTopPackages(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	// Get limit from query params (default: 10)
	limit := 10
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	packages := a.analyticsEngine.GetTopPackages(limit)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"packages": packages,
		"total":    len(packages),
	})
}

// handleAnalyticsTrendingPackages returns trending packages
func (a *App) handleAnalyticsTrendingPackages(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	// Get limit from query params (default: 10)
	limit := 10
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	packages := a.analyticsEngine.GetTrendingPackages(limit)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"packages": packages,
		"total":    len(packages),
	})
}

// handleAnalyticsTrends returns download trends over time
func (a *App) handleAnalyticsTrends(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	trends := a.analyticsEngine.GetTrends()

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"trends": trends,
	})
}

// handleAnalyticsTotalStats returns overall statistics
func (a *App) handleAnalyticsTotalStats(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	stats := a.analyticsEngine.GetTotalStats()

	return c.Status(fiber.StatusOK).JSON(stats)
}

// handleAnalyticsRegistryStats returns per-registry statistics
func (a *App) handleAnalyticsRegistryStats(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	registry := c.Params("registry")
	if registry == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "registry parameter is required",
		})
	}

	stats := a.analyticsEngine.GetRegistryStats(registry)

	return c.Status(fiber.StatusOK).JSON(stats)
}

// handleAnalyticsPackageStats returns statistics for a specific package
func (a *App) handleAnalyticsPackageStats(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	registry := c.Params("registry")
	name := c.Params("name")

	if registry == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "registry and name parameters are required",
		})
	}

	stats, exists := a.analyticsEngine.GetPackageStats(registry, name)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "package not found in analytics",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"package": stats,
	})
}

// handleAnalyticsSearch searches for packages matching a query
func (a *App) handleAnalyticsSearch(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")

	query := c.Query("q")
	if query == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "query parameter 'q' is required",
		})
	}

	// Get limit from query params (default: 20)
	limit := 20
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	results := a.analyticsEngine.SearchPackages(query, limit)

	log.Debug().
		Str("query", query).
		Int("results", len(results)).
		Msg("Analytics search completed")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"results": results,
		"total":   len(results),
		"query":   query,
	})
}
