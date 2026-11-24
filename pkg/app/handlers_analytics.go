package app

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// handleAnalyticsTopPackages returns the most downloaded packages
func (a *App) handleAnalyticsTopPackages(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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

// trendingPackage keeps the Go field names the dashboard reads from the analytics engine.
type trendingPackage struct {
	Registry          string
	Name              string
	Downloads         int64
	RecentDownloads   int64
	PreviousDownloads int64
	Trend             float64
}

// handleAnalyticsTrendingPackages ranks packages by downloads in the last 7 days. Persisted
// history serves it so a restart keeps the ranking; the in-memory engine covers stores without it.
func (a *App) handleAnalyticsTrendingPackages(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	// Get limit from query params (default: 10)
	limit := 10
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	if source, ok := a.metadata.(metadata.TrendingSource); ok {
		stored, err := source.GetTrendingPackages(c.Context(), limit)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read trending packages")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to read trending packages",
			})
		}
		packages := make([]trendingPackage, 0, len(stored))
		for _, p := range stored {
			trend := 0.0
			if p.Previous > 0 {
				trend = float64(p.Recent-p.Previous) / float64(p.Previous) * 100
			}
			packages = append(packages, trendingPackage{
				Registry:          p.Registry,
				Name:              p.Name,
				Downloads:         p.Recent,
				RecentDownloads:   p.Recent,
				PreviousDownloads: p.Previous,
				Trend:             trend,
			})
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"packages": packages,
			"total":    len(packages),
		})
	}

	packages := a.analyticsEngine.GetTrendingPackages(limit)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"packages": packages,
		"total":    len(packages),
	})
}

// handleAnalyticsTrends returns download trends over time
func (a *App) handleAnalyticsTrends(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	trends := a.analyticsEngine.GetTrends()

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"trends": trends,
	})
}

// handleAnalyticsTotalStats returns overall statistics
func (a *App) handleAnalyticsTotalStats(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	stats := a.analyticsEngine.GetTotalStats()

	return c.Status(fiber.StatusOK).JSON(stats)
}

// handleAnalyticsRegistryStats returns per-registry statistics
func (a *App) handleAnalyticsRegistryStats(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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
func (a *App) handleAnalyticsPackageStats(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	registry := c.Params("registry")
	// The wildcard route carries names with slashes (@scope/pkg, Go module paths).
	name := c.Params("*")

	if registry == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "registry and name parameters are required",
		})
	}

	// Analytics live in memory and restart empty, so a package with no record yet is a normal
	// answer, not a missing resource: a 404 here shows up as a failed request in every client.
	stats, _ := a.analyticsEngine.GetPackageStats(registry, name)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"package": stats,
	})
}

// handleAnalyticsSearch searches for packages matching a query
func (a *App) handleAnalyticsSearch(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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
