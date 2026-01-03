package app

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lukaszraczylo/gohoarder/internal/version"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
	"github.com/rs/zerolog/log"
)

// handlePackages handles /api/packages endpoint
func (a *App) handlePackages(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	// Check if this is a vulnerability endpoint request
	if strings.HasSuffix(c.Path(), "/vulnerabilities") {
		return a.handleVulnerabilities(c)
	}

	switch c.Method() {
	case "GET":
		return a.handleListPackages(c)
	case "DELETE":
		return a.handleDeletePackage(c)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}
}

// handleListPackages returns list of cached packages
func (a *App) handleListPackages(c *fiber.Ctx) error {
	ctx := c.Context()

	// Get packages from metadata store
	allPackages, err := a.metadata.ListPackages(ctx, &metadata.ListOptions{
		Limit:  1000, // Get more to account for duplicates
		Offset: 0,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list packages"})
	}

	log.Debug().Int("total_packages_from_db", len(allPackages)).Msg("Retrieved packages from database")

	// Filter, clean, and deduplicate packages
	// Map stores both cleaned package and original name for scan lookups
	type packageEntry struct {
		pkg          *metadata.Package
		originalName string
	}
	seen := make(map[string]*packageEntry)
	skippedCount := 0
	for _, pkg := range allPackages {
		// Skip metadata entries (npm metadata pages, pypi pages, etc.)
		if pkg.Version == "list" || pkg.Version == "latest" || pkg.Version == "metadata" || pkg.Version == "page" {
			skippedCount++
			log.Debug().
				Str("name", pkg.Name).
				Str("version", pkg.Version).
				Str("registry", pkg.Registry).
				Msg("Skipping metadata entry")
			continue
		}

		// Clean the package name (remove /@v/version.ext suffix)
		originalName := pkg.Name
		cleanName := pkg.Name
		if idx := strings.Index(cleanName, "/@v/"); idx != -1 {
			cleanName = cleanName[:idx]
		}

		// Create deduplication key
		key := cleanName + "@" + pkg.Version

		// Keep the entry with the largest size (typically .zip files)
		if existing, ok := seen[key]; !ok || pkg.Size > existing.pkg.Size {
			// Create a copy with cleaned name
			cleanPkg := *pkg
			cleanPkg.Name = cleanName
			seen[key] = &packageEntry{
				pkg:          &cleanPkg,
				originalName: originalName,
			}
		}
	}

	log.Debug().
		Int("skipped_metadata", skippedCount).
		Int("unique_packages", len(seen)).
		Msg("Filtered and deduplicated packages")

	// Convert map to slice, keeping track of original names
	type packageWithOriginalName struct {
		pkg          *metadata.Package
		originalName string
	}
	packagesWithNames := make([]packageWithOriginalName, 0, len(seen))
	for _, entry := range seen {
		packagesWithNames = append(packagesWithNames, packageWithOriginalName{
			pkg:          entry.pkg,
			originalName: entry.originalName,
		})
	}

	// Enhance packages with vulnerability information if security scanning is enabled
	var response map[string]interface{}
	if a.config.Security.Enabled {
		enhancedPackages := make([]map[string]interface{}, 0, len(packagesWithNames))
		for _, entry := range packagesWithNames {
			pkg := entry.pkg
			pkgMap := map[string]interface{}{
				"id":              pkg.ID,
				"registry":        pkg.Registry,
				"name":            pkg.Name,
				"version":         pkg.Version,
				"size":            pkg.Size,
				"checksum_sha256": pkg.ChecksumSHA256,
				"cached_at":       pkg.CachedAt,
				"last_accessed":   pkg.LastAccessed,
				"download_count":  pkg.DownloadCount,
			}

			// Add vulnerability info if scanned
			if pkg.SecurityScanned {
				// Use original name for scan result lookup (handles Go packages with /@v/ suffix)
				scanResult, err := a.metadata.GetScanResult(ctx, pkg.Registry, entry.originalName, pkg.Version)
				if err == nil && scanResult != nil {
					// Count vulnerabilities by severity
					severityCounts := make(map[string]int)
					for _, vuln := range scanResult.Vulnerabilities {
						severityCounts[strings.ToUpper(vuln.Severity)]++
					}

					pkgMap["vulnerabilities"] = map[string]interface{}{
						"scanned":   true,
						"status":    scanResult.Status,
						"scannedAt": scanResult.ScannedAt.Format(time.RFC3339),
						"counts": map[string]int{
							"critical": severityCounts["CRITICAL"],
							"high":     severityCounts["HIGH"],
							"moderate": severityCounts["MODERATE"],
							"low":      severityCounts["LOW"],
						},
						"total": scanResult.VulnerabilityCount,
					}
				} else {
					pkgMap["vulnerabilities"] = map[string]interface{}{
						"scanned": false,
						"status":  "pending",
					}
				}
			} else {
				pkgMap["vulnerabilities"] = map[string]interface{}{
					"scanned": false,
					"status":  "not_scanned",
				}
			}

			enhancedPackages = append(enhancedPackages, pkgMap)
		}

		response = map[string]interface{}{
			"packages": enhancedPackages,
			"total":    len(enhancedPackages),
		}
	} else {
		// Non-enhanced mode - just return the packages
		packages := make([]*metadata.Package, 0, len(packagesWithNames))
		for _, entry := range packagesWithNames {
			packages = append(packages, entry.pkg)
		}
		response = map[string]interface{}{
			"packages": packages,
			"total":    len(packages),
		}
	}

	// Success response
	return c.Status(fiber.StatusOK).JSON(response)
}

// handleDeletePackage deletes a cached package
func (a *App) handleDeletePackage(c *fiber.Ctx) error {
	ctx := c.Context()

	// Parse path: /api/packages/{registry}/{name}/{version}
	// For Go packages, name can contain slashes (e.g., github.com/user/repo)
	// Version is always the last segment
	path := strings.TrimPrefix(c.Path(), "/api/packages/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid path format, expected /api/packages/{registry}/{name}/{version}",
		})
	}

	registry := parts[0]
	version := parts[len(parts)-1]
	name := strings.Join(parts[1:len(parts)-1], "/")

	// For Go packages, we need to find and delete all cache entries (.info, .mod, .zip)
	// For other registries, we can delete directly
	var deletedCount int
	var lastErr error

	if registry == "go" {
		// List all packages matching the base name and version
		allPackages, err := a.metadata.ListPackages(ctx, &metadata.ListOptions{
			Limit: 1000,
		})
		if err != nil {
			log.Error().Err(err).Msg("Failed to list packages for deletion")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list packages"})
		}

		log.Debug().
			Str("registry", registry).
			Str("name", name).
			Str("version", version).
			Int("total_packages", len(allPackages)).
			Msg("Searching for packages to delete")

		// Find and delete all entries for this package
		for _, pkg := range allPackages {
			if pkg.Registry != registry || pkg.Version != version {
				continue
			}

			// Check if this package name matches (either exact or with /@v/ suffix)
			cleanName := pkg.Name
			if idx := strings.Index(cleanName, "/@v/"); idx != -1 {
				cleanName = cleanName[:idx]
			}

			log.Debug().
				Str("db_name", pkg.Name).
				Str("clean_name", cleanName).
				Str("search_name", name).
				Bool("matches", cleanName == name).
				Msg("Checking package")

			if cleanName == name {
				if err := a.cache.Delete(ctx, pkg.Registry, pkg.Name, pkg.Version); err != nil {
					log.Warn().
						Err(err).
						Str("registry", pkg.Registry).
						Str("name", pkg.Name).
						Str("version", pkg.Version).
						Msg("Failed to delete package variant")
					lastErr = err
				} else {
					deletedCount++
					log.Info().
						Str("registry", pkg.Registry).
						Str("name", pkg.Name).
						Str("version", pkg.Version).
						Msg("Deleted package variant")
				}
			}
		}

		log.Debug().
			Int("deleted_count", deletedCount).
			Msg("Delete operation completed")

		if deletedCount == 0 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "package not found"})
		}

		if lastErr != nil && deletedCount == 0 {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete package"})
		}
	} else {
		// For NPM and PyPI, delete directly
		if err := a.cache.Delete(ctx, registry, name, version); err != nil {
			log.Error().
				Err(err).
				Str("registry", registry).
				Str("name", name).
				Str("version", version).
				Msg("Failed to delete package")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to delete package"})
		}
		deletedCount = 1
	}

	// Broadcast event via WebSocket
	a.wsServer.Broadcast(websocket.EventPackageDeleted, map[string]interface{}{
		"registry": registry,
		"name":     name,
		"version":  version,
	})

	// Success response
	response := map[string]interface{}{
		"deleted": true,
		"package": map[string]string{
			"registry": registry,
			"name":     name,
			"version":  version,
		},
	}

	// For Go packages, include count of deleted variants
	if registry == "go" {
		response["deleted_count"] = deletedCount
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// handleStats handles /api/stats endpoint
func (a *App) handleStats(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	if c.Method() != "GET" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}

	ctx := c.Context()

	// Get cache statistics for all registries from database
	cacheStats, err := a.cache.GetStats(ctx, "")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get cache stats")
		cacheStats = &metadata.Stats{}
	}

	// Get all packages to calculate per-registry breakdown
	packages, err := a.metadata.ListPackages(ctx, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages")
		packages = []*metadata.Package{}
	}

	// Calculate per-registry breakdown (exclude metadata entries like "list", "latest")
	registryStats := make(map[string]map[string]interface{})

	for _, pkg := range packages {
		// Skip metadata entries (npm metadata pages, pypi pages, etc.)
		if pkg.Version == "list" || pkg.Version == "latest" || pkg.Version == "metadata" || pkg.Version == "page" {
			continue
		}

		// Track per-registry stats
		if _, ok := registryStats[pkg.Registry]; !ok {
			registryStats[pkg.Registry] = map[string]interface{}{
				"count":     0,
				"size":      int64(0),
				"downloads": int64(0),
			}
		}
		registryStats[pkg.Registry]["count"] = registryStats[pkg.Registry]["count"].(int) + 1
		registryStats[pkg.Registry]["size"] = registryStats[pkg.Registry]["size"].(int64) + pkg.Size
		registryStats[pkg.Registry]["downloads"] = registryStats[pkg.Registry]["downloads"].(int64) + int64(pkg.DownloadCount)
	}

	// Combine statistics using database stats for accuracy
	stats := map[string]interface{}{
		"total_packages":      cacheStats.TotalPackages,
		"total_downloads":     cacheStats.TotalDownloads,
		"total_size":          cacheStats.TotalSize,
		"cache_hits":          cacheStats.TotalDownloads,
		"cache_misses":        0, // TODO: Track cache misses
		"cache_evictions":     0, // TODO: Track evictions
		"cache_size":          cacheStats.TotalSize,
		"scanned_packages":    cacheStats.ScannedPackages,
		"vulnerable_packages": cacheStats.VulnerablePackages,
	}

	// Convert registry stats to interface map
	registries := make(map[string]interface{})
	for registry, regStats := range registryStats {
		registries[registry] = regStats
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"stats":      stats,
		"registries": registries,
	})
}

// handleTimeSeriesStats handles /api/stats/timeseries endpoint
// Returns time-series download statistics for charts
func (a *App) handleTimeSeriesStats(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	if c.Method() != "GET" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}

	ctx := c.Context()

	// Get query parameters
	period := c.Query("period", "1day") // Default to 1 day
	registry := c.Query("registry")     // Optional registry filter

	// Validate period
	validPeriods := map[string]bool{"1h": true, "1day": true, "7day": true, "30day": true}
	if !validPeriods[period] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid period, must be one of: 1h, 1day, 7day, 30day",
		})
	}

	// Get time-series stats
	stats, err := a.metadata.GetTimeSeriesStats(ctx, period, registry)
	if err != nil {
		log.Error().Err(err).Str("period", period).Str("registry", registry).Msg("Failed to get time-series stats")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to get time-series statistics",
		})
	}

	return c.Status(fiber.StatusOK).JSON(stats)
}

// handleConfig handles /api/config endpoint
// Returns runtime configuration for the frontend
func (a *App) handleConfig(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	if c.Method() != "GET" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}

	// Build server URL from request
	scheme := "http"
	if c.Protocol() == "https" {
		scheme = "https"
	}
	serverURL := scheme + "://" + c.Hostname()

	config := map[string]interface{}{
		"server_url": serverURL,
		"version":    version.Version,
		"features": map[string]bool{
			"security_scanning": a.config.Security.Enabled,
			"websockets":        true,
		},
	}

	return c.Status(fiber.StatusOK).JSON(config)
}

// handleInfo handles /api/info endpoint
func (a *App) handleInfo(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/json")
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Set("Access-Control-Allow-Headers", "Content-Type")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	if c.Method() != "GET" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}

	info := map[string]interface{}{
		"name":    "GoHoarder",
		"version": version.Version,
		"config": map[string]interface{}{
			"storage_backend":  a.config.Storage.Backend,
			"metadata_backend": a.config.Metadata.Backend,
			"cache_ttl":        a.config.Cache.DefaultTTL.String(),
			"max_cache_size":   a.config.Cache.MaxSizeBytes,
		},
		"features": map[string]bool{
			"security_scanning": a.config.Security.Enabled,
			"pre_warming":       a.prewarmWorker != nil,
			"websockets":        true,
			"analytics":         true,
		},
	}

	return c.Status(fiber.StatusOK).JSON(info)
}
