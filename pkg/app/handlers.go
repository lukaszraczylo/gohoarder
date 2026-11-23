package app

import (
	"context"
	stderrors "errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/internal/version"
	apperrors "github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
	"github.com/rs/zerolog/log"
)

// handlePackages handles /api/packages endpoint
func (a *App) handlePackages(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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

// packageSummary is the list payload for one package when scan results are attached.
func packageSummary(pkg *metadata.Package) map[string]interface{} {
	summary := map[string]interface{}{
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
	if pkg.ReleaseVersion != "" {
		summary["release_version"] = pkg.ReleaseVersion
	}
	return summary
}

// Pagination limits of GET /api/packages.
const (
	defaultPageSize = 25
	maxPageSize     = 200
)

// listParams are the parsed query parameters of GET /api/packages.
type listParams struct {
	opts  metadata.GroupListOptions
	paged bool
}

// parseSeverities reads a comma-separated severity filter such as "critical,high".
func parseSeverities(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		sev := strings.ToLower(strings.TrimSpace(part))
		if sev == "" || slices.Contains(out, sev) {
			continue
		}
		if !slices.Contains(metadata.Severities, sev) {
			return nil, fmt.Errorf("invalid severity %q, must be one of: %s", sev, strings.Join(metadata.Severities, ", "))
		}
		out = append(out, sev)
	}
	return out, nil
}

// parseListParams reads page, page_size, registry, q, sort, order and severity.
// Without page or page_size the list is unpaginated, as it was before paging existed.
func parseListParams(c fiber.Ctx) (listParams, error) {
	p := listParams{opts: metadata.GroupListOptions{
		Registry: c.Query("registry"),
		Query:    c.Query("q"),
		SortBy:   metadata.GroupSortName,
	}}
	switch sortBy := c.Query("sort"); sortBy {
	case metadata.GroupSortName, metadata.GroupSortCachedAt, metadata.GroupSortDownloads, metadata.GroupSortSize:
		p.opts.SortBy = sortBy
		p.opts.SortDesc = sortBy != metadata.GroupSortName
	}
	switch c.Query("order") {
	case "asc":
		p.opts.SortDesc = false
	case "desc":
		p.opts.SortDesc = true
	}
	severities, err := parseSeverities(c.Query("severity"))
	if err != nil {
		return p, err
	}
	p.opts.Severities = severities
	if c.Query("page") != "" || c.Query("page_size") != "" {
		p.paged = true
		p.opts.Page = max(fiber.Query[int](c, "page", 1), 1)
		p.opts.PageSize = fiber.Query[int](c, "page_size", defaultPageSize)
		if p.opts.PageSize < 1 {
			p.opts.PageSize = defaultPageSize
		}
		p.opts.PageSize = min(p.opts.PageSize, maxPageSize)
	}
	return p, nil
}

// scanDecisions judges scanned packages, falling back to plain summaries without a scan manager.
func (a *App) scanDecisions(ctx context.Context, ids []string) ([]scanner.ScanDecision, error) {
	if a.scanManager != nil {
		return a.scanManager.ScanDecisions(ctx, ids)
	}
	summaries, err := a.metadata.GetScanSummaries(ctx, ids, false)
	if err != nil {
		return nil, err
	}
	out := make([]scanner.ScanDecision, len(summaries))
	for i, s := range summaries {
		out[i] = scanner.ScanDecision{Summary: s}
	}
	return out, nil
}

// vulnerabilityInfo is the per-row scan block of the list payload.
func vulnerabilityInfo(pkg *metadata.Package, decisions map[string]scanner.ScanDecision) map[string]interface{} {
	if !pkg.SecurityScanned {
		return map[string]interface{}{"scanned": false, "status": "not_scanned", "isBlocked": false}
	}
	d, ok := decisions[pkg.ID]
	if !ok || !d.Summary.HasScan {
		return map[string]interface{}{"scanned": false, "status": "pending", "isBlocked": false}
	}
	sum := d.Summary
	return map[string]interface{}{
		"scanned":   true,
		"status":    sum.Status,
		"scannedAt": sum.ScannedAt.Format(time.RFC3339),
		"counts": map[string]int{
			"critical": sum.Critical,
			"high":     sum.High,
			"moderate": sum.Moderate,
			"low":      sum.Low,
		},
		"total":     sum.Total,
		"isBlocked": d.Blocked,
	}
}

// handleListPackages returns cached packages, one page of groups when page or
// page_size is given and every group otherwise.
func (a *App) handleListPackages(c fiber.Ctx) error {
	ctx := c.Context()
	params, err := parseListParams(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	page, err := a.metadata.ListPackageGroups(ctx, params.opts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list packages"})
	}

	response := fiber.Map{
		"total":        len(page.Packages),
		"total_groups": page.TotalGroups,
	}
	if params.paged {
		response["page"] = params.opts.Page
		response["page_size"] = params.opts.PageSize
	}

	if !a.config.Security.Enabled {
		response["packages"] = page.Packages
		return c.Status(fiber.StatusOK).JSON(response)
	}

	var scannedIDs []string
	for _, pkg := range page.Packages {
		if pkg.SecurityScanned {
			scannedIDs = append(scannedIDs, pkg.ID)
		}
	}
	decisions := map[string]scanner.ScanDecision{}
	if len(scannedIDs) > 0 {
		list, err := a.scanDecisions(ctx, scannedIDs)
		if err != nil {
			log.Error().Err(err).Msg("Failed to load scan summaries")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to list packages"})
		}
		for _, d := range list {
			decisions[d.Summary.PackageID] = d
		}
	}

	enhanced := make([]map[string]interface{}, 0, len(page.Packages))
	for _, pkg := range page.Packages {
		pkgMap := packageSummary(pkg)
		pkgMap["vulnerabilities"] = vulnerabilityInfo(pkg, decisions)
		enhanced = append(enhanced, pkgMap)
	}
	response["packages"] = enhanced
	return c.Status(fiber.StatusOK).JSON(response)
}

// handleDeletePackage deletes a cached package
func (a *App) handleDeletePackage(c fiber.Ctx) error {
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
			Registry:   registry,
			NamePrefix: name,
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
			var appErr *apperrors.Error
			if stderrors.As(err, &appErr) && appErr.Code == apperrors.ErrCodeNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "package not found"})
			}
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
func (a *App) handleStats(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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

	registryStats := make(map[string]map[string]interface{})
	byRegistry, err := a.metadata.GetRegistryStats(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get registry stats")
	}
	for _, rs := range byRegistry {
		registryStats[rs.Registry] = map[string]interface{}{
			"count":     int(rs.Count),
			"size":      rs.Size,
			"downloads": rs.Downloads,
		}
	}

	// Blocked packages need the blocking policy, so judge every scanned package in one batch.
	blockedCount, err := a.countBlocked(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to judge scanned packages")
	}

	// Combine statistics using database stats for accuracy
	stats := map[string]interface{}{
		"total_packages":      cacheStats.TotalPackages,
		"total_downloads":     cacheStats.TotalDownloads,
		"total_size":          cacheStats.TotalSize,
		"max_cache_size":      a.config.Cache.MaxSizeBytes,
		"idle_ttl":            int64(a.config.Cache.IdleTTL / time.Second), // seconds, 0 = idle eviction off
		"cache_hits":          cacheStats.TotalDownloads,
		"cache_misses":        0, // TODO: Track cache misses
		"cache_evictions":     0, // TODO: Track evictions
		"cache_size":          cacheStats.TotalSize,
		"scanned_packages":    cacheStats.ScannedPackages,
		"vulnerable_packages": cacheStats.VulnerablePackages,
		"blocked_packages":    blockedCount,
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
func (a *App) handleTimeSeriesStats(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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
func (a *App) handleConfig(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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
func (a *App) handleInfo(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

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
