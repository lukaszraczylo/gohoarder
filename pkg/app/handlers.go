package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/internal/version"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
	"github.com/rs/zerolog/log"
)

// handlePackages handles /api/packages endpoint
func (a *App) handlePackages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Check if this is a vulnerability endpoint request
	if strings.HasSuffix(r.URL.Path, "/vulnerabilities") {
		a.handleVulnerabilities(w, r)
		return
	}

	switch r.Method {
	case "GET":
		a.handleListPackages(w, r)
	case "DELETE":
		a.handleDeletePackage(w, r)
	default:
		errors.WriteErrorSimple(w, errors.BadRequest("method not allowed"))
	}
}

// handleListPackages returns list of cached packages
func (a *App) handleListPackages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get packages from metadata store
	allPackages, err := a.metadata.ListPackages(ctx, &metadata.ListOptions{
		Limit:  1000, // Get more to account for duplicates
		Offset: 0,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages")
		errors.WriteErrorSimple(w, errors.InternalServer("failed to list packages"))
		return
	}

	// Filter, clean, and deduplicate packages
	seen := make(map[string]*metadata.Package)
	for _, pkg := range allPackages {
		// Skip metadata entries (npm metadata pages, pypi pages, etc.)
		if pkg.Version == "list" || pkg.Version == "latest" || pkg.Version == "metadata" || pkg.Version == "page" {
			continue
		}

		// Clean the package name (remove /@v/version.ext suffix)
		cleanName := pkg.Name
		if idx := strings.Index(cleanName, "/@v/"); idx != -1 {
			cleanName = cleanName[:idx]
		}

		// Create deduplication key
		key := cleanName + "@" + pkg.Version

		// Keep the entry with the largest size (typically .zip files)
		if existing, ok := seen[key]; !ok || pkg.Size > existing.Size {
			// Create a copy with cleaned name
			cleanPkg := *pkg
			cleanPkg.Name = cleanName
			seen[key] = &cleanPkg
		}
	}

	// Convert map to slice
	packages := make([]*metadata.Package, 0, len(seen))
	for _, pkg := range seen {
		packages = append(packages, pkg)
	}

	// Enhance packages with vulnerability information if security scanning is enabled
	var response map[string]interface{}
	if a.config.Security.Enabled {
		enhancedPackages := make([]map[string]interface{}, 0, len(packages))
		for _, pkg := range packages {
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
				scanResult, err := a.metadata.GetScanResult(ctx, pkg.Registry, pkg.Name, pkg.Version)
				if err == nil && scanResult != nil {
					// Count vulnerabilities by severity
					severityCounts := make(map[string]int)
					for _, vuln := range scanResult.Vulnerabilities {
						severityCounts[strings.ToUpper(vuln.Severity)]++
					}

					pkgMap["vulnerabilities"] = map[string]interface{}{
						"scanned": true,
						"status":  scanResult.Status,
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
		response = map[string]interface{}{
			"packages": packages,
			"total":    len(packages),
		}
	}

	// Success response
	errors.WriteJSONSimple(w, http.StatusOK, response)
}

// handleDeletePackage deletes a cached package
func (a *App) handleDeletePackage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse path: /api/packages/{registry}/{name}/{version}
	// For Go packages, name can contain slashes (e.g., github.com/user/repo)
	// Version is always the last segment
	path := strings.TrimPrefix(r.URL.Path, "/api/packages/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		errors.WriteErrorSimple(w, errors.BadRequest("invalid path format, expected /api/packages/{registry}/{name}/{version}"))
		return
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
			errors.WriteErrorSimple(w, errors.InternalServer("failed to list packages"))
			return
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
			errors.WriteErrorSimple(w, errors.NotFound("package not found"))
			return
		}

		if lastErr != nil && deletedCount == 0 {
			errors.WriteErrorSimple(w, errors.InternalServer("failed to delete package"))
			return
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
			errors.WriteErrorSimple(w, errors.InternalServer("failed to delete package"))
			return
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

	errors.WriteJSONSimple(w, http.StatusOK, response)
}

// handleStats handles /api/stats endpoint
func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		errors.WriteErrorSimple(w, errors.BadRequest("method not allowed"))
		return
	}

	ctx := r.Context()

	// Get cache statistics for all registries
	cacheStats, err := a.cache.GetStats(ctx, "")
	if err != nil {
		log.Error().Err(err).Msg("Failed to get cache stats")
		cacheStats = &metadata.Stats{}
	}

	// Get all packages to calculate total size and downloads
	packages, err := a.metadata.ListPackages(ctx, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages")
		packages = []*metadata.Package{}
	}

	// Calculate totals and registry breakdown from actual packages (exclude metadata entries like "list", "latest")
	var totalSize int64
	var totalDownloads int64
	var actualPackageCount int
	registryStats := make(map[string]map[string]interface{})

	for _, pkg := range packages {
		// Skip metadata entries (npm metadata pages, pypi pages, etc.)
		if pkg.Version == "list" || pkg.Version == "latest" || pkg.Version == "metadata" || pkg.Version == "page" {
			continue
		}
		totalSize += pkg.Size
		totalDownloads += int64(pkg.DownloadCount)
		actualPackageCount++

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

	// Combine statistics
	stats := map[string]interface{}{
		"total_packages":      actualPackageCount,
		"total_downloads":     totalDownloads,
		"total_size":          totalSize,
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

	errors.WriteJSONSimple(w, http.StatusOK, map[string]interface{}{
		"stats":      stats,
		"registries": registries,
	})
}

// handleInfo handles /api/info endpoint
func (a *App) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		errors.WriteErrorSimple(w, errors.BadRequest("method not allowed"))
		return
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
			"distributed_locking": a.lockManager != nil,
			"security_scanning":   a.config.Security.Enabled,
			"pre_warming":         a.prewarmWorker != nil,
			"websockets":          true,
			"analytics":           true,
		},
	}

	errors.WriteJSONSimple(w, http.StatusOK, info)
}
