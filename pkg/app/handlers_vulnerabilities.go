package app

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// handleVulnerabilities handles /api/packages/{registry}/{name}/{version}/vulnerabilities endpoint
func (a *App) handleVulnerabilities(c fiber.Ctx) error {
	c.Set("Content-Type", "application/json")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusOK)
	}

	if c.Method() != "GET" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "method not allowed"})
	}

	ctx := c.Context()

	// Parse path: /api/packages/{registry}/{name}/{version}/vulnerabilities
	path := strings.TrimPrefix(c.Path(), "/api/packages/")
	path = strings.TrimSuffix(path, "/vulnerabilities")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid path format, expected /api/packages/{registry}/{name}/{version}/vulnerabilities",
		})
	}

	registry := parts[0]
	version := parts[len(parts)-1]
	name := strings.Join(parts[1:len(parts)-1], "/")

	log.Debug().
		Str("registry", registry).
		Str("name", name).
		Str("version", version).
		Msg("Getting vulnerabilities for package")

	key, pkg, pkgErr := a.resolvePackageKey(ctx, registry, name, version)
	releaseVersion := ""
	if pkgErr == nil && pkg != nil {
		releaseVersion = pkg.ReleaseVersion
	}

	// Get scan result from metadata store
	scanResult, err := a.metadata.GetScanResult(ctx, registry, key, version)
	if err != nil {
		if pkgErr != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "package not found"})
		}

		// Package exists but not scanned yet
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"package": fiber.Map{
				"registry":        registry,
				"name":            name,
				"version":         version,
				"release_version": releaseVersion,
			},
			"scanned":             false,
			"status":              "pending",
			"vulnerabilities":     []interface{}{},
			"vulnerability_count": 0,
			"message":             "Package not yet scanned for vulnerabilities",
			"security_scanned":    pkg.SecurityScanned,
			"decision":            fiber.Map{"verdict": VerdictPending, "blocked": false, "reason": "", "bypass": nil},
			"scanners":            []interface{}{},
		})
	}

	// Get active bypasses to show which vulnerabilities are bypassed
	bypasses, err := a.metadata.GetActiveCVEBypasses(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get CVE bypasses")
		bypasses = []*metadata.CVEBypass{}
	}

	// Build bypass map for fast lookup.
	// Normalize Go cache-key names (modulePath/@v/version.zip) to the
	// natural module path so admin bypass targets like
	// "go/github.com/foo/bar@v1.2.3" match the package.
	bypassName := name
	if registry == "go" {
		if idx := strings.Index(bypassName, "/@v/"); idx >= 0 {
			bypassName = bypassName[:idx]
		}
	}
	packageKey := registry + "/" + bypassName + "@" + version
	packageKeyNoVersion := registry + "/" + bypassName
	releaseKey := ""
	if releaseVersion != "" {
		releaseKey = registry + "/" + bypassName + "@" + releaseVersion
	}
	bypassedCVEs := make(map[string]*metadata.CVEBypass)
	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypeCVE && bypass.Active {
			// Check if bypass applies to this package
			if bypass.AppliesTo == "" || bypass.AppliesTo == packageKey || bypass.AppliesTo == packageKeyNoVersion || (releaseKey != "" && bypass.AppliesTo == releaseKey) {
				bypassedCVEs[strings.ToUpper(bypass.Target)] = bypass
			}
		}
	}

	// Enrich vulnerabilities with bypass information
	enrichedVulns := make([]map[string]interface{}, 0, len(scanResult.Vulnerabilities))
	severityCounts := make(map[string]int)

	for _, vuln := range scanResult.Vulnerabilities {
		bypassed := false
		var bypassInfo map[string]interface{}

		// Check if this CVE is bypassed
		if bypass, ok := bypassedCVEs[strings.ToUpper(vuln.ID)]; ok {
			bypassed = true
			bypassInfo = map[string]interface{}{
				"id":         bypass.ID,
				"reason":     bypass.Reason,
				"created_by": bypass.CreatedBy,
				"expires_at": bypass.ExpiresAt,
			}
		} else {
			// Count non-bypassed vulnerabilities by severity
			severityCounts[metadata.NormalizeSeverity(vuln.Severity)]++
		}

		enrichedVuln := map[string]interface{}{
			"id":          vuln.ID,
			"severity":    vuln.Severity,
			"title":       vuln.Title,
			"description": vuln.Description,
			"references":  vuln.References,
			"fixed_in":    vuln.FixedIn,
			"detected_by": vuln.DetectedBy,
			"bypassed":    bypassed,
		}

		if bypassed {
			enrichedVuln["bypass"] = bypassInfo
		}

		enrichedVulns = append(enrichedVulns, enrichedVuln)
	}

	// Build response
	response := fiber.Map{
		"package": fiber.Map{
			"registry":        registry,
			"name":            name,
			"version":         version,
			"release_version": releaseVersion,
		},
		"scanned":             true,
		"scanner":             scanResult.Scanner,
		"scanned_at":          scanResult.ScannedAt,
		"status":              scanResult.Status,
		"vulnerabilities":     enrichedVulns,
		"vulnerability_count": scanResult.VulnerabilityCount,
		"severity_counts": fiber.Map{
			"critical": severityCounts["CRITICAL"],
			"high":     severityCounts["HIGH"],
			"moderate": severityCounts["MODERATE"],
			"low":      severityCounts["LOW"],
		},
		"bypassed_count": len(scanResult.Vulnerabilities) - (severityCounts["CRITICAL"] + severityCounts["HIGH"] + severityCounts["MODERATE"] + severityCounts["LOW"]),
		"scanners":       scannerBreakdown(scanResult),
		"decision":       a.packageDecision(ctx, pkg),
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

// goCacheKeyExts orders the Go cache files a module version is stored under; the
// .zip carries the scan result.
var goCacheKeyExts = []string{"zip", "mod", "info"}

// resolvePackageKey maps the name the dashboard shows to the stored row name.
// Go rows are stored under cache keys (module/@v/version.ext), not the module path.
func (a *App) resolvePackageKey(ctx context.Context, registry, name, version string) (string, *metadata.Package, error) {
	pkg, err := a.metadata.GetPackage(ctx, registry, name, version)
	if err == nil || registry != "go" || strings.Contains(name, "/@v/") {
		return name, pkg, err
	}
	for _, ext := range goCacheKeyExts {
		key := name + "/@v/" + version + "." + ext
		if p, kerr := a.metadata.GetPackage(ctx, registry, key, version); kerr == nil {
			return key, p, nil
		}
	}
	return name, nil, err
}

// scannerBreakdown counts each scanner's findings by severity, from the merged scan's detected_by lists.
func scannerBreakdown(res *metadata.ScanResult) []map[string]interface{} {
	names := strings.Split(res.Scanner, "+")
	counts := make(map[string]map[string]int, len(names))
	for _, n := range names {
		counts[n] = map[string]int{"critical": 0, "high": 0, "moderate": 0, "low": 0}
	}
	for _, v := range res.Vulnerabilities {
		by := v.DetectedBy
		if len(by) == 0 && len(names) == 1 {
			by = names
		}
		sev := strings.ToLower(metadata.NormalizeSeverity(v.Severity))
		for _, n := range by {
			if c, ok := counts[n]; ok {
				c[sev]++
			}
		}
	}
	out := make([]map[string]interface{}, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		c := counts[n]
		out = append(out, map[string]interface{}{
			"name":            n,
			"findings":        c["critical"] + c["high"] + c["moderate"] + c["low"],
			"severity_counts": c,
		})
	}
	return out
}

// packageDecision is the verdict the proxy applies to one package, with the bypass that applied.
func (a *App) packageDecision(ctx context.Context, pkg *metadata.Package) fiber.Map {
	decision := fiber.Map{"verdict": VerdictCleared, "blocked": false, "reason": "", "bypass": nil}
	if pkg == nil {
		return decision
	}
	list, err := a.scanDecisions(ctx, []string{pkg.ID})
	if err != nil || len(list) == 0 {
		if err != nil {
			log.Warn().Err(err).Str("package", pkg.Name).Msg("Failed to judge package")
		}
		return decision
	}
	d := list[0]
	decision["verdict"] = verdictOf(d)
	decision["blocked"] = d.Blocked
	decision["reason"] = d.Reason
	decision["bypass"] = bypassSummary(d.Bypass)
	return decision
}
