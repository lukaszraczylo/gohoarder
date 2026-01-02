package app

import (
	"net/http"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// handleVulnerabilities handles /api/packages/{registry}/{name}/{version}/vulnerabilities endpoint
func (a *App) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
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

	// Parse path: /api/packages/{registry}/{name}/{version}/vulnerabilities
	path := strings.TrimPrefix(r.URL.Path, "/api/packages/")
	path = strings.TrimSuffix(path, "/vulnerabilities")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		errors.WriteErrorSimple(w, errors.BadRequest("invalid path format, expected /api/packages/{registry}/{name}/{version}/vulnerabilities"))
		return
	}

	registry := parts[0]
	version := parts[len(parts)-1]
	name := strings.Join(parts[1:len(parts)-1], "/")

	log.Debug().
		Str("registry", registry).
		Str("name", name).
		Str("version", version).
		Msg("Getting vulnerabilities for package")

	// Get scan result from metadata store
	scanResult, err := a.metadata.GetScanResult(ctx, registry, name, version)
	if err != nil {
		// Check if package exists
		pkg, pkgErr := a.metadata.GetPackage(ctx, registry, name, version)
		if pkgErr != nil {
			errors.WriteErrorSimple(w, errors.NotFound("package not found"))
			return
		}

		// Package exists but not scanned yet
		errors.WriteJSONSimple(w, http.StatusOK, map[string]interface{}{
			"package": map[string]string{
				"registry": registry,
				"name":     name,
				"version":  version,
			},
			"scanned":             false,
			"status":              "pending",
			"vulnerabilities":     []interface{}{},
			"vulnerability_count": 0,
			"message":             "Package not yet scanned for vulnerabilities",
			"security_scanned":    pkg.SecurityScanned,
		})
		return
	}

	// Get active bypasses to show which vulnerabilities are bypassed
	bypasses, err := a.metadata.GetActiveCVEBypasses(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get CVE bypasses")
		bypasses = []*metadata.CVEBypass{}
	}

	// Build bypass map for fast lookup
	bypassedCVEs := make(map[string]*metadata.CVEBypass)
	packageKey := registry + "/" + name + "@" + version
	packageKeyNoVersion := registry + "/" + name

	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypeCVE && bypass.Active {
			// Check if bypass applies to this package
			if bypass.AppliesTo == "" || bypass.AppliesTo == packageKey || bypass.AppliesTo == packageKeyNoVersion {
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
			severityCounts[strings.ToUpper(vuln.Severity)]++
		}

		enrichedVuln := map[string]interface{}{
			"id":          vuln.ID,
			"severity":    vuln.Severity,
			"title":       vuln.Title,
			"description": vuln.Description,
			"references":  vuln.References,
			"fixed_in":    vuln.FixedIn,
			"bypassed":    bypassed,
		}

		if bypassed {
			enrichedVuln["bypass"] = bypassInfo
		}

		enrichedVulns = append(enrichedVulns, enrichedVuln)
	}

	// Build response
	response := map[string]interface{}{
		"package": map[string]string{
			"registry": registry,
			"name":     name,
			"version":  version,
		},
		"scanned":             true,
		"scanner":             scanResult.Scanner,
		"scanned_at":          scanResult.ScannedAt,
		"status":              scanResult.Status,
		"vulnerabilities":     enrichedVulns,
		"vulnerability_count": scanResult.VulnerabilityCount,
		"severity_counts": map[string]int{
			"critical": severityCounts["CRITICAL"],
			"high":     severityCounts["HIGH"],
			"medium":   severityCounts["MEDIUM"],
			"low":      severityCounts["LOW"],
		},
		"bypassed_count": len(scanResult.Vulnerabilities) - (severityCounts["CRITICAL"] + severityCounts["HIGH"] + severityCounts["MEDIUM"] + severityCounts["LOW"]),
	}

	errors.WriteJSONSimple(w, http.StatusOK, response)
}
