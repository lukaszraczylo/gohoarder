package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/osv"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/trivy"
	"github.com/rs/zerolog/log"
)

// Scanner defines the interface for security scanners
type Scanner interface {
	// Name returns the scanner name
	Name() string

	// Scan scans a package for vulnerabilities
	Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error)

	// Health checks scanner health
	Health(ctx context.Context) error
}

// DatabaseUpdater is implemented by scanners that need database updates
type DatabaseUpdater interface {
	UpdateDatabase(ctx context.Context) error
}

// Manager manages multiple security scanners
type Manager struct {
	scanners        []Scanner
	enabled         bool
	config          config.SecurityConfig
	metadataStore   metadata.MetadataStore
}

// New creates a new scanner manager with configured scanners
func New(cfg config.SecurityConfig, metadataStore metadata.MetadataStore) (*Manager, error) {
	manager := &Manager{
		scanners:      make([]Scanner, 0),
		enabled:       cfg.Enabled,
		config:        cfg,
		metadataStore: metadataStore,
	}

	if !cfg.Enabled {
		log.Info().Msg("Security scanning disabled")
		return manager, nil
	}

	// Initialize Trivy scanner
	if cfg.Scanners.Trivy.Enabled {
		trivyScanner := trivy.New(cfg.Scanners.Trivy)
		manager.RegisterScanner(trivyScanner)
		log.Info().Msg("Trivy scanner enabled")

		// Update database on startup if configured
		if cfg.UpdateDBOnStartup {
			if err := trivyScanner.UpdateDatabase(context.Background()); err != nil {
				log.Warn().Err(err).Msg("Failed to update Trivy database on startup")
			}
		}
	}

	// Initialize OSV scanner
	if cfg.Scanners.OSV.Enabled {
		osvScanner := osv.New(cfg.Scanners.OSV)
		manager.RegisterScanner(osvScanner)
		log.Info().Msg("OSV scanner enabled")
	}

	if len(manager.scanners) == 0 {
		log.Warn().Msg("Security scanning enabled but no scanners configured")
	}

	return manager, nil
}

// RegisterScanner registers a scanner
func (m *Manager) RegisterScanner(scanner Scanner) {
	m.scanners = append(m.scanners, scanner)
}

// ScanPackage scans a package using all registered scanners and saves results
func (m *Manager) ScanPackage(ctx context.Context, registry, packageName, version string, filePath string) error {
	if !m.enabled {
		return nil
	}

	log.Info().
		Str("registry", registry).
		Str("package", packageName).
		Str("version", version).
		Msg("Starting security scan")

	// Collect results from all scanners
	var scanResults []*metadata.ScanResult
	scannerNames := make([]string, 0)

	for _, scanner := range m.scanners {
		result, err := scanner.Scan(ctx, registry, packageName, version, filePath)
		if err != nil {
			log.Error().
				Err(err).
				Str("scanner", scanner.Name()).
				Str("package", packageName).
				Msg("Scanner failed")
			continue
		}

		scanResults = append(scanResults, result)
		scannerNames = append(scannerNames, scanner.Name())

		log.Info().
			Str("scanner", scanner.Name()).
			Str("package", packageName).
			Str("status", string(result.Status)).
			Int("vulnerabilities", result.VulnerabilityCount).
			Msg("Scan completed")
	}

	// If no scanners succeeded, return
	if len(scanResults) == 0 {
		log.Warn().
			Str("package", packageName).
			Msg("All scanners failed, no results to save")
		return nil
	}

	// Merge and deduplicate results from all scanners
	mergedResult := m.mergeResults(scanResults, scannerNames)

	// Save consolidated result to metadata store
	if err := m.metadataStore.SaveScanResult(ctx, mergedResult); err != nil {
		log.Error().
			Err(err).
			Str("package", packageName).
			Msg("Failed to save consolidated scan result")
		return err
	}

	log.Info().
		Str("package", packageName).
		Str("status", string(mergedResult.Status)).
		Int("total_vulnerabilities", mergedResult.VulnerabilityCount).
		Int("unique_cves", len(mergedResult.Vulnerabilities)).
		Strs("scanners", scannerNames).
		Msg("Consolidated scan results saved")

	return nil
}

// mergeResults merges and deduplicates scan results from multiple scanners
func (m *Manager) mergeResults(results []*metadata.ScanResult, scannerNames []string) *metadata.ScanResult {
	if len(results) == 0 {
		return nil
	}

	// Use first result as base
	merged := &metadata.ScanResult{
		ID:             results[0].ID,
		Registry:       results[0].Registry,
		PackageName:    results[0].PackageName,
		PackageVersion: results[0].PackageVersion,
		Scanner:        strings.Join(scannerNames, "+"), // Combined scanner name
		ScannedAt:      results[0].ScannedAt,
		Status:         metadata.ScanStatusClean,
		Vulnerabilities: make([]metadata.Vulnerability, 0),
		Details:        make(map[string]interface{}),
	}

	// Use map for deduplication - key is CVE ID in uppercase
	vulnMap := make(map[string]*metadata.Vulnerability)
	severityCounts := make(map[string]int)

	// Merge vulnerabilities from all scanners
	for i, result := range results {
		scannerName := scannerNames[i]

		// Track scanner details
		merged.Details[scannerName] = result.Details

		// Add/merge vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			cveKey := strings.ToUpper(vuln.ID)

			// Check if CVE already exists
			if existing, exists := vulnMap[cveKey]; exists {
				// CVE found by multiple scanners - merge information
				log.Debug().
					Str("cve", vuln.ID).
					Strs("existing_scanners", existing.DetectedBy).
					Str("new_scanner", scannerName).
					Msg("CVE found by multiple scanners, merging")

				// Add scanner to DetectedBy list
				existing.DetectedBy = append(existing.DetectedBy, scannerName)

				// Prefer higher severity if different
				if m.compareSeverity(vuln.Severity, existing.Severity) > 0 {
					existing.Severity = vuln.Severity
				}

				// Merge references (deduplicate URLs)
				refSet := make(map[string]bool)
				for _, ref := range existing.References {
					refSet[ref] = true
				}
				for _, ref := range vuln.References {
					if !refSet[ref] {
						existing.References = append(existing.References, ref)
						refSet[ref] = true
					}
				}

				// Prefer fixed_in version if not already set
				if existing.FixedIn == "" && vuln.FixedIn != "" {
					existing.FixedIn = vuln.FixedIn
				}

			} else {
				// New CVE - add to map
				vulnCopy := vuln
				vulnCopy.DetectedBy = []string{scannerName}
				vulnMap[cveKey] = &vulnCopy
			}
		}

		// Update status to worst case
		if result.Status == metadata.ScanStatusVulnerable {
			merged.Status = metadata.ScanStatusVulnerable
		} else if result.Status == metadata.ScanStatusPending && merged.Status != metadata.ScanStatusVulnerable {
			merged.Status = metadata.ScanStatusPending
		}
	}

	// Convert map to slice and count severities
	for _, vuln := range vulnMap {
		merged.Vulnerabilities = append(merged.Vulnerabilities, *vuln)
		severityCounts[strings.ToUpper(vuln.Severity)]++
	}

	// Update counts
	merged.VulnerabilityCount = len(merged.Vulnerabilities)
	merged.Details["severity_counts"] = severityCounts
	merged.Details["deduplication_summary"] = fmt.Sprintf(
		"Merged results from %d scanners (%s)",
		len(scannerNames),
		strings.Join(scannerNames, ", "),
	)

	return merged
}

// compareSeverity returns >0 if s1 is more severe than s2, <0 if less, 0 if equal
func (m *Manager) compareSeverity(s1, s2 string) int {
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
		"UNKNOWN":  0,
	}

	v1 := severityOrder[strings.ToUpper(s1)]
	v2 := severityOrder[strings.ToUpper(s2)]

	return v1 - v2
}

// CheckVulnerabilities checks if a package exceeds vulnerability thresholds
func (m *Manager) CheckVulnerabilities(ctx context.Context, registry, packageName, version string) (bool, string, error) {
	if !m.enabled {
		return false, "", nil
	}

	// Get active CVE bypasses from database
	bypasses, err := m.metadataStore.GetActiveCVEBypasses(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get CVE bypasses, continuing without bypasses")
		bypasses = []*metadata.CVEBypass{} // Continue without bypasses
	}

	// Check if entire package is bypassed
	packageKey := fmt.Sprintf("%s/%s@%s", registry, packageName, version)
	packageKeyNoVersion := fmt.Sprintf("%s/%s", registry, packageName)

	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypePackage && bypass.Active {
			if bypass.Target == packageKey || bypass.Target == packageKeyNoVersion {
				log.Info().
					Str("package", packageKey).
					Str("bypass_id", bypass.ID).
					Str("reason", bypass.Reason).
					Time("expires_at", bypass.ExpiresAt).
					Msg("Package bypassed by admin")
				return false, "", nil
			}
		}
	}

	// Get latest scan result
	result, err := m.metadataStore.GetScanResult(ctx, registry, packageName, version)
	if err != nil {
		// No scan result found - allow download (will be scanned after)
		return false, "", nil
	}

	// Build set of bypassed CVEs for fast lookup
	bypassedCVEs := make(map[string]*metadata.CVEBypass)
	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypeCVE && bypass.Active {
			// Check if bypass applies to this package (if AppliesTo is set)
			if bypass.AppliesTo != "" && bypass.AppliesTo != packageKey && bypass.AppliesTo != packageKeyNoVersion {
				continue // This bypass doesn't apply to this package
			}
			bypassedCVEs[strings.ToUpper(bypass.Target)] = bypass
		}
	}

	// Count vulnerabilities by severity, excluding bypassed CVEs
	severityCounts := make(map[string]int)
	for _, vuln := range result.Vulnerabilities {
		// Check if this CVE is bypassed
		if bypass, ok := bypassedCVEs[strings.ToUpper(vuln.ID)]; ok {
			log.Debug().
				Str("cve", vuln.ID).
				Str("package", packageName).
				Str("bypass_id", bypass.ID).
				Str("reason", bypass.Reason).
				Time("expires_at", bypass.ExpiresAt).
				Msg("CVE bypassed by admin")
			continue
		}
		severityCounts[strings.ToUpper(vuln.Severity)]++
	}

	// Check against thresholds
	thresholds := m.config.BlockThresholds

	// Check critical
	if thresholds.Critical >= 0 && severityCounts["CRITICAL"] > thresholds.Critical {
		return true, fmt.Sprintf("Package has %d CRITICAL vulnerabilities (threshold: %d)",
			severityCounts["CRITICAL"], thresholds.Critical), nil
	}

	// Check high
	if thresholds.High >= 0 && severityCounts["HIGH"] > thresholds.High {
		return true, fmt.Sprintf("Package has %d HIGH vulnerabilities (threshold: %d)",
			severityCounts["HIGH"], thresholds.High), nil
	}

	// Check medium
	if thresholds.Medium >= 0 && severityCounts["MEDIUM"] > thresholds.Medium {
		return true, fmt.Sprintf("Package has %d MEDIUM vulnerabilities (threshold: %d)",
			severityCounts["MEDIUM"], thresholds.Medium), nil
	}

	// Check low
	if thresholds.Low >= 0 && severityCounts["LOW"] > thresholds.Low {
		return true, fmt.Sprintf("Package has %d LOW vulnerabilities (threshold: %d)",
			severityCounts["LOW"], thresholds.Low), nil
	}

	// Check block on severity
	if m.config.BlockOnSeverity != "" && m.config.BlockOnSeverity != "none" {
		severity := strings.ToUpper(m.config.BlockOnSeverity)

		// Block if any vulnerabilities at or above the specified severity exist
		switch severity {
		case "CRITICAL":
			if severityCounts["CRITICAL"] > 0 {
				return true, fmt.Sprintf("Package has CRITICAL vulnerabilities"), nil
			}
		case "HIGH":
			if severityCounts["CRITICAL"] > 0 || severityCounts["HIGH"] > 0 {
				return true, fmt.Sprintf("Package has HIGH or CRITICAL vulnerabilities"), nil
			}
		case "MEDIUM":
			if severityCounts["CRITICAL"] > 0 || severityCounts["HIGH"] > 0 || severityCounts["MEDIUM"] > 0 {
				return true, fmt.Sprintf("Package has MEDIUM, HIGH, or CRITICAL vulnerabilities"), nil
			}
		case "LOW":
			if len(result.Vulnerabilities) > 0 {
				return true, fmt.Sprintf("Package has vulnerabilities"), nil
			}
		}
	}

	return false, "", nil
}

// UpdateDatabases updates vulnerability databases for all scanners
func (m *Manager) UpdateDatabases(ctx context.Context) error {
	if !m.enabled {
		return nil
	}

	log.Info().Msg("Updating vulnerability databases")

	for _, scanner := range m.scanners {
		if updater, ok := scanner.(DatabaseUpdater); ok {
			if err := updater.UpdateDatabase(ctx); err != nil {
				log.Error().
					Err(err).
					Str("scanner", scanner.Name()).
					Msg("Failed to update database")
				return err
			}
		}
	}

	log.Info().Msg("Vulnerability databases updated successfully")
	return nil
}

// Health checks health of all scanners
func (m *Manager) Health(ctx context.Context) error {
	if !m.enabled {
		return nil
	}

	for _, scanner := range m.scanners {
		if err := scanner.Health(ctx); err != nil {
			return fmt.Errorf("scanner %s health check failed: %w", scanner.Name(), err)
		}
	}
	return nil
}
