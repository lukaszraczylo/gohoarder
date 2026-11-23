// Package scanner orchestrates pluggable vulnerability scanners and
// records their results against cached packages.
package scanner

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	hoardererrors "github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/events"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/ghsa"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/govulncheck"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/grype"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/npmaudit"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/osv"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/pipaudit"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/trivy"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
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

const (
	// DetailInfrastructureError marks a stored scan-error result as caused by
	// scanner infrastructure (timeout, upstream 5xx) rather than by the package.
	DetailInfrastructureError = "infrastructure_error"

	defaultScanRetryInterval = 5 * time.Minute
	maxScanRetries           = 6
)

// Manager manages multiple security scanners
type Manager struct {
	metadataStore metadata.MetadataStore
	broadcaster   events.Broadcaster
	retryTimers   map[string]*time.Timer
	inflight      map[string]int
	scanners      []Scanner
	config        config.SecurityConfig
	bcMu          sync.RWMutex
	stateMu       sync.Mutex
	enabled       bool
	stopped       bool
}

// Enabled reports whether security scanning is on.
func (m *Manager) Enabled() bool {
	return m.enabled
}

// Stop cancels pending scan retries.
func (m *Manager) Stop() {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.stopped = true
	for key, timer := range m.retryTimers {
		timer.Stop()
		delete(m.retryTimers, key)
	}
}

func scanKey(registry, packageName, version string) string {
	return registry + "/" + packageName + "@" + version
}

func (m *Manager) markInflight(key string, delta int) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.inflight[key] += delta
	if m.inflight[key] <= 0 {
		delete(m.inflight, key)
	}
}

func (m *Manager) isInflight(key string) bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.inflight[key] > 0
}

// scheduleRetry rescans a package whose scan failed on infrastructure.
func (m *Manager) scheduleRetry(registry, packageName, version, filePath string, attempt int) {
	interval := m.config.ScanRetryInterval
	if interval <= 0 {
		interval = defaultScanRetryInterval
	}
	key := scanKey(registry, packageName, version)

	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.stopped {
		return
	}
	if old, ok := m.retryTimers[key]; ok {
		old.Stop()
	}
	m.retryTimers[key] = time.AfterFunc(interval, func() {
		m.stateMu.Lock()
		delete(m.retryTimers, key)
		m.stateMu.Unlock()
		if err := m.scan(context.Background(), registry, packageName, version, filePath, attempt); err != nil {
			log.Warn().Err(err).Str("package", packageName).Int("attempt", attempt).Msg("Scan retry failed")
		}
	})
}

// SetBroadcaster wires an events.Broadcaster onto the scanner so scan
// lifecycle events are published. Pass nil to disable broadcasting.
// Safe for concurrent use.
func (m *Manager) SetBroadcaster(b events.Broadcaster) {
	m.bcMu.Lock()
	m.broadcaster = b
	m.bcMu.Unlock()
}

// emit publishes an event via the configured broadcaster, if any.
// Non-blocking: the underlying transport handles overflow by dropping.
func (m *Manager) emit(eventType string, payload map[string]interface{}) {
	m.bcMu.RLock()
	b := m.broadcaster
	m.bcMu.RUnlock()
	if b == nil {
		return
	}
	b.BroadcastEvent(eventType, payload)
}

// New creates a new scanner manager with configured scanners
func New(cfg config.SecurityConfig, metadataStore metadata.MetadataStore) (*Manager, error) {
	manager := &Manager{
		scanners:      make([]Scanner, 0),
		enabled:       cfg.Enabled,
		config:        cfg,
		metadataStore: metadataStore,
		retryTimers:   make(map[string]*time.Timer),
		inflight:      make(map[string]int),
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

	// Initialize Grype scanner
	if cfg.Scanners.Grype.Enabled {
		grypeScanner := grype.New(cfg.Scanners.Grype)
		manager.RegisterScanner(grypeScanner)
		log.Info().Msg("Grype scanner enabled")

		// Update database on startup if configured
		if cfg.UpdateDBOnStartup {
			if err := grypeScanner.UpdateDatabase(context.Background()); err != nil {
				log.Warn().Err(err).Msg("Failed to update Grype database on startup")
			}
		}
	}

	// Initialize govulncheck scanner
	if cfg.Scanners.Govulncheck.Enabled {
		govulncheckScanner := govulncheck.New(cfg.Scanners.Govulncheck)
		manager.RegisterScanner(govulncheckScanner)
		log.Info().Msg("govulncheck scanner enabled")
	}

	// Initialize npm-audit scanner
	if cfg.Scanners.NpmAudit.Enabled {
		npmAuditScanner := npmaudit.New(cfg.Scanners.NpmAudit)
		manager.RegisterScanner(npmAuditScanner)
		log.Info().Msg("npm-audit scanner enabled")
	}

	// Initialize pip-audit scanner
	if cfg.Scanners.PipAudit.Enabled {
		pipAuditScanner := pipaudit.New(cfg.Scanners.PipAudit)
		manager.RegisterScanner(pipAuditScanner)
		log.Info().Msg("pip-audit scanner enabled")
	}

	// Initialize GitHub Advisory Database scanner
	if cfg.Scanners.GHSA.Enabled {
		ghsaScanner := ghsa.New(cfg.Scanners.GHSA)
		manager.RegisterScanner(ghsaScanner)
		log.Info().Msg("GitHub Advisory Database scanner enabled")
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
	return m.scan(ctx, registry, packageName, version, filePath, 0)
}

// scan runs every applicable scanner. attempt is 0 for the first scan and
// counts retries after an infrastructure failure.
func (m *Manager) scan(ctx context.Context, registry, packageName, version string, filePath string, attempt int) error {
	if !m.enabled {
		return nil
	}

	key := scanKey(registry, packageName, version)
	m.markInflight(key, 1)
	defer m.markInflight(key, -1)

	log.Info().
		Str("registry", registry).
		Str("package", packageName).
		Str("version", version).
		Msg("Starting security scan")

	// Collect results from all scanners
	var scanResults []*metadata.ScanResult
	scannerNames := make([]string, 0)
	var infraFailures, otherFailures int

	for _, scanner := range m.scanners {
		// Skip scanners that don't support this registry
		if !m.shouldRunScanner(scanner.Name(), registry) {
			log.Debug().
				Str("scanner", scanner.Name()).
				Str("registry", registry).
				Msg("Skipping scanner - not compatible with registry")
			continue
		}

		result, err := scanner.Scan(ctx, registry, packageName, version, filePath)
		if err != nil {
			log.Error().
				Err(err).
				Str("scanner", scanner.Name()).
				Str("package", packageName).
				Msg("Scanner failed")
			if scanerr.IsInfrastructure(err) {
				infraFailures++
			} else {
				otherFailures++
			}
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

	// If no scanners succeeded, persist a synthetic error result so callers
	// fail closed (no scan == blocked) rather than silently leaving
	// SecurityScanned=false which would allow the package to be served.
	if len(scanResults) == 0 {
		infraOnly := infraFailures > 0 && otherFailures == 0
		if attempt > 0 && !infraOnly {
			// Keep the earlier infrastructure-error result rather than
			// replacing it with a failure the package did not cause.
			return nil
		}
		log.Warn().
			Str("package", packageName).
			Bool("infrastructure", infraOnly).
			Msg("All scanners failed, saving scan-error result")

		errResult := &metadata.ScanResult{
			ID:                 uuid.New().String(),
			Registry:           registry,
			PackageName:        packageName,
			PackageVersion:     version,
			Scanner:            "all",
			ScannedAt:          time.Now(),
			Status:             metadata.ScanStatusError,
			VulnerabilityCount: 0,
			Vulnerabilities:    []metadata.Vulnerability{},
			Details: map[string]interface{}{
				"error":                   "all configured scanners failed for this package",
				DetailInfrastructureError: infraOnly,
			},
		}
		if err := m.metadataStore.SaveScanResult(ctx, errResult); err != nil {
			log.Error().
				Err(err).
				Str("package", packageName).
				Msg("Failed to save scan-error result")
			return err
		}
		m.emit(string(websocket.EventScanComplete), map[string]interface{}{
			"registry":            registry,
			"name":                packageName,
			"version":             version,
			"status":              string(errResult.Status),
			"vulnerability_count": errResult.VulnerabilityCount,
		})
		if infraOnly && attempt < maxScanRetries {
			m.scheduleRetry(registry, packageName, version, filePath, attempt+1)
		}
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

	m.emit(string(websocket.EventScanComplete), map[string]interface{}{
		"registry":            registry,
		"name":                packageName,
		"version":             version,
		"status":              string(mergedResult.Status),
		"vulnerability_count": mergedResult.VulnerabilityCount,
	})

	return nil
}

// mergeResults merges and deduplicates scan results from multiple scanners
func (m *Manager) mergeResults(results []*metadata.ScanResult, scannerNames []string) *metadata.ScanResult {
	if len(results) == 0 {
		return nil
	}

	// Use first result as base
	merged := &metadata.ScanResult{
		ID:              results[0].ID,
		Registry:        results[0].Registry,
		PackageName:     results[0].PackageName,
		PackageVersion:  results[0].PackageVersion,
		Scanner:         strings.Join(scannerNames, "+"), // Combined scanner name
		ScannedAt:       results[0].ScannedAt,
		Status:          metadata.ScanStatusClean,
		Vulnerabilities: make([]metadata.Vulnerability, 0),
		Details:         make(map[string]interface{}),
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

		// Update status to worst case.
		// Order: vulnerable > error > pending > clean. Vulnerable wins because
		// the cache layer must surface the actual vulns. Otherwise, if any
		// scanner errored, propagate so CheckVulnerabilities can fail closed.
		switch result.Status {
		case metadata.ScanStatusVulnerable:
			merged.Status = metadata.ScanStatusVulnerable
		case metadata.ScanStatusError:
			if merged.Status != metadata.ScanStatusVulnerable {
				merged.Status = metadata.ScanStatusError
			}
		case metadata.ScanStatusPending:
			if merged.Status != metadata.ScanStatusVulnerable && merged.Status != metadata.ScanStatusError {
				merged.Status = metadata.ScanStatusPending
			}
		}
	}

	// Convert map to slice and count severities
	for _, vuln := range vulnMap {
		merged.Vulnerabilities = append(merged.Vulnerabilities, *vuln)
		severityCounts[metadata.NormalizeSeverity(vuln.Severity)]++
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
		"MODERATE": 2,
		"MEDIUM":   2, // Support both for backwards compatibility
		"LOW":      1,
		"UNKNOWN":  0,
	}

	v1 := severityOrder[strings.ToUpper(s1)]
	v2 := severityOrder[strings.ToUpper(s2)]

	return v1 - v2
}

// normalizeBypassPackageName reduces a stored package cache key to the
// natural registry/package identifier used in admin bypass targets.
// Go module packages are stored with a cache key of
// "modulePath/@v/version.zip" (and .info/.mod variants); the admin-facing
// target uses the bare module path, e.g. "go/github.com/foo/bar@v1.2.3".
// npm/pypi names are stored unchanged, so this is a no-op for them.
func normalizeBypassPackageName(registry, name string) string {
	if registry == "go" {
		if idx := strings.Index(name, "/@v/"); idx >= 0 {
			return name[:idx]
		}
	}
	return name
}

// releaseVersionKey returns "registry/name@release_version" for packages keyed by file name (PyPI), else "".
func (m *Manager) releaseVersionKey(ctx context.Context, registry, packageName, version, bypassName string) string {
	pkg, err := m.metadataStore.GetPackage(ctx, registry, packageName, version)
	if err != nil || pkg == nil || pkg.ReleaseVersion == "" {
		return ""
	}
	return fmt.Sprintf("%s/%s@%s", registry, bypassName, pkg.ReleaseVersion)
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
	bypassName := normalizeBypassPackageName(registry, packageName)
	packageKey := fmt.Sprintf("%s/%s@%s", registry, bypassName, version)
	packageKeyNoVersion := fmt.Sprintf("%s/%s", registry, bypassName)
	releaseKey := m.releaseVersionKey(ctx, registry, packageName, version, bypassName)

	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypePackage && bypass.Active {
			if bypass.Target == packageKey || bypass.Target == packageKeyNoVersion || (releaseKey != "" && bypass.Target == releaseKey) {
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

	// Get latest scan result.
	// SECURITY: Fail closed when no scan exists or backend errors.
	// Previously this returned (false, "", nil) which allowed unscanned
	// packages through — a fail-open bypass. Cache layer is expected to
	// wait for the initial scan via SecurityScanned flag; once that flag
	// is set, GetScanResult MUST return a record. A missing record at this
	// point indicates either a cleared/lost scan or a transient error;
	// either way we block.
	result, err := m.metadataStore.GetScanResult(ctx, registry, packageName, version)
	if err != nil {
		var hErr *hoardererrors.Error
		if stderrors.As(err, &hErr) && hErr.Code == hoardererrors.ErrCodeNotFound {
			if !m.config.FailClosed && m.isInflight(scanKey(registry, packageName, version)) {
				return false, "", nil
			}
			return true, "no scan available - fail closed", nil
		}
		// Real backend error (DB transient, etc.) — also block.
		log.Warn().
			Err(err).
			Str("package", packageName).
			Msg("Failed to retrieve scan result, failing closed")
		return true, "scan lookup failed - fail closed", nil
	}
	if result == nil {
		// File-backed metadata store returns (nil, nil) on not-found.
		return true, "no scan available - fail closed", nil
	}

	// If the scan itself errored (all scanners failed for this package),
	// block. A scan-error record means we don't actually know whether the
	// package is safe.
	if result.Status == metadata.ScanStatusError {
		if infra, _ := result.Details[DetailInfrastructureError].(bool); infra && !m.config.FailClosed {
			log.Warn().Str("package", packageName).Msg("Scan failed on infrastructure, serving package; scan will be retried")
			return false, "", nil
		}
		return true, "scan failed - fail closed", nil
	}

	// Build set of bypassed CVEs for fast lookup
	bypassedCVEs := make(map[string]*metadata.CVEBypass)
	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypeCVE && bypass.Active {
			// Check if bypass applies to this package (if AppliesTo is set)
			if bypass.AppliesTo != "" && bypass.AppliesTo != packageKey && bypass.AppliesTo != packageKeyNoVersion && (releaseKey == "" || bypass.AppliesTo != releaseKey) {
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
		severityCounts[metadata.NormalizeSeverity(vuln.Severity)]++
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

	// Check moderate (medium)
	moderateCount := severityCounts["MODERATE"] + severityCounts["MEDIUM"] // Support both for backwards compatibility
	if thresholds.Medium >= 0 && moderateCount > thresholds.Medium {
		return true, fmt.Sprintf("Package has %d MODERATE vulnerabilities (threshold: %d)",
			moderateCount, thresholds.Medium), nil
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
				return true, "Package has CRITICAL vulnerabilities", nil
			}
		case "HIGH":
			if severityCounts["CRITICAL"] > 0 || severityCounts["HIGH"] > 0 {
				return true, "Package has HIGH or CRITICAL vulnerabilities", nil
			}
		case "MODERATE", "MEDIUM":
			moderateCount := severityCounts["MODERATE"] + severityCounts["MEDIUM"]
			if severityCounts["CRITICAL"] > 0 || severityCounts["HIGH"] > 0 || moderateCount > 0 {
				return true, "Package has MODERATE, HIGH, or CRITICAL vulnerabilities", nil
			}
		case "LOW":
			if len(result.Vulnerabilities) > 0 {
				return true, "Package has vulnerabilities", nil
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

// shouldRunScanner determines if a scanner should run for a given registry
// Language-specific scanners only run for their target ecosystems
func (m *Manager) shouldRunScanner(scannerName, registry string) bool {
	registry = strings.ToLower(registry)

	// Language-specific scanners - only run for their target registry
	switch scannerName {
	case "govulncheck":
		return registry == "go"
	case "npm-audit":
		return registry == "npm"
	case "pip-audit":
		return registry == "pypi"

	// Multi-ecosystem scanners - run for all registries
	case "trivy", "osv", "grype", "github-advisory-database":
		return true

	// Default: allow scanner to run (for future scanners)
	default:
		return true
	}
}
