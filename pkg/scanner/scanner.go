// Package scanner orchestrates pluggable vulnerability scanners and
// records their results against cached packages.
package scanner

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"slices"
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
	DetailInfrastructureError = scanerr.DetailInfrastructure

	defaultScanRetryInterval = 5 * time.Minute
	maxScanRetries           = 6
)

// FileSource returns a readable local copy of a stored package for a retry, plus its cleanup.
type FileSource func(ctx context.Context, registry, packageName, version string) (path string, cleanup func(), err error)

// SetFileSource lets a retry re-read the stored blob when the file its first scan used is gone,
// as with remote storage whose scan source is a temp file removed after the first attempt.
func (m *Manager) SetFileSource(fs FileSource) {
	m.stateMu.Lock()
	m.fileSource = fs
	m.stateMu.Unlock()
}

func (m *Manager) currentFileSource() FileSource {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	return m.fileSource
}

// healthTTL bounds how often /health forks each scanner's version command; under scan load one round took over a second.
const healthTTL = 30 * time.Second

type healthCache struct {
	at     time.Time
	err    error
	states []ScannerStatus
	mu     sync.Mutex
}

// ScannerStatus is one scanner's last health probe.
type ScannerStatus struct {
	Name    string
	Version string // empty when the scanner does not report one
	Healthy bool
}

// versioned is implemented by scanners that learn their version during a health probe.
type versioned interface{ Version() string }

// Manager manages multiple security scanners
type Manager struct {
	health        healthCache
	metadataStore metadata.MetadataStore
	broadcaster   events.Broadcaster
	retryTimers   map[string]*time.Timer
	fileSource    FileSource
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
		source := m.fileSource
		m.stateMu.Unlock()

		ctx := context.Background()
		path := filePath
		if _, statErr := os.Stat(filePath); statErr != nil && source != nil {
			fresh, cleanup, err := source(ctx, registry, packageName, version)
			if err != nil {
				log.Warn().Err(err).Str("package", packageName).Int("attempt", attempt).Msg("Scan retry could not re-read package")
				return
			}
			defer cleanup()
			path = fresh
		}
		if err := m.scan(ctx, registry, packageName, version, path, attempt); err != nil {
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

	scanVersion := m.scanVersion(ctx, registry, packageName, version)

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

		result, err := scanner.Scan(ctx, registry, packageName, scanVersion, filePath)
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

		// A scanner that returns an error-status result failed exactly like one
		// that returns an error: another scanner's verdict still stands.
		if result.Status == metadata.ScanStatusError {
			log.Error().
				Str("scanner", scanner.Name()).
				Str("package", packageName).
				Interface("details", result.Details).
				Msg("Scanner returned an error result")
			if infra, _ := result.Details[DetailInfrastructureError].(bool); infra {
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
	// The store finds the package by its cache version, not the release version.
	mergedResult.PackageVersion = version

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

// scanVersion is the version scanners are asked about. PyPI artifacts are cached
// under their file name; the release version is on the package row.
func (m *Manager) scanVersion(ctx context.Context, registry, packageName, version string) string {
	pkg, err := m.metadataStore.GetPackage(ctx, registry, packageName, version)
	if err != nil || pkg == nil || pkg.ReleaseVersion == "" {
		return version
	}
	return pkg.ReleaseVersion
}

// succeeded drops error-status results; a failed scanner leaves no trace in the merge.
func succeeded(results []*metadata.ScanResult, names []string) ([]*metadata.ScanResult, []string) {
	okResults := make([]*metadata.ScanResult, 0, len(results))
	okNames := make([]string, 0, len(results))
	for i, r := range results {
		if r.Status == metadata.ScanStatusError {
			continue
		}
		okResults = append(okResults, r)
		okNames = append(okNames, names[i])
	}
	return okResults, okNames
}

// mergeResults merges and deduplicates scan results from multiple scanners
func (m *Manager) mergeResults(results []*metadata.ScanResult, scannerNames []string) *metadata.ScanResult {
	if len(results) == 0 {
		return nil
	}

	results, scannerNames = succeeded(results, scannerNames)

	// Use first result as base, or the failure itself when none succeeded
	if len(results) == 0 {
		return &metadata.ScanResult{
			Status:          metadata.ScanStatusError,
			Vulnerabilities: make([]metadata.Vulnerability, 0),
			Details:         map[string]interface{}{"error": "all scanners failed"},
		}
	}
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

	findings := newFindingSet()
	severityCounts := make(map[string]int)

	// Merge vulnerabilities from all scanners; one advisory reported under different ids is one finding.
	for i, result := range results {
		scannerName := scannerNames[i]

		// Track scanner details
		merged.Details[scannerName] = result.Details

		for _, vuln := range result.Vulnerabilities {
			vuln.DetectedBy = []string{scannerName}
			findings.add(vuln)
		}

		// Update status to worst case: vulnerable > pending > clean.
		// Error results never reach this loop (see succeeded).
		switch result.Status {
		case metadata.ScanStatusVulnerable:
			merged.Status = metadata.ScanStatusVulnerable
		case metadata.ScanStatusPending:
			if merged.Status != metadata.ScanStatusVulnerable {
				merged.Status = metadata.ScanStatusPending
			}
		}
	}

	// Convert to a slice and count severities
	for _, vuln := range findings.list() {
		merged.Vulnerabilities = append(merged.Vulnerabilities, vuln)
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

// severityRank orders severities; unknown ones rank 0.
func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MODERATE", "MEDIUM": // MEDIUM is the older name
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// findingSet merges findings that share any id or alias.
type findingSet struct {
	byID  map[string]int
	items []*metadata.Vulnerability
}

func newFindingSet() *findingSet { return &findingSet{byID: make(map[string]int)} }

// add inserts vuln, or folds it into the findings that already carry one of its ids.
func (fs *findingSet) add(vuln metadata.Vulnerability) {
	ids := vuln.IDs()
	target := -1
	for _, id := range ids {
		i, ok := fs.byID[id]
		if !ok {
			continue
		}
		if target < 0 {
			target = i
		} else if i != target {
			// The new finding links two findings seen so far: they are one advisory.
			fs.fold(target, i)
		}
	}
	if target < 0 {
		fs.items = append(fs.items, &vuln)
		target = len(fs.items) - 1
	} else {
		fs.fold(target, -1, vuln)
	}
	for _, id := range fs.items[target].IDs() {
		fs.byID[id] = target
	}
}

// fold merges items[from] (or extra, when from is negative) into items[into].
func (fs *findingSet) fold(into, from int, extra ...metadata.Vulnerability) {
	dst := fs.items[into]
	var srcs []metadata.Vulnerability
	if from >= 0 {
		srcs = append(srcs, *fs.items[from])
		fs.items[from] = nil
	} else {
		srcs = extra
	}
	for _, src := range srcs {
		mergeFinding(dst, src)
	}
	for id, i := range fs.byID {
		if from >= 0 && i == from {
			fs.byID[id] = into
		}
	}
}

// list returns the merged findings in the order they were first seen.
func (fs *findingSet) list() []metadata.Vulnerability {
	out := make([]metadata.Vulnerability, 0, len(fs.items))
	for _, v := range fs.items {
		if v != nil {
			out = append(out, *v)
		}
	}
	return out
}

// mergeFinding folds src into dst: scanners, ids, the worse severity, references and the fix.
func mergeFinding(dst *metadata.Vulnerability, src metadata.Vulnerability) {
	for _, name := range src.DetectedBy {
		if !slices.Contains(dst.DetectedBy, name) {
			dst.DetectedBy = append(dst.DetectedBy, name)
		}
	}

	// A CVE id is the one people search for, so it leads whichever scanner saw it first.
	id, aliases := dst.ID, append(slices.Clone(dst.Aliases), src.ID)
	aliases = append(aliases, src.Aliases...)
	if !metadata.IsCVE(id) && metadata.IsCVE(src.ID) {
		id = src.ID
		aliases = append(aliases, dst.ID)
	}
	dst.ID = id
	dst.Aliases = metadata.NormalizeAliases(id, aliases...)

	if severityRank(src.Severity) > severityRank(dst.Severity) {
		dst.Severity = src.Severity
	}
	for _, ref := range src.References {
		if !slices.Contains(dst.References, ref) {
			dst.References = append(dst.References, ref)
		}
	}
	if dst.FixedIn == "" && src.FixedIn != "" {
		dst.FixedIn = src.FixedIn
	}
	if dst.Title == "" {
		dst.Title = src.Title
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
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

	bypassName := normalizeBypassPackageName(registry, packageName)
	releaseKey := m.releaseVersionKey(ctx, registry, packageName, version, bypassName)
	if packageBypassed(registry, bypassName, version, releaseKey, bypasses) {
		return false, "", nil
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
			return m.missingScanDecision(registry, packageName, version)
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

	infra, _ := result.Details[DetailInfrastructureError].(bool)
	return m.evaluateScan(registry, packageName, version, releaseKey, bypasses, scanFacts{
		status:  result.Status,
		infra:   infra,
		vulns:   result.Vulnerabilities,
		hasList: true,
	})
}

// missingScanDecision is the verdict for a package flagged scanned that has no scan record.
func (m *Manager) missingScanDecision(registry, packageName, version string) (bool, string, error) {
	if !m.config.FailClosed && m.isInflight(scanKey(registry, packageName, version)) {
		return false, "", nil
	}
	return true, "no scan available - fail closed", nil
}

// packageBypassed reports whether an active admin bypass covers the whole package.
func packageBypassed(registry, bypassName, version, releaseKey string, bypasses []*metadata.CVEBypass) bool {
	return packageBypass(registry, bypassName, version, releaseKey, bypasses) != nil
}

// packageBypass returns the active admin bypass that covers the whole package, or nil.
func packageBypass(registry, bypassName, version, releaseKey string, bypasses []*metadata.CVEBypass) *metadata.CVEBypass {
	packageKey := fmt.Sprintf("%s/%s@%s", registry, bypassName, version)
	packageKeyNoVersion := fmt.Sprintf("%s/%s", registry, bypassName)
	for _, bypass := range bypasses {
		if bypass.Type == metadata.BypassTypePackage && bypass.Active {
			if bypass.Target == packageKey || bypass.Target == packageKeyNoVersion || (releaseKey != "" && bypass.Target == releaseKey) {
				log.Info().
					Str("package", packageKey).
					Str("bypass_id", bypass.ID).
					Str("reason", bypass.Reason).
					Time("expires_at", bypass.ExpiresAt).
					Msg("Package bypassed by admin")
				return bypass
			}
		}
	}
	return nil
}

// cveBypasses maps upper-cased CVE ids to the active bypass that applies to this package.
func cveBypasses(registry, bypassName, version, releaseKey string, bypasses []*metadata.CVEBypass) map[string]*metadata.CVEBypass {
	packageKey := fmt.Sprintf("%s/%s@%s", registry, bypassName, version)
	packageKeyNoVersion := fmt.Sprintf("%s/%s", registry, bypassName)
	out := make(map[string]*metadata.CVEBypass)
	for _, bypass := range bypasses {
		if bypass.Type != metadata.BypassTypeCVE || !bypass.Active {
			continue
		}
		if bypass.AppliesTo != "" && bypass.AppliesTo != packageKey && bypass.AppliesTo != packageKeyNoVersion && (releaseKey == "" || bypass.AppliesTo != releaseKey) {
			continue
		}
		out[strings.ToUpper(bypass.Target)] = bypass
	}
	return out
}

// scanFacts is what the blocking policy needs to know about one scan.
type scanFacts struct {
	counts  map[string]int // per-severity counts, used when hasList is false
	status  metadata.ScanStatus
	vulns   []metadata.Vulnerability
	total   int  // findings when the list is not loaded
	infra   bool // the scan failed on infrastructure, not on the package
	hasList bool // vulns is the full list, so CVE bypasses can be applied
}

// evaluateScan applies bypasses and thresholds to one scan.
func (m *Manager) evaluateScan(registry, packageName, version, releaseKey string, bypasses []*metadata.CVEBypass, f scanFacts) (bool, string, error) {
	// If the scan itself errored (all scanners failed for this package),
	// block. A scan-error record means we don't actually know whether the
	// package is safe.
	if f.status == metadata.ScanStatusError {
		if f.infra && !m.config.FailClosed {
			log.Warn().Str("package", packageName).Msg("Scan failed on infrastructure, serving package; scan will be retried")
			return false, "", nil
		}
		return true, "scan failed - fail closed", nil
	}

	bypassedCVEs := cveBypasses(registry, normalizeBypassPackageName(registry, packageName), version, releaseKey, bypasses)

	// Count vulnerabilities by severity, excluding bypassed CVEs
	severityCounts := f.counts
	remaining := f.total
	if f.hasList {
		severityCounts = make(map[string]int)
		remaining = 0
		for _, vuln := range f.vulns {
			// Check if this CVE is bypassed
			if bypass, ok := metadata.BypassFor(bypassedCVEs, vuln); ok {
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
			remaining++
		}
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
			if remaining > 0 {
				return true, "Package has vulnerabilities", nil
			}
		}
	}

	return false, "", nil
}

// ScanDecision pairs a package's latest scan with the blocking verdict.
type ScanDecision struct {
	Summary *metadata.ScanSummary
	// Bypass is the active admin bypass that applied to this package, if any.
	Bypass  *metadata.CVEBypass
	Reason  string
	Blocked bool
}

// ScanDecisions judges scanned packages in a constant number of statements. A nil
// packageIDs judges every scanned package. The verdicts equal CheckVulnerabilities.
func (m *Manager) ScanDecisions(ctx context.Context, packageIDs []string) ([]ScanDecision, error) {
	var bypasses []*metadata.CVEBypass
	if m.enabled {
		var err error
		if bypasses, err = m.metadataStore.GetActiveCVEBypasses(ctx); err != nil {
			log.Warn().Err(err).Msg("Failed to get CVE bypasses, continuing without bypasses")
			bypasses = nil
		}
	}
	// Per-CVE bypasses need the vulnerability ids; counts alone decide otherwise.
	withList := false
	for _, b := range bypasses {
		if b.Type == metadata.BypassTypeCVE && b.Active {
			withList = true
			break
		}
	}

	summaries, err := m.metadataStore.GetScanSummaries(ctx, packageIDs, withList)
	if err != nil {
		return nil, err
	}
	decisions := make([]ScanDecision, 0, len(summaries))
	for _, sum := range summaries {
		d := ScanDecision{Summary: sum}
		if m.enabled {
			d.Blocked, d.Reason, d.Bypass = m.judgeSummary(sum, bypasses, withList)
		}
		decisions = append(decisions, d)
	}
	return decisions, nil
}

func (m *Manager) judgeSummary(sum *metadata.ScanSummary, bypasses []*metadata.CVEBypass, withList bool) (bool, string, *metadata.CVEBypass) {
	bypassName := normalizeBypassPackageName(sum.Registry, sum.Name)
	releaseKey := ""
	if sum.ReleaseVersion != "" {
		releaseKey = fmt.Sprintf("%s/%s@%s", sum.Registry, bypassName, sum.ReleaseVersion)
	}
	if b := packageBypass(sum.Registry, bypassName, sum.Version, releaseKey, bypasses); b != nil {
		return false, "", b
	}
	if !sum.HasScan {
		blocked, reason, _ := m.missingScanDecision(sum.Registry, sum.Name, sum.Version)
		return blocked, reason, nil
	}
	infra, _ := sum.Details[DetailInfrastructureError].(bool)
	facts := scanFacts{status: sum.Status, infra: infra, total: sum.Total, hasList: withList, vulns: sum.Vulnerabilities}
	if !withList {
		facts.counts = map[string]int{
			"CRITICAL": sum.Critical, "HIGH": sum.High, "MODERATE": sum.Moderate, "LOW": sum.Low,
		}
	}
	blocked, reason, _ := m.evaluateScan(sum.Registry, sum.Name, sum.Version, releaseKey, bypasses, facts)
	var applied *metadata.CVEBypass
	if withList {
		covered := cveBypasses(sum.Registry, bypassName, sum.Version, releaseKey, bypasses)
		for _, v := range sum.Vulnerabilities {
			if b, ok := metadata.BypassFor(covered, v); ok {
				applied = b
				break
			}
		}
	}
	return blocked, reason, applied
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

	m.health.mu.Lock()
	defer m.health.mu.Unlock()
	m.refreshHealth(ctx)
	return m.health.err
}

// Statuses reports each registered scanner's health from the same 30 s cache as Health.
func (m *Manager) Statuses(ctx context.Context) []ScannerStatus {
	if !m.enabled {
		return nil
	}

	m.health.mu.Lock()
	defer m.health.mu.Unlock()
	m.refreshHealth(ctx)
	return slices.Clone(m.health.states)
}

// refreshHealth re-probes the scanners when the cached result is older than healthTTL; the caller holds health.mu.
func (m *Manager) refreshHealth(ctx context.Context) {
	if !m.health.at.IsZero() && time.Since(m.health.at) < healthTTL {
		return
	}
	states, err := m.checkScanners(ctx)
	if ctx.Err() != nil {
		m.health.err, m.health.states = err, states
		return
	}
	m.health.at, m.health.err, m.health.states = time.Now(), err, states
}

// checkScanners probes every scanner and returns the first failure, so one broken scanner does not hide the rest.
func (m *Manager) checkScanners(ctx context.Context) ([]ScannerStatus, error) {
	var first error
	states := make([]ScannerStatus, 0, len(m.scanners))
	for _, scanner := range m.scanners {
		err := scanner.Health(ctx)
		st := ScannerStatus{Name: scanner.Name(), Healthy: err == nil}
		if v, ok := scanner.(versioned); ok {
			st.Version = v.Version()
		}
		states = append(states, st)
		if err != nil && first == nil {
			first = fmt.Errorf("scanner %s health check failed: %w", scanner.Name(), err)
		}
	}
	return states, first
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
