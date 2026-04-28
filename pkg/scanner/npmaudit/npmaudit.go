// Package npmaudit wraps the `npm audit` CLI to surface vulnerability
// findings for npm packages.
package npmaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// ScannerName is the name of this scanner
const ScannerName = "npm-audit"

// Scanner implements the npm audit vulnerability scanner
type Scanner struct {
	config config.NpmAuditConfig
}

// New creates a new npm audit scanner
func New(cfg config.NpmAuditConfig) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// Scan scans an npm package using npm audit
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	// Only scan npm packages
	if registry != "npm" {
		return &metadata.ScanResult{
			ID:                 uuid.New().String(),
			Registry:           registry,
			PackageName:        packageName,
			PackageVersion:     version,
			Scanner:            ScannerName,
			ScannedAt:          time.Now(),
			Status:             metadata.ScanStatusClean,
			VulnerabilityCount: 0,
			Vulnerabilities:    []metadata.Vulnerability{},
			Details: map[string]interface{}{
				"skipped": "npm-audit only supports npm packages",
			},
		}, nil
	}

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Str("version", version).
		Msg("Starting npm audit scan")

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "npm-audit-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Extract the .tgz file
	if err := s.extractTgz(filePath, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to extract tgz: %w", err)
	}

	// Find the package directory (usually "package/")
	packageDir := filepath.Join(tmpDir, "package")
	if _, err := os.Stat(packageDir); os.IsNotExist(err) {
		// Try the tmpDir itself
		packageDir = tmpDir
	}

	// npm tarballs ship only package.json — there is no lockfile. We must
	// generate one before `npm audit` can resolve the dependency tree.
	// NOTE: this performs network egress (npm registry lookups for
	// transitive deps). Acceptable here because the scanner runs server-
	// side and the operator already trusts upstream resolution to cache
	// the package; we use --ignore-scripts to avoid running install hooks.
	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Msg("Generating package-lock.json for npm audit (network egress)")

	installCmd := exec.CommandContext(ctx, "npm", "install",
		"--package-lock-only",
		"--omit=dev",
		"--ignore-scripts",
		"--no-audit",
	)
	installCmd.Dir = packageDir
	if installOut, err := installCmd.CombinedOutput(); err != nil {
		log.Warn().
			Err(err).
			Str("package", packageName).
			Str("output", string(installOut)).
			Msg("npm install --package-lock-only failed; returning scan-error")
		return s.scanErrorResult(registry, packageName, version,
			fmt.Sprintf("npm install --package-lock-only failed: %v", err)), nil
	}

	// Run npm audit against the freshly generated lockfile.
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Dir = packageDir
	output, _ := cmd.CombinedOutput() // npm audit returns non-zero when vulns found

	// Parse npm audit output
	var auditResult NpmAuditResult
	if len(output) > 0 {
		if err := json.Unmarshal(output, &auditResult); err != nil {
			log.Warn().Err(err).Msg("Failed to parse npm audit output")
			// Parse failure means we couldn't determine vulnerability state — fail closed.
			return s.scanErrorResult(registry, packageName, version,
				fmt.Sprintf("failed to parse npm audit output: %v", err)), nil
		}
	}

	// Convert to our format
	result := s.convertResult(&auditResult, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("npm audit scan completed")

	return result, nil
}

// Health checks if npm is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "npm", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm not available: %w", err)
	}
	return nil
}

// extractTgz extracts a .tgz file
func (s *Scanner) extractTgz(tgzPath, destDir string) error {
	cmd := exec.Command("tar", "-xzf", tgzPath, "-C", destDir)
	return cmd.Run()
}

// emptyResult returns an empty scan result

// scanErrorResult returns a result marked as scan-error so the manager merge
// and CheckVulnerabilities can fail closed. Use this when the scan could not
// complete and we therefore have no signal about vulnerabilities.
func (s *Scanner) scanErrorResult(registry, packageName, version, reason string) *metadata.ScanResult {
	return &metadata.ScanResult{
		ID:                 uuid.New().String(),
		Registry:           registry,
		PackageName:        packageName,
		PackageVersion:     version,
		Scanner:            ScannerName,
		ScannedAt:          time.Now(),
		Status:             metadata.ScanStatusError,
		VulnerabilityCount: 0,
		Vulnerabilities:    []metadata.Vulnerability{},
		Details: map[string]interface{}{
			"error": reason,
		},
	}
}

// convertResult converts npm audit output to our ScanResult format
func (s *Scanner) convertResult(auditResult *NpmAuditResult, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	// Process vulnerabilities from the audit result
	for _, vuln := range auditResult.Vulnerabilities {
		// Normalize severity
		normalizedSeverity := metadata.NormalizeSeverity(vuln.Severity)
		severityCounts[normalizedSeverity]++

		// Get references
		refs := make([]string, 0)
		if vuln.URL != "" {
			refs = append(refs, vuln.URL)
		}
		for _, ref := range vuln.References {
			if ref.URL != "" {
				refs = append(refs, ref.URL)
			}
		}

		// Get fixed version
		fixedIn := ""
		if vuln.FixAvailable != nil {
			fixedIn = fmt.Sprintf("%v", vuln.FixAvailable)
		}

		vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
			ID:          vuln.Via,
			Severity:    normalizedSeverity,
			Title:       vuln.Name,
			Description: vuln.Name,
			References:  refs,
			FixedIn:     fixedIn,
		})
	}

	status := metadata.ScanStatusClean
	if len(vulnerabilities) > 0 {
		status = metadata.ScanStatusVulnerable
	}

	return &metadata.ScanResult{
		ID:                 uuid.New().String(),
		Registry:           registry,
		PackageName:        packageName,
		PackageVersion:     version,
		Scanner:            ScannerName,
		ScannedAt:          time.Now(),
		Status:             status,
		VulnerabilityCount: len(vulnerabilities),
		Vulnerabilities:    vulnerabilities,
		Details: map[string]interface{}{
			"severity_counts": severityCounts,
		},
	}
}

// NpmAuditResult represents npm audit JSON output
type NpmAuditResult struct {
	Vulnerabilities    map[string]NpmVulnerability `json:"vulnerabilities"`
	Metadata           NpmAuditMetadata            `json:"metadata"`
	AuditReportVersion int                         `json:"auditReportVersion"`
}

type NpmVulnerability struct {
	Name         string         `json:"name"`
	Severity     string         `json:"severity"`
	Via          string         `json:"via"`
	Effects      []string       `json:"effects"`
	Range        string         `json:"range"`
	FixAvailable interface{}    `json:"fixAvailable"`
	URL          string         `json:"url"`
	References   []NpmReference `json:"references"`
}

type NpmReference struct {
	URL string `json:"url"`
}

type NpmAuditMetadata struct {
	Vulnerabilities NpmVulnCounts `json:"vulnerabilities"`
	Dependencies    int           `json:"dependencies"`
}

type NpmVulnCounts struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
	Total    int `json:"total"`
}
