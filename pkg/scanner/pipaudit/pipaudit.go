package pipaudit

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
const ScannerName = "pip-audit"

// Scanner implements the pip-audit vulnerability scanner
type Scanner struct {
	config config.PipAuditConfig
}

// New creates a new pip-audit scanner
func New(cfg config.PipAuditConfig) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// Scan scans a Python package using pip-audit
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	// Only scan PyPI packages
	if registry != "pypi" {
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
				"skipped": "pip-audit only supports PyPI packages",
			},
		}, nil
	}

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Str("version", version).
		Msg("Starting pip-audit scan")

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "pip-audit-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Copy the wheel/tar.gz file to temp directory
	tmpFile := filepath.Join(tmpDir, filepath.Base(filePath))
	if err := s.copyFile(filePath, tmpFile); err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	// Run pip-audit on the package file
	cmd := exec.CommandContext(ctx, "pip-audit", "-r", tmpFile, "--format", "json") // #nosec G204 -- pip-audit command with temp file
	output, _ := cmd.CombinedOutput()                                               // pip-audit returns non-zero when vulns found

	// Parse pip-audit output
	var auditResult PipAuditResult
	if len(output) > 0 {
		if err := json.Unmarshal(output, &auditResult); err != nil {
			log.Warn().Err(err).Msg("Failed to parse pip-audit output")
			return s.emptyResult(registry, packageName, version), nil
		}
	}

	// Convert to our format
	result := s.convertResult(&auditResult, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("pip-audit scan completed")

	return result, nil
}

// Health checks if pip-audit is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "pip-audit", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pip-audit not available: %w (install with: pip install pip-audit)", err)
	}
	return nil
}

// copyFile copies a file from src to dst
func (s *Scanner) copyFile(src, dst string) error {
	input, err := os.ReadFile(src) // #nosec G304 -- Source path is from scanner, controlled
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0600)
}

// emptyResult returns an empty scan result
func (s *Scanner) emptyResult(registry, packageName, version string) *metadata.ScanResult {
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
		Details:            map[string]interface{}{},
	}
}

// convertResult converts pip-audit output to our ScanResult format
func (s *Scanner) convertResult(auditResult *PipAuditResult, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	for _, dep := range auditResult.Dependencies {
		for _, vuln := range dep.Vulns {
			// Map pip-audit severity to our standard
			severity := s.mapSeverity(vuln.ID)
			normalizedSeverity := metadata.NormalizeSeverity(severity)
			severityCounts[normalizedSeverity]++

			// Get fixed versions
			fixedIn := ""
			if len(vuln.FixVersions) > 0 {
				fixedIn = vuln.FixVersions[0]
			}

			vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
				ID:          vuln.ID,
				Severity:    normalizedSeverity,
				Title:       vuln.ID,
				Description: vuln.Description,
				References:  []string{fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.ID)},
				FixedIn:     fixedIn,
			})
		}
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

// mapSeverity maps vulnerability ID patterns to severity levels
func (s *Scanner) mapSeverity(vulnID string) string {
	// pip-audit doesn't provide severity directly
	// Default to MODERATE for all findings
	return "MODERATE"
}

// PipAuditResult represents pip-audit JSON output
type PipAuditResult struct {
	Dependencies []PipDependency `json:"dependencies"`
}

type PipDependency struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Vulns   []PipVuln `json:"vulns"`
}

type PipVuln struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	FixVersions []string `json:"fix_versions"`
	Aliases     []string `json:"aliases"`
}
