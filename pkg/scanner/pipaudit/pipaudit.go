// Package pipaudit wraps the `pip-audit` CLI to scan Python wheels and
// source distributions for known vulnerabilities.
package pipaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Copy the wheel/tar.gz file to temp directory
	tmpFile := filepath.Join(tmpDir, filepath.Base(filePath))
	if err := s.copyFile(filePath, tmpFile); err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	// Build the appropriate pip-audit invocation based on artifact type.
	// `-r` expects requirements.txt — passing a wheel/tarball there is wrong.
	// Wheels can be scanned directly via positional arg. Source distributions
	// (tarballs) need to be extracted; if they contain a pyproject.toml we
	// can scan that, otherwise we fail closed.
	cmd, prepErr := s.buildAuditCmd(ctx, tmpDir, tmpFile)
	if prepErr != nil {
		log.Warn().
			Err(prepErr).
			Str("package", packageName).
			Str("version", version).
			Msg("pip-audit could not prepare input artifact, returning scan-error")
		return s.scanErrorResult(registry, packageName, version, prepErr.Error()), nil
	}
	output, _ := cmd.CombinedOutput() // pip-audit returns non-zero when vulns found

	// Parse pip-audit output
	var auditResult PipAuditResult
	if len(output) > 0 {
		if err := json.Unmarshal(output, &auditResult); err != nil {
			log.Warn().Err(err).Msg("Failed to parse pip-audit output")
			// Parse failure → no signal → fail closed.
			return s.scanErrorResult(registry, packageName, version,
				fmt.Sprintf("failed to parse pip-audit output: %v", err)), nil
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

// buildAuditCmd constructs the right pip-audit command for the input artifact.
//
//   - .whl  -> pip-audit <wheel> --format json
//   - .tar.gz / .tgz / .zip (sdist) -> extract; if pyproject.toml exists
//     run `pip-audit --pyproject <pyproject> --format json`; otherwise error.
//
// extractDir is used as a workspace for sdist extraction.
func (s *Scanner) buildAuditCmd(ctx context.Context, extractDir, artifact string) (*exec.Cmd, error) {
	lower := strings.ToLower(artifact)
	switch {
	case strings.HasSuffix(lower, ".whl"):
		// pip-audit can scan a wheel directly via positional argument.
		return exec.CommandContext(ctx, "pip-audit", artifact, "--format", "json"), nil // #nosec G204 -- artifact path is in controlled tmp dir

	case strings.HasSuffix(lower, ".tar.gz"),
		strings.HasSuffix(lower, ".tgz"),
		strings.HasSuffix(lower, ".zip"):
		// Source distributions must be unpacked first.
		sdistDir := filepath.Join(extractDir, "sdist")
		if err := os.MkdirAll(sdistDir, 0o750); err != nil {
			return nil, fmt.Errorf("create sdist dir: %w", err)
		}
		if err := s.extractSdist(artifact, sdistDir); err != nil {
			return nil, fmt.Errorf("extract sdist: %w", err)
		}
		pyproject, err := findPyProject(sdistDir)
		if err != nil {
			return nil, fmt.Errorf("no pyproject.toml in sdist: %w", err)
		}
		return exec.CommandContext(ctx, "pip-audit", "--pyproject", pyproject, "--format", "json"), nil // #nosec G204 -- pyproject path under controlled tmp dir

	default:
		return nil, fmt.Errorf("unsupported pip artifact extension: %s", filepath.Base(artifact))
	}
}

// extractSdist unpacks a Python source distribution into destDir.
func (s *Scanner) extractSdist(archive, destDir string) error {
	lower := strings.ToLower(archive)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return exec.Command("tar", "-xzf", archive, "-C", destDir).Run()
	case strings.HasSuffix(lower, ".zip"):
		return exec.Command("unzip", "-q", archive, "-d", destDir).Run()
	default:
		return fmt.Errorf("unknown archive type: %s", archive)
	}
}

// findPyProject returns the path to a pyproject.toml within root, walking
// one level deep (sdists typically extract to <pkg>-<ver>/).
func findPyProject(root string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == "pyproject.toml" {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", fmt.Errorf("pyproject.toml not found under %s", root)
	}
	return found, nil
}

// scanErrorResult returns a result marked scan-error so manager merge and
// CheckVulnerabilities can fail closed when this scanner could not run.
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

// emptyResult returns an empty scan result

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
