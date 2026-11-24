// Package pipaudit wraps the `pip-audit` CLI to scan Python wheels and
// source distributions for known vulnerabilities.
package pipaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanver"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// ScannerName is the name of this scanner
const ScannerName = "pip-audit"

// Scanner implements the pip-audit vulnerability scanner
type Scanner struct {
	version scanver.Cache
	config  config.PipAuditConfig
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

	if !validName.MatchString(packageName) || !validVersion.MatchString(version) {
		return s.scanErrorResult(ctx, registry, packageName, version,
			fmt.Sprintf("not a project name and version: %q %q", packageName, version), ""), nil
	}

	tmpDir, err := os.MkdirTemp("", "pip-audit-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// pip-audit has no wheel or sdist input: its positional argument is a project directory. The
	// release is audited by its pinned name and version. --no-deps and --disable-pip keep it to
	// that release, with no resolution of its dependencies.
	reqFile := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(reqFile, []byte(packageName+"=="+version+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write requirements: %w", err)
	}

	cmd := exec.CommandContext(ctx, "pip-audit", "-r", reqFile, "--no-deps", "--disable-pip", "-f", "json") // #nosec G204 -- name and version are validated, file is in a controlled temp dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, _ := cmd.Output() // pip-audit exits non-zero when it finds vulnerabilities

	var auditResult PipAuditResult
	if err := json.Unmarshal(output, &auditResult); err != nil {
		log.Warn().Err(err).Str("stderr", stderr.String()).Msg("Failed to parse pip-audit output")
		return s.scanErrorResult(ctx, registry, packageName, version,
			fmt.Sprintf("failed to parse pip-audit output: %v: %s", err, strings.TrimSpace(stderr.String())), stderr.String()), nil
	}
	for _, dep := range auditResult.Dependencies {
		if dep.SkipReason != "" {
			// pip-audit exits 0 for a package it could not audit; that is no verdict.
			return s.scanErrorResult(ctx, registry, packageName, version, dep.SkipReason, ""), nil
		}
	}

	result := s.convertResult(&auditResult, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("pip-audit scan completed")

	return result, nil
}

var (
	validName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	validVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+!_-]*$`)
)

// Health checks if pip-audit is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "pip-audit", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("pip-audit not available: %w (install with: pip install pip-audit)", err)
	}
	s.version.Record(string(output))
	return nil
}

// scanErrorResult returns a scan-error result. The manager leaves it out of the merge and counts it
// as an infrastructure failure when the context ended or the tool output shows the network was unreachable.
func (s *Scanner) scanErrorResult(ctx context.Context, registry, packageName, version, reason, toolOutput string) *metadata.ScanResult {
	infra := ctx.Err() != nil || scanerr.NetworkFailure(toolOutput)
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
		Details:            scanerr.ErrorDetails(reason, infra),
	}
}

// convertResult converts pip-audit output to our ScanResult format
func (s *Scanner) convertResult(auditResult *PipAuditResult, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	seen := make(map[string]bool)
	for _, dep := range auditResult.Dependencies {
		for _, vuln := range dep.Vulns {
			// pip-audit lists an advisory once per alias.
			if seen[vuln.ID] {
				continue
			}
			seen[vuln.ID] = true
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
				Aliases:     metadata.NormalizeAliases(vuln.ID, vuln.Aliases...),
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
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	SkipReason string    `json:"skip_reason"`
	Vulns      []PipVuln `json:"vulns"`
}

type PipVuln struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	FixVersions []string `json:"fix_versions"`
	Aliases     []string `json:"aliases"`
}

// Version returns the version the last successful health check reported.
func (s *Scanner) Version() string { return s.version.Version() }
