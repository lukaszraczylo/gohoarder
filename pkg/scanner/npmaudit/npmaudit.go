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
	defer os.RemoveAll(tmpDir)

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

	// Run npm audit
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json", "--package-lock-only")
	cmd.Dir = packageDir
	output, _ := cmd.CombinedOutput() // npm audit returns non-zero when vulns found

	// Parse npm audit output
	var auditResult NpmAuditResult
	if len(output) > 0 {
		if err := json.Unmarshal(output, &auditResult); err != nil {
			log.Warn().Err(err).Msg("Failed to parse npm audit output")
			// Return clean result on parse error
			return s.emptyResult(registry, packageName, version), nil
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
	AuditReportVersion int                           `json:"auditReportVersion"`
	Vulnerabilities    map[string]NpmVulnerability   `json:"vulnerabilities"`
	Metadata           NpmAuditMetadata              `json:"metadata"`
}

type NpmVulnerability struct {
	Name         string                 `json:"name"`
	Severity     string                 `json:"severity"`
	Via          string                 `json:"via"`
	Effects      []string               `json:"effects"`
	Range        string                 `json:"range"`
	FixAvailable interface{}            `json:"fixAvailable"`
	URL          string                 `json:"url"`
	References   []NpmReference         `json:"references"`
}

type NpmReference struct {
	URL string `json:"url"`
}

type NpmAuditMetadata struct {
	Vulnerabilities NpmVulnCounts `json:"vulnerabilities"`
	Dependencies    int           `json:"dependencies"`
}

type NpmVulnCounts struct {
	Info      int `json:"info"`
	Low       int `json:"low"`
	Moderate  int `json:"moderate"`
	High      int `json:"high"`
	Critical  int `json:"critical"`
	Total     int `json:"total"`
}
