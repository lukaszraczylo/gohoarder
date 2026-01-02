package govulncheck

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// ScannerName is the name of this scanner
const ScannerName = "govulncheck"

// Scanner implements the govulncheck vulnerability scanner for Go modules
type Scanner struct {
	config config.GovulncheckConfig
}

// New creates a new govulncheck scanner
func New(cfg config.GovulncheckConfig) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// Scan scans a Go module using govulncheck
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	// Only scan Go packages
	if registry != "go" {
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
				"skipped": "govulncheck only supports Go modules",
			},
		}, nil
	}

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Str("version", version).
		Msg("Starting govulncheck scan")

	// Create a temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "govulncheck-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract the .zip file
	if err := s.extractZip(filePath, tmpDir); err != nil {
		return nil, fmt.Errorf("failed to extract zip: %w", err)
	}

	// Run govulncheck
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "-mode=binary", tmpDir) // #nosec G204 -- govulncheck command with temp directory
	output, _ := cmd.CombinedOutput()

	// govulncheck returns non-zero when vulnerabilities are found
	// Parse output regardless of error
	var vulns []GovulncheckVuln
	if len(output) > 0 {
		// Parse line-delimited JSON
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var entry GovulncheckEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				log.Warn().Err(err).Str("line", line).Msg("Failed to parse govulncheck line")
				continue
			}
			if entry.Finding != nil && entry.Finding.OSV != "" {
				vulns = append(vulns, GovulncheckVuln{
					OSV:          entry.Finding.OSV,
					FixedVersion: entry.Finding.FixedVersion,
				})
			}
		}
	}

	// Convert to our format
	result := s.convertResult(vulns, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("govulncheck scan completed")

	return result, nil
}

// Health checks if govulncheck is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "govulncheck", "-version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("govulncheck not available: %w (install with: go install golang.org/x/vuln/cmd/govulncheck@latest)", err)
	}
	return nil
}

// extractZip extracts a zip file to destination
func (s *Scanner) extractZip(zipPath, destDir string) error {
	cmd := exec.Command("unzip", "-q", zipPath, "-d", destDir)
	return cmd.Run()
}

// convertResult converts govulncheck findings to our ScanResult format
func (s *Scanner) convertResult(vulns []GovulncheckVuln, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)
	seen := make(map[string]bool)

	for _, vuln := range vulns {
		// Deduplicate by OSV ID
		if seen[vuln.OSV] {
			continue
		}
		seen[vuln.OSV] = true

		// govulncheck doesn't provide severity in output
		// Default to HIGH for found vulnerabilities
		severity := metadata.NormalizeSeverity("HIGH")
		severityCounts[severity]++

		vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
			ID:          vuln.OSV,
			Severity:    severity,
			Title:       vuln.OSV,
			Description: fmt.Sprintf("Vulnerability %s found by govulncheck", vuln.OSV),
			References:  []string{fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSV)},
			FixedIn:     vuln.FixedVersion,
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
			"note":            "govulncheck provides reachability analysis for Go modules",
		},
	}
}

// GovulncheckEntry represents a single line of govulncheck JSON output
type GovulncheckEntry struct {
	Finding *GovulncheckFinding `json:"finding,omitempty"`
}

type GovulncheckFinding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type GovulncheckVuln struct {
	OSV          string
	FixedVersion string
}
