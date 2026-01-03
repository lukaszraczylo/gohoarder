package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// ScannerName is the name of this scanner
const ScannerName = "grype"

// Scanner implements the Grype vulnerability scanner
type Scanner struct {
	config config.GrypeConfig
}

// New creates a new Grype scanner
func New(cfg config.GrypeConfig) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// Scan scans a package using Grype
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Str("version", version).
		Str("file", filePath).
		Msg("Starting Grype scan")

	// Run grype scan
	cmd := exec.CommandContext(ctx, "grype", filePath, "-o", "json", "-q")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Grype returns non-zero exit code when vulnerabilities are found
		// Only treat it as error if we got no output
		if len(output) == 0 {
			return nil, fmt.Errorf("grype scan failed: %w (output: %s)", err, string(output))
		}
	}

	// Parse Grype JSON output
	var grypeResult GrypeResult
	if err := json.Unmarshal(output, &grypeResult); err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	// Convert to our format
	result := s.convertGrypeResult(&grypeResult, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("Grype scan completed")

	return result, nil
}

// Health checks if Grype is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "grype", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("grype not available: %w", err)
	}
	return nil
}

// UpdateDatabase updates Grype's vulnerability database
func (s *Scanner) UpdateDatabase(ctx context.Context) error {
	log.Info().Str("scanner", ScannerName).Msg("Updating Grype database")

	cmd := exec.CommandContext(ctx, "grype", "db", "update")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update grype database: %w (output: %s)", err, string(output))
	}

	log.Info().Str("scanner", ScannerName).Msg("Grype database updated successfully")
	return nil
}

// convertGrypeResult converts Grype output to our ScanResult format
func (s *Scanner) convertGrypeResult(grypeResult *GrypeResult, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	// Process each vulnerability match
	for _, match := range grypeResult.Matches {
		// Normalize severity
		normalizedSeverity := metadata.NormalizeSeverity(match.Vulnerability.Severity)

		// Count by severity
		severityCounts[normalizedSeverity]++

		// Extract fixed version
		fixedIn := ""
		if match.Vulnerability.Fix.State == "fixed" {
			for _, version := range match.Vulnerability.Fix.Versions {
				if fixedIn == "" {
					fixedIn = version
				}
			}
		}

		// Add to vulnerabilities list
		vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
			ID:          match.Vulnerability.ID,
			Severity:    normalizedSeverity,
			Title:       match.Vulnerability.ID, // Grype doesn't have separate title
			Description: match.Vulnerability.Description,
			References:  match.Vulnerability.URLs,
			FixedIn:     fixedIn,
		})
	}

	// Determine overall status
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
			"grype_version":   grypeResult.Descriptor.Version,
		},
	}
}

// GrypeResult represents Grype JSON output structure
type GrypeResult struct {
	Source     GrypeSource     `json:"source"`
	Descriptor GrypeDescriptor `json:"descriptor"`
	Matches    []GrypeMatch    `json:"matches"`
}

type GrypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GrypeSource struct {
	Target map[string]interface{} `json:"target"`
	Type   string                 `json:"type"`
}

type GrypeMatch struct {
	Artifact      GrypeArtifact      `json:"artifact"`
	Vulnerability GrypeVulnerability `json:"vulnerability"`
}

type GrypeVulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	URLs        []string `json:"urls"`
	Fix         GrypeFix `json:"fix"`
}

type GrypeFix struct {
	State    string   `json:"state"`
	Versions []string `json:"versions"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}
