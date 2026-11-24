// Package grype wraps the Anchore `grype` CLI to scan packages for
// known vulnerabilities.
package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/gomodule"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanver"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// ScannerName is the name of this scanner
const ScannerName = "grype"

// Scanner implements the Grype vulnerability scanner
type Scanner struct {
	version scanver.Cache
	config  config.GrypeConfig
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

	target := purl(registry, packageName, version)
	if target == "" {
		target = filePath
	}
	cmd := exec.CommandContext(ctx, "grype", target, "-o", "json", "-q") // #nosec G204 -- target is a purl or the stored artifact path
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil && len(output) == 0 {
		return nil, fmt.Errorf("grype scan failed: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	grypeResult, err := parse(output)
	if err != nil {
		return nil, err
	}

	// Convert to our format
	result := s.convertGrypeResult(grypeResult, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("Grype scan completed")

	return result, nil
}

// purl names the package for grype. A bare npm, PyPI or Go archive has no lockfile or installed
// metadata, so grype catalogs nothing in it and reports clean; a purl is matched against the
// database directly. Empty means no purl can be built.
func purl(registry, name, version string) string {
	if name == "" || version == "" {
		return ""
	}
	version = strings.ReplaceAll(version, "+", "%2B")
	switch registry {
	case "npm":
		return "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + version
	case "go":
		return "pkg:golang/" + gomodule.Path(name) + "@" + version
	case "pypi":
		return "pkg:pypi/" + strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(name)) + "@" + version
	}
	return ""
}

func parse(output []byte) (*GrypeResult, error) {
	var res GrypeResult
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}
	return &res, nil
}

// Health checks if Grype is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "grype", "version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("grype not available: %w", err)
	}
	s.version.Record(string(output))
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
			Aliases:     metadata.NormalizeAliases(match.Vulnerability.ID, grypeAliases(match)...),
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
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"` // a string for file, directory and purl sources, an object for images
}

type GrypeMatch struct {
	Artifact               GrypeArtifact      `json:"artifact"`
	Vulnerability          GrypeVulnerability `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVuln `json:"relatedVulnerabilities"`
}

// GrypeRelatedVuln is another id of the matched advisory, such as the CVE of a GHSA match.
type GrypeRelatedVuln struct {
	ID string `json:"id"`
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

// Version returns the version the last successful health check reported.
func (s *Scanner) Version() string { return s.version.Version() }

// grypeAliases lists the ids grype relates to a match, plus any named by its advisory links.
func grypeAliases(match GrypeMatch) []string {
	out := make([]string, 0, len(match.RelatedVulnerabilities))
	for _, rel := range match.RelatedVulnerabilities {
		out = append(out, rel.ID)
	}
	return append(out, metadata.ExtractAdvisoryIDs(match.Vulnerability.URLs...)...)
}
