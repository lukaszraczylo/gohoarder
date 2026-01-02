package trivy

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
const ScannerName = "trivy"

// Scanner implements the Scanner interface using Trivy
type Scanner struct {
	config config.TrivyConfig
}

// TrivyResult represents Trivy JSON output structure
type TrivyResult struct {
	SchemaVersion int                  `json:"SchemaVersion"`
	ArtifactName  string               `json:"ArtifactName"`
	ArtifactType  string               `json:"ArtifactType"`
	Metadata      TrivyMetadata        `json:"Metadata"`
	Results       []TrivyVulnResult    `json:"Results"`
}

type TrivyMetadata struct {
	OS           *TrivyOS          `json:"OS,omitempty"`
	RepoTags     []string          `json:"RepoTags,omitempty"`
	RepoDigests  []string          `json:"RepoDigests,omitempty"`
	ImageConfig  *TrivyImageConfig `json:"ImageConfig,omitempty"`
}

type TrivyOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type TrivyImageConfig struct {
	Architecture string `json:"architecture"`
	Created      string `json:"created"`
}

type TrivyVulnResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
	PrimaryURL       string   `json:"PrimaryURL"`
}

// New creates a new Trivy scanner
func New(cfg config.TrivyConfig) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// UpdateDatabase updates Trivy's vulnerability database
func (s *Scanner) UpdateDatabase(ctx context.Context) error {
	log.Info().Msg("Updating Trivy vulnerability database")

	cmd := exec.CommandContext(ctx, "trivy", "image", "--download-db-only")
	if s.config.CacheDB != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("TRIVY_CACHE_DIR=%s", s.config.CacheDB))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update Trivy database: %w (output: %s)", err, string(output))
	}

	log.Info().Msg("Trivy vulnerability database updated successfully")
	return nil
}

// Scan scans a package for vulnerabilities using Trivy
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	// Set timeout
	if s.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.config.Timeout)
		defer cancel()
	}

	// Determine scan type based on registry
	scanType := s.determineScanType(registry, filePath)

	// Build Trivy command
	args := []string{
		scanType,
		"--format", "json",
		"--quiet",
		filePath,
	}

	cmd := exec.CommandContext(ctx, "trivy", args...)

	// Set cache directory if configured
	if s.config.CacheDB != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("TRIVY_CACHE_DIR=%s", s.config.CacheDB))
	}

	// Execute scan
	output, err := cmd.Output()
	if err != nil {
		// Check if it's a timeout
		if ctx.Err() == context.DeadlineExceeded {
			return &metadata.ScanResult{
				ID:              uuid.New().String(),
				Registry:        registry,
				PackageName:     packageName,
				PackageVersion:  version,
				Scanner:         s.Name(),
				ScannedAt:       time.Now(),
				Status:          metadata.ScanStatusError,
				Details: map[string]interface{}{
					"error": "scan timeout",
				},
			}, nil
		}

		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	// Parse Trivy output
	var trivyResult TrivyResult
	if err := json.Unmarshal(output, &trivyResult); err != nil {
		return nil, fmt.Errorf("failed to parse Trivy output: %w", err)
	}

	// Convert to metadata.ScanResult
	return s.convertTrivyResult(&trivyResult, registry, packageName, version), nil
}

// determineScanType determines the appropriate Trivy scan type
func (s *Scanner) determineScanType(registry, filePath string) string {
	// For now, use filesystem scan for packages
	// Container image scanning would need different handling
	ext := strings.ToLower(filePath[strings.LastIndex(filePath, ".")+1:])

	switch registry {
	case "npm":
		return "fs" // Filesystem scan for npm packages
	case "pypi":
		return "fs" // Filesystem scan for Python packages
	case "go":
		return "fs" // Filesystem scan for Go modules
	default:
		// Check file extension
		if ext == "tar" || ext == "tgz" || ext == "gz" {
			return "fs"
		}
		return "fs"
	}
}

// convertTrivyResult converts Trivy result to metadata.ScanResult
func (s *Scanner) convertTrivyResult(trivyResult *TrivyResult, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	// Aggregate all vulnerabilities from all results
	for _, result := range trivyResult.Results {
		for _, vuln := range result.Vulnerabilities {
			// Normalize severity to standard values (CRITICAL, HIGH, MODERATE, LOW)
			normalizedSeverity := metadata.NormalizeSeverity(vuln.Severity)

			// Count by severity
			severityCounts[normalizedSeverity]++

			// Add to vulnerabilities list
			vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
				ID:          vuln.VulnerabilityID,
				Severity:    normalizedSeverity,
				Title:       vuln.Title,
				Description: vuln.Description,
				References:  vuln.References,
				FixedIn:     vuln.FixedVersion,
			})
		}
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
		Scanner:            s.Name(),
		ScannedAt:          time.Now(),
		Status:             status,
		VulnerabilityCount: len(vulnerabilities),
		Vulnerabilities:    vulnerabilities,
		Details: map[string]interface{}{
			"artifact_name": trivyResult.ArtifactName,
			"artifact_type": trivyResult.ArtifactType,
			"severity_counts": severityCounts,
		},
	}
}

// Health checks if Trivy is available and working
func (s *Scanner) Health(ctx context.Context) error {
	// Check if trivy command exists
	cmd := exec.CommandContext(ctx, "trivy", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy not available: %w (output: %s)", err, string(output))
	}

	log.Debug().Str("version", strings.TrimSpace(string(output))).Msg("Trivy health check passed")
	return nil
}
