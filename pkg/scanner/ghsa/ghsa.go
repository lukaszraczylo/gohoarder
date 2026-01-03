package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
)

// ScannerName is the name of this scanner
const ScannerName = "github-advisory-database"

// Scanner implements the GitHub Advisory Database vulnerability scanner
type Scanner struct {
	httpClient *http.Client
	config     config.GHSAConfig
}

// New creates a new GitHub Advisory Database scanner
func New(cfg config.GHSAConfig) *Scanner {
	return &Scanner{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// Scan scans a package using GitHub Advisory Database API
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Str("version", version).
		Str("registry", registry).
		Msg("Starting GitHub Advisory Database scan")

	// Map registry to GitHub ecosystem
	ecosystem := s.mapRegistryToEcosystem(registry)
	if ecosystem == "" {
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
				"skipped": fmt.Sprintf("GitHub Advisory Database does not support registry: %s", registry),
			},
		}, nil
	}

	// Query GitHub Advisory Database
	advisories, err := s.queryAdvisories(ctx, ecosystem, packageName)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query GitHub Advisory Database")
		return s.emptyResult(registry, packageName, version), nil
	}

	// Filter advisories that affect this version
	affectedAdvisories := s.filterAffectedAdvisories(advisories, version)

	// Convert to our format
	result := s.convertResult(affectedAdvisories, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("GitHub Advisory Database scan completed")

	return result, nil
}

// Health checks if GitHub API is accessible
func (s *Scanner) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/advisories", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	if s.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.Token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("github advisory database not accessible: %w", err)
	}
	defer resp.Body.Close() // #nosec G104 -- Cleanup, error not critical

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api returned status: %d", resp.StatusCode)
	}

	return nil
}

// mapRegistryToEcosystem maps our registry names to GitHub ecosystem names
func (s *Scanner) mapRegistryToEcosystem(registry string) string {
	mapping := map[string]string{
		"npm":   "npm",
		"pypi":  "pip",
		"go":    "go",
		"maven": "maven",
		"nuget": "nuget",
		"cargo": "cargo",
		"pub":   "pub",
	}
	return mapping[strings.ToLower(registry)]
}

// queryAdvisories queries GitHub Advisory Database for a package
func (s *Scanner) queryAdvisories(ctx context.Context, ecosystem, packageName string) ([]GHSAAdvisory, error) {
	url := fmt.Sprintf("https://api.github.com/advisories?ecosystem=%s&affects=%s&per_page=100", ecosystem, packageName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	if s.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.Token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query advisories: %w", err)
	}
	defer resp.Body.Close() // #nosec G104 -- Cleanup, error not critical

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github api returned status %d: %s", resp.StatusCode, string(body))
	}

	var advisories []GHSAAdvisory
	if err := json.NewDecoder(resp.Body).Decode(&advisories); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return advisories, nil
}

// filterAffectedAdvisories filters advisories that affect the given version
func (s *Scanner) filterAffectedAdvisories(advisories []GHSAAdvisory, version string) []GHSAAdvisory {
	// Check if this version is affected
	// GitHub API already filters by package, but we need to check version ranges
	// For now, we'll include all advisories that match the package
	// A more sophisticated implementation would parse version ranges
	affected := append([]GHSAAdvisory(nil), advisories...)

	return affected
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

// convertResult converts GitHub Advisory Database results to our ScanResult format
func (s *Scanner) convertResult(advisories []GHSAAdvisory, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	for _, advisory := range advisories {
		// Normalize severity
		normalizedSeverity := metadata.NormalizeSeverity(advisory.Severity)
		severityCounts[normalizedSeverity]++

		// Extract references
		refs := make([]string, 0)
		if advisory.HTMLURL != "" {
			refs = append(refs, advisory.HTMLURL)
		}
		for _, ref := range advisory.References {
			if ref.URL != "" {
				refs = append(refs, ref.URL)
			}
		}

		// Get fixed versions
		fixedIn := ""
		for _, vuln := range advisory.Vulnerabilities {
			if vuln.FirstPatchedVersion != nil && vuln.FirstPatchedVersion.Identifier != "" {
				fixedIn = vuln.FirstPatchedVersion.Identifier
				break
			}
		}

		vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
			ID:          advisory.GHSAID,
			Severity:    normalizedSeverity,
			Title:       advisory.Summary,
			Description: advisory.Description,
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

// GHSAAdvisory represents a GitHub Security Advisory
type GHSAAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           string              `json:"cve_id"`
	Summary         string              `json:"summary"`
	Description     string              `json:"description"`
	Severity        string              `json:"severity"`
	HTMLURL         string              `json:"html_url"`
	PublishedAt     string              `json:"published_at"`
	UpdatedAt       string              `json:"updated_at"`
	References      []GHSAReference     `json:"references"`
	Vulnerabilities []GHSAVulnerability `json:"vulnerabilities"`
}

type GHSAReference struct {
	URL string `json:"url"`
}

type GHSAVulnerability struct {
	FirstPatchedVersion *GHSAPatchVersion `json:"first_patched_version"`
	Package             GHSAPackage       `json:"package"`
	VulnerableVersions  string            `json:"vulnerable_version_range"`
}

type GHSAPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type GHSAPatchVersion struct {
	Identifier string `json:"identifier"`
}
