package osv

import (
	"bytes"
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

const (
	// ScannerName is the name of this scanner
	ScannerName = "osv"

	defaultOSVAPIURL = "https://api.osv.dev/v1/query"
)

// Scanner implements the Scanner interface using OSV.dev API
type Scanner struct {
	config     config.OSVConfig
	httpClient *http.Client
}

// OSVRequest represents the request structure for OSV API
type OSVRequest struct {
	Package PackageInfo `json:"package"`
	Version string      `json:"version,omitempty"`
}

// PackageInfo contains package ecosystem and name
type PackageInfo struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"` // npm, PyPI, Go, etc.
}

// OSVResponse represents the response from OSV API
type OSVResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// OSVVulnerability represents a vulnerability in OSV format
type OSVVulnerability struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Severity   []OSVSeverity   `json:"severity,omitempty"`
	References []OSVReference  `json:"references,omitempty"`
	Affected   []OSVAffected   `json:"affected"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
}

// OSVSeverity represents severity information
type OSVSeverity struct {
	Type  string `json:"type"`  // CVSS_V3, etc.
	Score string `json:"score"` // Severity score
}

// OSVReference represents a reference link
type OSVReference struct {
	Type string `json:"type"` // WEB, ADVISORY, etc.
	URL  string `json:"url"`
}

// OSVAffected represents affected package versions
type OSVAffected struct {
	Package           PackageInfo        `json:"package"`
	Ranges            []OSVRange         `json:"ranges,omitempty"`
	Versions          []string           `json:"versions,omitempty"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific,omitempty"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific,omitempty"`
}

// OSVRange represents version ranges
type OSVRange struct {
	Type   string      `json:"type"` // SEMVER, GIT, etc.
	Events []OSVEvent  `json:"events"`
}

// OSVEvent represents version range events
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// New creates a new OSV scanner
func New(cfg config.OSVConfig) *Scanner {
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = defaultOSVAPIURL
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Scanner{
		config: cfg,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the scanner name
func (s *Scanner) Name() string {
	return ScannerName
}

// Scan scans a package for vulnerabilities using OSV.dev API
func (s *Scanner) Scan(ctx context.Context, registry, packageName, version string, filePath string) (*metadata.ScanResult, error) {
	// Convert registry to OSV ecosystem
	ecosystem := s.registryToEcosystem(registry)

	// Build request
	req := OSVRequest{
		Package: PackageInfo{
			Name:      packageName,
			Ecosystem: ecosystem,
		},
		Version: version,
	}

	// Marshal request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV request: %w", err)
	}

	// Create HTTP request
	apiURL := s.config.APIURL
	if apiURL == "" {
		apiURL = defaultOSVAPIURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OSV API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OSV response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var osvResp OSVResponse
	if err := json.Unmarshal(body, &osvResp); err != nil {
		return nil, fmt.Errorf("failed to parse OSV response: %w", err)
	}

	// Convert to metadata.ScanResult
	return s.convertOSVResult(&osvResp, registry, packageName, version), nil
}

// registryToEcosystem converts our registry name to OSV ecosystem
func (s *Scanner) registryToEcosystem(registry string) string {
	switch strings.ToLower(registry) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "cargo", "crates":
		return "crates.io"
	case "rubygems":
		return "RubyGems"
	default:
		return registry
	}
}

// convertOSVResult converts OSV response to metadata.ScanResult
func (s *Scanner) convertOSVResult(osvResp *OSVResponse, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0, len(osvResp.Vulns))
	severityCounts := make(map[string]int)

	for _, vuln := range osvResp.Vulns {
		// Determine severity from various sources
		severity := s.determineSeverity(&vuln)
		severityCounts[severity]++

		// Extract references
		references := make([]string, 0, len(vuln.References))
		for _, ref := range vuln.References {
			references = append(references, ref.URL)
		}

		// Find fixed version
		fixedVersion := s.findFixedVersion(&vuln, version)

		vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
			ID:          vuln.ID,
			Severity:    severity,
			Title:       vuln.Summary,
			Description: vuln.Details,
			References:  references,
			FixedIn:     fixedVersion,
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
		Scanner:            s.Name(),
		ScannedAt:          time.Now(),
		Status:             status,
		VulnerabilityCount: len(vulnerabilities),
		Vulnerabilities:    vulnerabilities,
		Details: map[string]interface{}{
			"ecosystem":       s.registryToEcosystem(registry),
			"severity_counts": severityCounts,
		},
	}
}

// determineSeverity extracts severity from OSV vulnerability
func (s *Scanner) determineSeverity(vuln *OSVVulnerability) string {
	// Try to get severity from CVSS
	for _, sev := range vuln.Severity {
		if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V2" {
			// Parse CVSS score to severity
			score := sev.Score
			if strings.Contains(strings.ToUpper(score), "CRITICAL") {
				return "CRITICAL"
			} else if strings.Contains(strings.ToUpper(score), "HIGH") {
				return "HIGH"
			} else if strings.Contains(strings.ToUpper(score), "MEDIUM") {
				return "MEDIUM"
			} else if strings.Contains(strings.ToUpper(score), "LOW") {
				return "LOW"
			}
		}
	}

	// Check database_specific for severity
	if vuln.DatabaseSpecific != nil {
		if sev, ok := vuln.DatabaseSpecific["severity"].(string); ok {
			return strings.ToUpper(sev)
		}
	}

	// Default to MEDIUM if unknown
	return "MEDIUM"
}

// findFixedVersion extracts the fixed version from OSV affected ranges
func (s *Scanner) findFixedVersion(vuln *OSVVulnerability, currentVersion string) string {
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}

// Health checks if OSV API is reachable
func (s *Scanner) Health(ctx context.Context) error {
	// Make a simple request to check API availability
	apiURL := s.config.APIURL
	if apiURL == "" {
		apiURL = defaultOSVAPIURL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", strings.Replace(apiURL, "/query", "", 1), nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("OSV API not reachable: %w", err)
	}
	defer resp.Body.Close()

	log.Debug().Int("status", resp.StatusCode).Msg("OSV health check passed")
	return nil
}
