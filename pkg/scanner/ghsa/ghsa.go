// Package ghsa implements a vulnerability scanner backed by the GitHub
// Security Advisory Database.
package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
	defer func() { _ = resp.Body.Close() }() // #nosec G104 -- Cleanup, error not critical

	// Accept any 2xx or 403 (rate limit) as healthy
	// Rate limits are expected without a GitHub token and shouldn't fail health checks
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		log.Debug().Msg("GitHub API rate limited (expected without token)")
		return nil
	}

	return fmt.Errorf("github api returned status: %d", resp.StatusCode)
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
	endpoint := fmt.Sprintf(
		"https://api.github.com/advisories?ecosystem=%s&affects=%s&per_page=100",
		url.QueryEscape(ecosystem),
		url.QueryEscape(packageName),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
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
	defer func() { _ = resp.Body.Close() }() // #nosec G104 -- Cleanup, error not critical

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

// filterAffectedAdvisories filters advisories that affect the given version.
// Each advisory may have multiple GHSAVulnerability entries; if any of them
// applies to our installed version (per its vulnerable_version_range), the
// advisory is considered affecting.
//
// Fail-closed: if the version or any range cannot be parsed, the advisory is
// included. We err on the side of reporting a possible vulnerability rather
// than silently dropping it.
func (s *Scanner) filterAffectedAdvisories(advisories []GHSAAdvisory, version string) []GHSAAdvisory {
	if version == "" {
		// Without a target version, conservatively include everything.
		return append([]GHSAAdvisory(nil), advisories...)
	}

	out := make([]GHSAAdvisory, 0, len(advisories))
	for _, adv := range advisories {
		if advisoryAffectsVersion(adv, version) {
			out = append(out, adv)
		}
	}
	return out
}

// advisoryAffectsVersion reports whether the given installed version falls
// within any of the advisory's vulnerable version ranges.
func advisoryAffectsVersion(adv GHSAAdvisory, version string) bool {
	// If the advisory carries no per-vuln range info, conservatively include.
	if len(adv.Vulnerabilities) == 0 {
		return true
	}

	for _, v := range adv.Vulnerabilities {
		rangeExpr := strings.TrimSpace(v.VulnerableVersions)
		if rangeExpr == "" {
			// No range — assume affected.
			return true
		}
		matched, ok := versionInRange(version, rangeExpr)
		if !ok {
			// Parse error → fail-closed: include.
			log.Debug().
				Str("ghsa_id", adv.GHSAID).
				Str("range", rangeExpr).
				Str("version", version).
				Msg("Could not parse GHSA vulnerable_version_range, including advisory")
			return true
		}
		if matched {
			return true
		}
	}
	return false
}

// versionInRange reports whether version satisfies expr. Returns (matched, ok)
// where ok=false signals a parse error. Supported forms (comma separated AND):
//
//	"= X"
//	"< X"
//	"<= X"
//	"> X"
//	">= X"
//	">= X, < Y"
//
// All clauses must be satisfied for the range to match.
func versionInRange(version, expr string) (bool, bool) {
	clauses := strings.Split(expr, ",")
	for _, c := range clauses {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		op, bound, ok := splitOpAndVersion(c)
		if !ok {
			return false, false
		}
		cmp, ok := compareVersions(version, bound)
		if !ok {
			return false, false
		}
		switch op {
		case "=", "==":
			if cmp != 0 {
				return false, true
			}
		case "<":
			if cmp >= 0 {
				return false, true
			}
		case "<=":
			if cmp > 0 {
				return false, true
			}
		case ">":
			if cmp <= 0 {
				return false, true
			}
		case ">=":
			if cmp < 0 {
				return false, true
			}
		default:
			return false, false
		}
	}
	return true, true
}

// splitOpAndVersion parses "<op> <version>" pairs (e.g. ">= 1.2.3").
func splitOpAndVersion(clause string) (op, ver string, ok bool) {
	clause = strings.TrimSpace(clause)
	// Longer operators first to avoid prefix shadowing.
	for _, candidate := range []string{">=", "<=", "==", "=", ">", "<"} {
		if strings.HasPrefix(clause, candidate) {
			rest := strings.TrimSpace(strings.TrimPrefix(clause, candidate))
			if rest == "" {
				return "", "", false
			}
			return candidate, rest, true
		}
	}
	return "", "", false
}

// compareVersions compares two dot-separated version strings.
// Returns (cmp, ok). Numeric segments are compared numerically.
// A pre-release suffix (anything after '-' or '+') is treated as lower-priority
// than the same version without one, matching common semver intuition for
// the cases we expect from the GitHub Advisory Database.
func compareVersions(a, b string) (int, bool) {
	aBase, aPre := splitPreRelease(a)
	bBase, bPre := splitPreRelease(b)

	aParts := strings.Split(aBase, ".")
	bParts := strings.Split(bBase, ".")

	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		var err error
		if i < len(aParts) {
			av, err = strconv.Atoi(aParts[i])
			if err != nil {
				return 0, false
			}
		}
		if i < len(bParts) {
			bv, err = strconv.Atoi(bParts[i])
			if err != nil {
				return 0, false
			}
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}

	// Bases equal; compare pre-release. No pre-release > has pre-release.
	switch {
	case aPre == "" && bPre == "":
		return 0, true
	case aPre == "" && bPre != "":
		return 1, true
	case aPre != "" && bPre == "":
		return -1, true
	default:
		return strings.Compare(aPre, bPre), true
	}
}

// splitPreRelease separates "1.2.3-rc1" into ("1.2.3", "rc1"). Build metadata
// after '+' is stripped (per semver).
func splitPreRelease(v string) (base, pre string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "-"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
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
