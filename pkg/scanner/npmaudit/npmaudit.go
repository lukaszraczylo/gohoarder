// Package npmaudit wraps the `npm audit` CLI to surface vulnerability
// findings for npm packages.
package npmaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
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

	tmpDir, err := os.MkdirTemp("", "npm-audit-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err = writeWrapper(tmpDir, packageName, filePath); err != nil {
		return s.scanErrorResult(ctx, registry, packageName, version, fmt.Sprintf("prepare audit project: %v", err), ""), nil
	}

	// npm audit needs a lockfile and a tarball ships none. The tarball is installed into a
	// wrapper project, so its own advisories are audited with its production dependencies, and
	// its devDependencies are never resolved. This step reaches the npm registry.
	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Msg("Generating package-lock.json for npm audit (network egress)")

	installCmd := exec.CommandContext(ctx, "npm", "install", // #nosec G204 -- fixed args
		"--package-lock-only",
		"--omit=dev",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
	)
	installCmd.Dir = tmpDir
	if installOut, installErr := installCmd.CombinedOutput(); installErr != nil {
		log.Warn().
			Err(installErr).
			Str("package", packageName).
			Str("output", string(installOut)).
			Msg("npm install --package-lock-only failed; returning scan-error")
		return s.scanErrorResult(ctx, registry, packageName, version,
			fmt.Sprintf("npm install --package-lock-only failed: %v", installErr), string(installOut)), nil
	}

	cmd := exec.CommandContext(ctx, "npm", "audit", "--omit=dev", "--json") // #nosec G204 -- fixed args
	cmd.Dir = tmpDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, _ := cmd.Output() // npm audit exits non-zero when it finds vulnerabilities

	auditResult, err := parse(output)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse npm audit output")
		return s.scanErrorResult(ctx, registry, packageName, version,
			fmt.Sprintf("failed to parse npm audit output: %v", err), stderr.String()), nil
	}
	if auditResult.Error != nil {
		return s.scanErrorResult(ctx, registry, packageName, version,
			fmt.Sprintf("npm audit failed: %s %s", auditResult.Error.Code, auditResult.Error.Summary), stderr.String()), nil
	}

	result := s.convertResult(auditResult, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("npm audit scan completed")

	return result, nil
}

// wrapperTarball is the archive's name inside the wrapper project.
const wrapperTarball = "artifact.tgz"

// writeWrapper makes dir a project whose only dependency is the archive.
func writeWrapper(dir, packageName, archive string) error {
	src, err := os.Open(archive) // #nosec G304 -- path from the cache, not user input
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	dst, err := root.Create(wrapperTarball)
	if err != nil {
		return err
	}
	if _, err = io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	manifest, err := json.Marshal(map[string]interface{}{
		"name":         "gohoarder-audit",
		"version":      "1.0.0",
		"private":      true,
		"dependencies": map[string]string{packageName: "file:./" + wrapperTarball},
	})
	if err != nil {
		return err
	}
	return root.WriteFile("package.json", manifest, 0o600)
}

// Health checks if npm is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "npm", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm not available: %w", err)
	}
	return nil
}

// scanErrorResult returns a result marked scan-error. The manager leaves it out of the merge
// and counts it as an infrastructure failure when the context ended or the tool output shows
// the network was unreachable.
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

// convertResult converts npm audit output to our ScanResult format
func (s *Scanner) convertResult(auditResult *NpmAuditResult, registry, packageName, version string) *metadata.ScanResult {
	vulnerabilities := make([]metadata.Vulnerability, 0)
	severityCounts := make(map[string]int)

	// Each advisory is listed once, under the package it affects. A string in `via` only says
	// that the package is affected through another one, whose own entry lists the advisory.
	seen := make(map[int]bool)
	names := make([]string, 0, len(auditResult.Vulnerabilities))
	for name := range auditResult.Vulnerabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, via := range auditResult.Vulnerabilities[name].Via {
			adv := via.Advisory
			if adv == nil || seen[adv.Source] {
				continue
			}
			seen[adv.Source] = true
			normalizedSeverity := metadata.NormalizeSeverity(adv.Severity)
			severityCounts[normalizedSeverity]++
			refs := make([]string, 0, 1)
			if adv.URL != "" {
				refs = append(refs, adv.URL)
			}
			vulnerabilities = append(vulnerabilities, metadata.Vulnerability{
				ID:          advisoryID(adv),
				Severity:    normalizedSeverity,
				Title:       adv.Title,
				Description: fmt.Sprintf("%s: %s (affected %s)", adv.Name, adv.Title, adv.Range),
				References:  refs,
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

// advisoryID is the GHSA id from the advisory URL, or the npm advisory number.
func advisoryID(adv *NpmAdvisory) string {
	if i := strings.LastIndex(adv.URL, "/"); i >= 0 && i+1 < len(adv.URL) {
		return adv.URL[i+1:]
	}
	return fmt.Sprintf("npm:%d", adv.Source)
}

func parse(output []byte) (*NpmAuditResult, error) {
	var res NpmAuditResult
	if err := json.Unmarshal(output, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// NpmAuditResult represents `npm audit --json` output (auditReportVersion 2), or its error document.
type NpmAuditResult struct {
	Vulnerabilities map[string]NpmVulnerability `json:"vulnerabilities"`
	Error           *NpmAuditError              `json:"error"`
}

// NpmAuditError is the document npm prints in place of a report, e.g. ENOLOCK.
type NpmAuditError struct {
	Code    string `json:"code"`
	Summary string `json:"summary"`
}

// NpmVulnerability is one affected package.
type NpmVulnerability struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Via      []NpmVia `json:"via"`
}

// NpmVia is a package name (affected through that package) or an advisory.
type NpmVia struct {
	Advisory *NpmAdvisory
	Package  string
}

// UnmarshalJSON accepts both shapes of an element of `via`.
func (v *NpmVia) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &v.Package)
	}
	v.Advisory = &NpmAdvisory{}
	return json.Unmarshal(data, v.Advisory)
}

// NpmAdvisory is a security advisory attached to a package.
type NpmAdvisory struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Severity string `json:"severity"`
	Range    string `json:"range"`
	Source   int    `json:"source"`
}
