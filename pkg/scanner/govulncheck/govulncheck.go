// Package govulncheck wraps the `govulncheck` CLI to scan Go modules for
// known vulnerabilities.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/gomodule"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
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

	module := gomodule.Path(packageName)
	if !validModule.MatchString(module) || !validVersion.MatchString(version) {
		return s.errorResult(ctx, registry, packageName, version,
			fmt.Sprintf("not a module path and version: %q %q", module, version), ""), nil
	}

	tmpDir, err := os.MkdirTemp("", "govulncheck-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// govulncheck never reports advisories against the main module of the tree it scans, so
	// scanning the module's own source reports a vulnerable module clean. The module is
	// scanned as a dependency of a wrapper module instead, and the wrapper imports its
	// packages because module-mode scanning only considers modules that provide an import.
	// Resolving the module reaches the module proxy.
	env := append(os.Environ(), "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local", "GOWORK=off")
	goMod := fmt.Sprintf("module gohoarder.audit\n\nrequire %s %s\n", module, version)
	if err = os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write go.mod: %w", err)
	}

	listCmd := exec.CommandContext(ctx, "go", "list", "-e", "-f", listFormat, module+"/...") // #nosec G204 -- module path is validated
	listCmd.Dir = tmpDir
	listCmd.Env = env
	var listErr bytes.Buffer
	listCmd.Stderr = &listErr
	listOut, err := listCmd.Output()
	if err != nil {
		return s.errorResult(ctx, registry, packageName, version,
			fmt.Sprintf("go list failed: %v: %s", err, strings.TrimSpace(listErr.String())), listErr.String()), nil
	}

	imports := importable(string(listOut))
	if len(imports) == 0 {
		return s.skippedResult(registry, packageName, version, "no importable package in module"), nil
	}
	var mainSrc strings.Builder
	mainSrc.WriteString("package main\n\nimport (\n")
	for _, pkg := range imports {
		fmt.Fprintf(&mainSrc, "\t_ %q\n", pkg)
	}
	mainSrc.WriteString(")\n\nfunc main() {}\n")
	if err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainSrc.String()), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write main.go: %w", err)
	}

	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "-scan", "module") // #nosec G204 -- fixed args, cwd is controlled temp dir
	cmd.Dir = tmpDir
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, _ := cmd.Output() // govulncheck -json exits 0 whether or not it finds anything

	vulns, err := parseFindings(output)
	if err != nil {
		return s.errorResult(ctx, registry, packageName, version,
			fmt.Sprintf("govulncheck failed: %v: %s", err, strings.TrimSpace(stderr.String())), stderr.String()), nil
	}

	result := s.convertResult(vulns, registry, packageName, version)

	log.Info().
		Str("scanner", ScannerName).
		Str("package", packageName).
		Int("vulnerabilities", result.VulnerabilityCount).
		Msg("govulncheck scan completed")

	return result, nil
}

// listFormat prints "import-path name go-files cgo-files [ERR]" per package.
const listFormat = "{{.ImportPath}} {{.Name}} {{len .GoFiles}} {{len .CgoFiles}} {{if .Error}}ERR{{end}}"

var (
	validModule  = regexp.MustCompile(`^[A-Za-z0-9._~/-]+$`)
	validVersion = regexp.MustCompile(`^v[0-9A-Za-z.+_-]+$`)
)

// importable lists the packages of `go list` output that another module can import.
func importable(listOut string) []string {
	var pkgs []string
	for _, line := range strings.Split(listOut, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] == "main" || (len(f) > 4 && f[4] == "ERR") {
			continue
		}
		if f[2] == "0" && f[3] == "0" {
			continue
		}
		if hasPathElement(f[0], "internal") || hasPathElement(f[0], "testdata") || hasPathElement(f[0], "vendor") {
			continue
		}
		pkgs = append(pkgs, f[0])
	}
	return pkgs
}

func hasPathElement(importPath, element string) bool {
	return slices.Contains(strings.Split(importPath, "/"), element)
}

// parseFindings reads govulncheck's stream of JSON messages. An output without the config
// message did not come from a completed run.
func parseFindings(output []byte) ([]GovulncheckVuln, error) {
	summaries := make(map[string]string)
	var vulns []GovulncheckVuln
	seen := make(map[string]bool)
	sawConfig := false
	dec := json.NewDecoder(bytes.NewReader(output))
	for {
		var msg GovulncheckEntry
		if err := dec.Decode(&msg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse govulncheck output: %w", err)
		}
		switch {
		case msg.Config != nil:
			sawConfig = true
		case msg.OSV != nil:
			summaries[msg.OSV.ID] = msg.OSV.Summary
		case msg.Finding != nil && msg.Finding.OSV != "" && !seen[msg.Finding.OSV]:
			seen[msg.Finding.OSV] = true
			v := GovulncheckVuln{OSV: msg.Finding.OSV, FixedVersion: msg.Finding.FixedVersion}
			if len(msg.Finding.Trace) > 0 {
				v.Module = msg.Finding.Trace[0].Module
				v.ModuleVersion = msg.Finding.Trace[0].Version
			}
			vulns = append(vulns, v)
		}
	}
	if !sawConfig {
		return nil, errors.New("no config message in output")
	}
	for i := range vulns {
		vulns[i].Summary = summaries[vulns[i].OSV]
	}
	return vulns, nil
}

// Health checks if govulncheck is available
func (s *Scanner) Health(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "govulncheck", "-version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("govulncheck not available: %w (install with: go install golang.org/x/vuln/cmd/govulncheck@latest)", err)
	}
	return nil
}

// errorResult returns a scan-error result. The manager leaves it out of the merge and counts it as
// an infrastructure failure when the context ended or the tool output shows the network was unreachable.
func (s *Scanner) errorResult(ctx context.Context, registry, packageName, version, reason, toolOutput string) *metadata.ScanResult {
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

// skippedResult returns a clean ScanResult marked as skipped with an explanation: the module has
// nothing another module can import, so there is nothing to audit.
func (s *Scanner) skippedResult(registry, packageName, version, reason string) *metadata.ScanResult {
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
			"skipped": reason,
		},
	}
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
			Description: describe(vuln),
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

func describe(v GovulncheckVuln) string {
	desc := v.Summary
	if desc == "" {
		desc = "Vulnerability " + v.OSV
	}
	if v.Module != "" {
		desc += fmt.Sprintf(" (%s@%s)", v.Module, v.ModuleVersion)
	}
	return desc
}

// GovulncheckEntry is one message of govulncheck's JSON stream; exactly one field is set.
type GovulncheckEntry struct {
	Config  *struct{}           `json:"config,omitempty"`
	OSV     *GovulncheckOSV     `json:"osv,omitempty"`
	Finding *GovulncheckFinding `json:"finding,omitempty"`
}

// GovulncheckOSV is the advisory a finding refers to.
type GovulncheckOSV struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type GovulncheckFinding struct {
	OSV          string              `json:"osv"`
	FixedVersion string              `json:"fixed_version,omitempty"`
	Trace        []GovulncheckModule `json:"trace"`
}

// GovulncheckModule is the module a finding is in.
type GovulncheckModule struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

type GovulncheckVuln struct {
	OSV           string
	FixedVersion  string
	Module        string
	ModuleVersion string
	Summary       string
}
