package vcs

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ModuleBuilder builds Go module artifacts from source
type ModuleBuilder struct{}

// NewModuleBuilder creates a new module builder
func NewModuleBuilder() *ModuleBuilder {
	return &ModuleBuilder{}
}

// ModuleInfo represents Go module version metadata (.info file)
type ModuleInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// BuildModuleZip creates a Go module zip from source directory
// Follows the Go module zip format specification: https://go.dev/ref/mod#zip-files
func (b *ModuleBuilder) BuildModuleZip(ctx context.Context, srcPath, modulePath, version string) (io.ReadCloser, error) {
	log.Debug().
		Str("src_path", srcPath).
		Str("module", modulePath).
		Str("version", version).
		Msg("Building module zip")

	// Create in-memory zip
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Collect all files to include in zip
	files, err := b.collectFiles(srcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	// Sort files for deterministic zip
	sort.Strings(files)

	// Add files to zip with proper prefix
	prefix := fmt.Sprintf("%s@%s/", modulePath, version)
	for _, relPath := range files {
		if err := b.addFileToZip(zipWriter, srcPath, relPath, prefix); err != nil {
			zipWriter.Close()
			return nil, fmt.Errorf("failed to add file %s: %w", relPath, err)
		}
	}

	if err := zipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zip writer: %w", err)
	}

	log.Debug().
		Str("module", modulePath).
		Str("version", version).
		Int("files", len(files)).
		Int("size", buf.Len()).
		Msg("Successfully built module zip")

	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// collectFiles walks the source directory and collects files to include
func (b *ModuleBuilder) collectFiles(srcPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip .git directory
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			// Skip vendor directory (per Go module zip spec)
			if info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(srcPath, path)
		if err != nil {
			return err
		}

		// Skip hidden files (except .gitignore, etc. if needed)
		if strings.HasPrefix(filepath.Base(relPath), ".") && relPath != ".gitignore" {
			return nil
		}

		// Include file
		files = append(files, relPath)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// addFileToZip adds a single file to the zip archive
func (b *ModuleBuilder) addFileToZip(zipWriter *zip.Writer, srcPath, relPath, prefix string) error {
	// Create zip header
	header := &zip.FileHeader{
		Name:   prefix + filepath.ToSlash(relPath),
		Method: zip.Deflate,
	}

	// Get file info for permissions
	fullPath := filepath.Join(srcPath, relPath)
	info, err := os.Stat(fullPath)
	if err != nil {
		return err
	}

	// Set modification time to a fixed value for deterministic zips
	// Go uses the timestamp from the version info
	header.Modified = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	header.SetMode(info.Mode())

	// Create file in zip
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	// Copy file contents
	file, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(writer, file); err != nil {
		return err
	}

	return nil
}

// GenerateModInfo creates .info file (JSON metadata)
func (b *ModuleBuilder) GenerateModInfo(ctx context.Context, srcPath, version string) ([]byte, error) {
	// Get commit timestamp from git
	timestamp, err := b.getGitCommitTime(srcPath)
	if err != nil {
		// Fallback to current time if git info not available
		log.Warn().Err(err).Msg("Failed to get git commit time, using current time")
		timestamp = time.Now()
	}

	info := ModuleInfo{
		Version: version,
		Time:    timestamp,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal module info: %w", err)
	}

	return data, nil
}

// getGitCommitTime retrieves the commit timestamp from git
func (b *ModuleBuilder) getGitCommitTime(repoPath string) (time.Time, error) {
	cmd := exec.Command("git", "log", "-1", "--format=%cI")
	cmd.Dir = repoPath

	output, err := cmd.Output()
	if err != nil {
		return time.Time{}, err
	}

	// Parse ISO 8601 timestamp
	timestamp, err := time.Parse(time.RFC3339, strings.TrimSpace(string(output)))
	if err != nil {
		return time.Time{}, err
	}

	return timestamp, nil
}

// ExtractGoMod extracts go.mod content
func (b *ModuleBuilder) ExtractGoMod(ctx context.Context, srcPath string) ([]byte, error) {
	goModPath := filepath.Join(srcPath, "go.mod")

	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	// Validate go.mod (basic check)
	if !strings.Contains(string(data), "module ") {
		return nil, fmt.Errorf("invalid go.mod: missing module directive")
	}

	return data, nil
}

// ValidateModule performs basic validation on the module
func (b *ModuleBuilder) ValidateModule(ctx context.Context, srcPath, expectedModulePath string) error {
	// Read go.mod
	goModData, err := b.ExtractGoMod(ctx, srcPath)
	if err != nil {
		return err
	}

	// Extract module path from go.mod
	lines := strings.Split(string(goModData), "\n")
	var declaredModulePath string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			declaredModulePath = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			break
		}
	}

	if declaredModulePath == "" {
		return fmt.Errorf("go.mod missing module declaration")
	}

	// Check if module path matches (allow version suffixes)
	if !strings.HasPrefix(expectedModulePath, declaredModulePath) {
		return fmt.Errorf("module path mismatch: expected %s, got %s", expectedModulePath, declaredModulePath)
	}

	return nil
}
