package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// Store implements a file-based metadata store
type Store struct {
	basePath string
	mu       sync.RWMutex
}

// Config holds file store configuration
type Config struct {
	Path string
}

// New creates a new file-based metadata store
func New(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		cfg.Path = "./metadata"
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create metadata directory: %w", err)
	}

	log.Info().
		Str("path", cfg.Path).
		Msg("File-based metadata store initialized")

	return &Store{
		basePath: cfg.Path,
	}, nil
}

// SavePackage saves package metadata
func (s *Store) SavePackage(ctx context.Context, pkg *metadata.Package) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create registry directory
	regDir := filepath.Join(s.basePath, pkg.Registry)
	if err := os.MkdirAll(regDir, 0755); err != nil {
		return err
	}

	// Save to file
	filename := filepath.Join(regDir, fmt.Sprintf("%s-%s.json", pkg.Name, pkg.Version))
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// GetPackage retrieves package metadata
func (s *Store) GetPackage(ctx context.Context, registry, name, version string) (*metadata.Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filename := filepath.Join(s.basePath, registry, fmt.Sprintf("%s-%s.json", name, version))
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var pkg metadata.Package
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	return &pkg, nil
}

// ListPackages lists all packages
func (s *Store) ListPackages(ctx context.Context, opts *metadata.ListOptions) ([]*metadata.Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var packages []*metadata.Package

	// Walk through all files
	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		var pkg metadata.Package
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil // Skip invalid JSON
		}

		packages = append(packages, &pkg)
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Apply pagination if options provided
	if opts != nil {
		if opts.Offset >= len(packages) {
			return []*metadata.Package{}, nil
		}

		end := opts.Offset + opts.Limit
		if end > len(packages) {
			end = len(packages)
		}

		return packages[opts.Offset:end], nil
	}

	return packages, nil
}

// DeletePackage deletes package metadata
func (s *Store) DeletePackage(ctx context.Context, registry, name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.basePath, registry, fmt.Sprintf("%s-%s.json", name, version))
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// SaveScanResult saves scan result
func (s *Store) SaveScanResult(ctx context.Context, result *metadata.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create scans directory
	scanDir := filepath.Join(s.basePath, "scans", result.Registry, result.PackageName)
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return err
	}

	// Save to file with timestamp
	timestamp := time.Now().Unix()
	filename := filepath.Join(scanDir, fmt.Sprintf("%s-%d.json", result.PackageVersion, timestamp))
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// UpdateDownloadCount increments download counter
func (s *Store) UpdateDownloadCount(ctx context.Context, registry, name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load package
	pkg, err := s.GetPackage(ctx, registry, name, version)
	if err != nil || pkg == nil {
		return err
	}

	// Increment counter
	pkg.DownloadCount++
	pkg.LastAccessed = time.Now()

	// Save back
	return s.SavePackage(ctx, pkg)
}

// GetStats returns statistics for a registry
func (s *Store) GetStats(ctx context.Context, registry string) (*metadata.Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &metadata.Stats{
		Registry:    registry,
		LastUpdated: time.Now(),
	}

	// Walk through files and calculate stats
	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var pkg metadata.Package
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}

		// Filter by registry if specified
		if registry != "" && pkg.Registry != registry {
			return nil
		}

		stats.TotalPackages++
		stats.TotalSize += pkg.Size
		stats.TotalDownloads += pkg.DownloadCount

		if pkg.SecurityScanned {
			stats.ScannedPackages++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return stats, nil
}

// GetScanResult retrieves latest scan result
func (s *Store) GetScanResult(ctx context.Context, registry, name, version string) (*metadata.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scanDir := filepath.Join(s.basePath, "scans", registry, name)
	pattern := filepath.Join(scanDir, fmt.Sprintf("%s-*.json", version))

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	if len(matches) == 0 {
		return nil, nil
	}

	// Get the latest file
	latestFile := matches[len(matches)-1]
	data, err := os.ReadFile(latestFile)
	if err != nil {
		return nil, err
	}

	var result metadata.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Count returns total number of packages
func (s *Store) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" && filepath.Dir(path) != filepath.Join(s.basePath, "scans") {
			count++
		}

		return nil
	})

	if err != nil {
		return 0, err
	}

	return count, nil
}

// Health checks if the store is healthy
func (s *Store) Health(ctx context.Context) error {
	// Check if directory is accessible
	_, err := os.Stat(s.basePath)
	return err
}

// SaveCVEBypass saves a CVE bypass (admin only)
func (s *Store) SaveCVEBypass(ctx context.Context, bypass *metadata.CVEBypass) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create bypasses directory
	bypassesDir := filepath.Join(s.basePath, "bypasses")
	if err := os.MkdirAll(bypassesDir, 0755); err != nil {
		return err
	}

	// Save to file
	filename := filepath.Join(bypassesDir, fmt.Sprintf("%s.json", bypass.ID))
	data, err := json.MarshalIndent(bypass, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// GetActiveCVEBypasses retrieves all active (non-expired) CVE bypasses
func (s *Store) GetActiveCVEBypasses(ctx context.Context) ([]*metadata.CVEBypass, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bypassesDir := filepath.Join(s.basePath, "bypasses")
	var bypasses []*metadata.CVEBypass
	now := time.Now()

	// Read all bypass files
	err := filepath.Walk(bypassesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // bypasses directory doesn't exist yet
			}
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var bypass metadata.CVEBypass
		if err := json.Unmarshal(data, &bypass); err != nil {
			log.Warn().Err(err).Str("file", path).Msg("Failed to unmarshal bypass")
			return nil
		}

		// Only include active and non-expired bypasses
		if bypass.Active && bypass.ExpiresAt.After(now) {
			bypasses = append(bypasses, &bypass)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return bypasses, nil
}

// ListCVEBypasses lists all CVE bypasses (including expired)
func (s *Store) ListCVEBypasses(ctx context.Context, opts *metadata.BypassListOptions) ([]*metadata.CVEBypass, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bypassesDir := filepath.Join(s.basePath, "bypasses")
	var bypasses []*metadata.CVEBypass
	now := time.Now()

	// Read all bypass files
	err := filepath.Walk(bypassesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // bypasses directory doesn't exist yet
			}
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var bypass metadata.CVEBypass
		if err := json.Unmarshal(data, &bypass); err != nil {
			log.Warn().Err(err).Str("file", path).Msg("Failed to unmarshal bypass")
			return nil
		}

		// Apply filters if options provided
		if opts != nil {
			if opts.Type != "" && bypass.Type != opts.Type {
				return nil
			}

			if !opts.IncludeExpired && bypass.ExpiresAt.Before(now) {
				return nil
			}

			if opts.ActiveOnly && !bypass.Active {
				return nil
			}
		}

		bypasses = append(bypasses, &bypass)

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Apply limit and offset if specified
	if opts != nil {
		if opts.Offset > 0 && opts.Offset < len(bypasses) {
			bypasses = bypasses[opts.Offset:]
		} else if opts.Offset >= len(bypasses) {
			return []*metadata.CVEBypass{}, nil
		}

		if opts.Limit > 0 && opts.Limit < len(bypasses) {
			bypasses = bypasses[:opts.Limit]
		}
	}

	return bypasses, nil
}

// DeleteCVEBypass deletes a CVE bypass by ID
func (s *Store) DeleteCVEBypass(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.basePath, "bypasses", fmt.Sprintf("%s.json", id))
	err := os.Remove(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("CVE bypass not found: %s", id)
		}
		return err
	}

	return nil
}

// CleanupExpiredBypasses removes expired bypasses
func (s *Store) CleanupExpiredBypasses(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bypassesDir := filepath.Join(s.basePath, "bypasses")
	count := 0
	now := time.Now()

	// Read all bypass files
	err := filepath.Walk(bypassesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // bypasses directory doesn't exist yet
			}
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var bypass metadata.CVEBypass
		if err := json.Unmarshal(data, &bypass); err != nil {
			log.Warn().Err(err).Str("file", path).Msg("Failed to unmarshal bypass")
			return nil
		}

		// Delete if expired
		if bypass.ExpiresAt.Before(now) {
			if err := os.Remove(path); err != nil {
				log.Warn().Err(err).Str("file", path).Msg("Failed to delete expired bypass")
			} else {
				count++
			}
		}

		return nil
	})

	if err != nil {
		return 0, err
	}

	return count, nil
}

// Close closes the store
func (s *Store) Close() error {
	// Nothing to close for file-based store
	return nil
}
