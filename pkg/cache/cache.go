package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

// ScannerInterface defines the interface for security scanners
// Defined here to avoid circular dependency with scanner package
type ScannerInterface interface {
	ScanPackage(ctx context.Context, registry, packageName, version string, filePath string) error
	CheckVulnerabilities(ctx context.Context, registry, packageName, version string) (blocked bool, reason string, err error)
}

// AnalyticsInterface defines the interface for analytics tracking
type AnalyticsInterface interface {
	TrackDownload(download analytics.PackageDownload)
}

// Manager coordinates caching operations between storage and metadata
type Manager struct {
	storage   storage.StorageBackend
	metadata  metadata.MetadataStore
	scanner   ScannerInterface
	analytics AnalyticsInterface
	sf        singleflight.Group
	config    Config
	mu        sync.RWMutex
	evicting  bool
}

// Config holds cache manager configuration
type Config struct {
	DefaultTTL        time.Duration // Default TTL for cached packages
	CleanupInterval   time.Duration // How often to run cleanup
	EvictionThreshold float64       // Trigger eviction when usage > threshold (0.0-1.0)
	MaxConcurrent     int           // Max concurrent upstream fetches
}

// CacheEntry represents a cached package
type CacheEntry struct {
	Data         io.ReadCloser
	Package      *metadata.Package
	UpstreamURL  string
	CacheControl string
	FromCache    bool
}

// New creates a new cache manager
func New(storage storage.StorageBackend, metadata metadata.MetadataStore, scanner ScannerInterface, analytics AnalyticsInterface, config Config) (*Manager, error) {
	if storage == nil {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "storage backend is required")
	}

	if metadata == nil {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "metadata store is required")
	}

	// Scanner is optional - can be nil if security scanning is disabled
	if scanner != nil {
		log.Info().Msg("Cache manager initialized with security scanning enabled")
	}

	// Analytics is optional - can be nil if analytics tracking is disabled
	if analytics != nil {
		log.Info().Msg("Cache manager initialized with analytics tracking enabled")
	}

	if config.DefaultTTL == 0 {
		config.DefaultTTL = 7 * 24 * time.Hour // 7 days default
	}

	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour
	}

	if config.EvictionThreshold == 0 {
		config.EvictionThreshold = 0.9 // 90% full
	}

	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 100
	}

	manager := &Manager{
		storage:   storage,
		metadata:  metadata,
		scanner:   scanner,
		analytics: analytics,
		config:    config,
	}

	// Start background cleanup worker
	go manager.cleanupWorker()

	return manager, nil
}

// Get retrieves a package from cache or upstream
func (m *Manager) Get(ctx context.Context, registry, name, version string, fetchFunc func(context.Context) (io.ReadCloser, string, error)) (*CacheEntry, error) {
	// Use singleflight to deduplicate concurrent requests
	key := fmt.Sprintf("%s/%s/%s", registry, name, version)

	result, err, _ := m.sf.Do(key, func() (interface{}, error) {
		return m.getOrFetch(ctx, registry, name, version, fetchFunc)
	})

	if err != nil {
		return nil, err
	}

	return result.(*CacheEntry), nil
}

// getOrFetch implements the actual get-or-fetch logic
func (m *Manager) getOrFetch(ctx context.Context, registry, name, version string, fetchFunc func(context.Context) (io.ReadCloser, string, error)) (*CacheEntry, error) {
	// Check metadata first
	pkg, err := m.metadata.GetPackage(ctx, registry, name, version)
	if err == nil {
		// Package found in metadata, check if expired
		if pkg.ExpiresAt != nil && time.Now().After(*pkg.ExpiresAt) {
			log.Debug().Str("package", name).Str("version", version).Msg("Package expired, re-fetching")
			metrics.RecordCacheEviction("ttl")
			// Delete expired package
			_ = m.deletePackage(ctx, pkg) // #nosec G104 -- Async cleanup
		} else {
			// Try to get from storage
			data, err := m.storage.Get(ctx, pkg.StorageKey)
			if err == nil {
				// Cache hit!
				metrics.RecordCacheHit(registry)
				_ = m.metadata.UpdateDownloadCount(ctx, registry, name, version) // #nosec G104 -- Async update, error logged

				// Track download in analytics if enabled
				if m.analytics != nil {
					m.trackDownload(registry, name, version, pkg.Size)
				}

				// Check for vulnerabilities if scanner is enabled
				if m.scanner != nil {
					blocked, reason, err := m.scanner.CheckVulnerabilities(ctx, registry, name, version)
					if err != nil {
						log.Warn().Err(err).Str("package", name).Msg("Failed to check vulnerabilities")
					}
					if blocked {
						metrics.RecordCacheHit(registry) // Record as blocked
						_ = data.Close()                 // #nosec G104                     // Close the data reader
						return nil, errors.New(errors.ErrCodeSecurityViolation, reason)
					}
				}

				return &CacheEntry{
					Package:   pkg,
					Data:      data,
					FromCache: true,
				}, nil
			}

			// Storage miss but metadata exists - inconsistency, clean up
			log.Warn().Str("package", name).Str("version", version).Msg("Metadata exists but storage missing")
			_ = m.metadata.DeletePackage(ctx, registry, name, version) // #nosec G104 -- Cleanup, error logged
		}
	}

	// Cache miss - fetch from upstream
	metrics.RecordCacheMiss(registry)

	if fetchFunc == nil {
		return nil, errors.NotFound(fmt.Sprintf("package not found and no fetch function provided: %s/%s@%s", registry, name, version))
	}

	log.Debug().Str("package", name).Str("version", version).Msg("Fetching from upstream")

	// Fetch from upstream
	data, upstreamURL, err := fetchFunc(ctx)
	if err != nil {
		metrics.RecordUpstreamRequest(registry, "error")
		return nil, errors.Wrap(err, errors.ErrCodeUpstreamFailure, "failed to fetch from upstream")
	}
	defer data.Close() // #nosec G104 -- Cleanup, error not critical

	metrics.RecordUpstreamRequest(registry, "success")

	// Store in cache (this will also trigger background scan)
	storedPkg, err := m.store(ctx, registry, name, version, data, upstreamURL)
	if err != nil {
		return nil, err
	}

	// Skip security scan wait for metadata entries (index pages, lists, etc.)
	isMetadataEntry := version == "list" || version == "page" || version == "latest" || version == "metadata"

	// Wait briefly for initial scan to complete if scanner is enabled
	// This prevents serving vulnerable packages on first request
	if m.scanner != nil && !isMetadataEntry {
		// Wait up to 30 seconds for scan to complete
		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-scanCtx.Done():
				// Timeout or context cancelled - proceed anyway
				// Package is cached, will be blocked on next request if vulnerable
				log.Warn().
					Str("package", name).
					Str("version", version).
					Msg("Scan timeout - allowing first download, will block on subsequent requests if vulnerable")
				goto servePkg

			case <-ticker.C:
				// First check if scan has completed by checking the SecurityScanned flag
				// This prevents race condition where CheckVulnerabilities() returns "clean"
				// before all scanners have finished
				pkg, err := m.metadata.GetPackage(scanCtx, registry, name, version)
				if err != nil {
					// Failed to get package metadata - continue waiting
					log.Debug().
						Str("package", name).
						Str("version", version).
						Err(err).
						Msg("Failed to get package metadata, waiting...")
					continue
				}

				if !pkg.SecurityScanned {
					// Scan still in progress - continue waiting
					log.Debug().
						Str("package", name).
						Str("version", version).
						Msg("Scan in progress, waiting...")
					continue
				}

				// Scan completed - now check if package should be blocked
				blocked, reason, err := m.scanner.CheckVulnerabilities(scanCtx, registry, name, version)
				if err != nil {
					// Unexpected error after scan complete - log and continue waiting
					log.Warn().
						Str("package", name).
						Str("version", version).
						Err(err).
						Msg("Error checking vulnerabilities, waiting...")
					continue
				}

				// Scan completed - check if blocked
				if blocked {
					log.Info().
						Str("package", name).
						Str("version", version).
						Str("reason", reason).
						Msg("Package cached but blocked due to vulnerabilities")
					return nil, errors.New(errors.ErrCodeSecurityViolation, reason)
				}

				// Package is clean - proceed to serve
				log.Info().
					Str("package", name).
					Str("version", version).
					Msg("Scan completed, package is clean")
				goto servePkg
			}
		}
	}

servePkg:
	// Re-open from storage for consistency
	storedData, err := m.storage.Get(ctx, storedPkg.StorageKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to retrieve just-stored package")
	}

	return &CacheEntry{
		Package:     storedPkg,
		Data:        storedData,
		FromCache:   false,
		UpstreamURL: upstreamURL,
	}, nil
}

// store stores a package in cache
func (m *Manager) store(ctx context.Context, registry, name, version string, data io.ReadCloser, upstreamURL string) (*metadata.Package, error) {
	// Generate storage key
	storageKey := m.generateStorageKey(registry, name, version)

	// Calculate checksums while storing
	// We need to read the data, calculate checksums, and store it
	// This requires buffering the data
	var buf []byte
	var err error

	// Read all data
	buf, err = io.ReadAll(data)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeUpstreamFailure, "failed to read upstream data")
	}

	// Calculate checksums
	h := sha256.New()
	h.Write(buf)
	checksumSHA256 := fmt.Sprintf("%x", h.Sum(nil))

	size := int64(len(buf))

	// Check quota before storing
	quota, err := m.storage.GetQuota(ctx)
	if err == nil && quota.Limit > 0 {
		if quota.Used+size > quota.Limit {
			// Trigger eviction
			if err := m.evict(ctx, size); err != nil {
				return nil, errors.QuotaExceeded(quota.Limit)
			}
		}
	}

	// Store in storage backend
	opts := &storage.PutOptions{
		ChecksumSHA256: checksumSHA256,
	}

	err = m.storage.Put(ctx, storageKey, io.NopCloser(bytes.NewReader(buf)), opts)
	if err != nil {
		return nil, err
	}

	// Create metadata entry
	now := time.Now()
	expiresAt := now.Add(m.config.DefaultTTL)

	pkg := &metadata.Package{
		ID:             uuid.New().String(),
		Registry:       registry,
		Name:           name,
		Version:        version,
		StorageKey:     storageKey,
		Size:           size,
		ChecksumSHA256: checksumSHA256,
		UpstreamURL:    upstreamURL,
		CachedAt:       now,
		LastAccessed:   now,
		ExpiresAt:      &expiresAt,
		DownloadCount:  0,
		Metadata:       make(map[string]string),
	}

	// Save metadata (skip metadata entries like index pages, lists, etc.)
	isMetadataEntry := version == "list" || version == "page" || version == "latest" || version == "metadata"
	if !isMetadataEntry {
		if err := m.metadata.SavePackage(ctx, pkg); err != nil {
			// Clean up storage if metadata save fails
			_ = m.storage.Delete(ctx, storageKey) // #nosec G104 -- Cleanup, error logged
			return nil, err
		}
	}

	// Scan package if scanner is enabled (run in background to not block cache operations)
	// Skip scanning metadata entries (index pages, lists, etc.)
	if m.scanner != nil && !isMetadataEntry {
		go func() {
			scanCtx := context.Background()
			var filePath string
			var cleanupFunc func()

			// Check if storage backend supports local paths
			if localProvider, ok := m.storage.(interface {
				GetLocalPath(ctx context.Context, key string) (string, error)
			}); ok {
				// Use direct file path from storage (avoid double download)
				path, err := localProvider.GetLocalPath(scanCtx, storageKey)
				if err != nil {
					log.Error().Err(err).Str("package", name).Msg("Failed to get local path for scanning")
					return
				}
				filePath = path
				cleanupFunc = func() {} // No cleanup needed for direct path
				log.Debug().Str("package", name).Str("path", filePath).Msg("Scanning package from storage path")
			} else {
				// Fallback: Create temp file for remote storage (S3, SMB, etc.)
				tempFilePath := filepath.Join(os.TempDir(), storageKey)

				// Create parent directories if they don't exist
				if err := os.MkdirAll(filepath.Dir(tempFilePath), 0750); err != nil {
					log.Error().Err(err).Str("package", name).Msg("Failed to create temp directory for scanning")
					return
				}

				tempFile, err := os.Create(tempFilePath) // #nosec G304 -- Temp file path is constructed from validated package name
				if err != nil {
					log.Error().Err(err).Str("package", name).Msg("Failed to create temp file for scanning")
					return
				}

				// Write package data to temp file
				if _, err := tempFile.Write(buf); err != nil {
					tempFile.Close()            // #nosec G104 -- Cleanup, error not critical
					_ = os.Remove(tempFilePath) // #nosec G104 -- Cleanup, error not critical
					log.Error().Err(err).Str("package", name).Msg("Failed to write temp file for scanning")
					return
				}
				tempFile.Close() // #nosec G104 -- Cleanup, error not critical

				filePath = tempFilePath
				cleanupFunc = func() { _ = os.Remove(tempFilePath) } // #nosec G104 -- Cleanup
				log.Debug().Str("package", name).Str("path", filePath).Msg("Scanning package from temp file")
			}

			defer cleanupFunc()

			// Scan package
			if err := m.scanner.ScanPackage(scanCtx, registry, name, version, filePath); err != nil {
				log.Error().Err(err).Str("package", name).Msg("Failed to scan package")
			}
		}()
	}

	return pkg, nil
}

// Delete removes a package from cache
func (m *Manager) Delete(ctx context.Context, registry, name, version string) error {
	pkg, err := m.metadata.GetPackage(ctx, registry, name, version)
	if err != nil {
		return err
	}

	return m.deletePackage(ctx, pkg)
}

// deletePackage deletes a package from both storage and metadata
func (m *Manager) deletePackage(ctx context.Context, pkg *metadata.Package) error {
	// Delete from storage
	if err := m.storage.Delete(ctx, pkg.StorageKey); err != nil {
		log.Warn().Err(err).Str("key", pkg.StorageKey).Msg("Failed to delete from storage")
	}

	// Delete from metadata
	return m.metadata.DeletePackage(ctx, pkg.Registry, pkg.Name, pkg.Version)
}

// evict implements LRU eviction
func (m *Manager) evict(ctx context.Context, needed int64) error {
	m.mu.Lock()
	if m.evicting {
		m.mu.Unlock()
		return errors.New(errors.ErrCodeStorageFailure, "eviction already in progress")
	}
	m.evicting = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.evicting = false
		m.mu.Unlock()
	}()

	log.Info().Int64("needed", needed).Msg("Starting LRU eviction")

	// List packages sorted by last accessed (oldest first)
	opts := &metadata.ListOptions{
		SortBy:   "last_accessed",
		SortDesc: false,
		Limit:    100,
	}

	var freed int64
	for freed < needed {
		packages, err := m.metadata.ListPackages(ctx, opts)
		if err != nil || len(packages) == 0 {
			break
		}

		for _, pkg := range packages {
			if err := m.deletePackage(ctx, pkg); err != nil {
				log.Warn().Err(err).Str("package", pkg.Name).Msg("Failed to evict package")
				continue
			}

			freed += pkg.Size
			metrics.RecordCacheEviction("lru")

			if freed >= needed {
				break
			}
		}

		if len(packages) < opts.Limit {
			break // No more packages
		}
	}

	log.Info().Int64("freed", freed).Msg("Eviction completed")
	return nil
}

// cleanupWorker runs periodic cleanup of expired packages
func (m *Manager) cleanupWorker() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx := context.Background()
		m.cleanup(ctx)
	}
}

// cleanup removes expired packages
func (m *Manager) cleanup(ctx context.Context) {
	log.Debug().Msg("Starting cleanup worker")

	// List all packages
	packages, err := m.metadata.ListPackages(ctx, &metadata.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages for cleanup")
		return
	}

	now := time.Now()
	var cleaned int

	for _, pkg := range packages {
		if pkg.ExpiresAt != nil && now.After(*pkg.ExpiresAt) {
			if err := m.deletePackage(ctx, pkg); err != nil {
				log.Warn().Err(err).Str("package", pkg.Name).Msg("Failed to clean up expired package")
				continue
			}
			cleaned++
		}
	}

	if cleaned > 0 {
		log.Info().Int("count", cleaned).Msg("Cleanup completed")
	}
}

// generateStorageKey generates a storage key for a package
func (m *Manager) generateStorageKey(registry, name, version string) string {
	return fmt.Sprintf("%s/%s/%s", registry, name, version)
}

// GetStats returns cache statistics
func (m *Manager) GetStats(ctx context.Context, registry string) (*metadata.Stats, error) {
	return m.metadata.GetStats(ctx, registry)
}

// Health checks cache manager health
func (m *Manager) Health(ctx context.Context) error {
	// Check storage health
	if err := m.storage.Health(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "storage health check failed")
	}

	// Check metadata health
	if err := m.metadata.Health(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeDatabaseFailure, "metadata health check failed")
	}

	return nil
}

// trackDownload tracks a package download event in analytics
func (m *Manager) trackDownload(registry, name, version string, size int64) {
	download := analytics.PackageDownload{
		Registry:  registry,
		Name:      name,
		Version:   version,
		Timestamp: time.Now(),
		BytesSize: size,
		ClientIP:  "", // TODO: Extract from context if available
		UserAgent: "", // TODO: Extract from context if available
	}

	m.analytics.TrackDownload(download)
}

// Close closes the cache manager
func (m *Manager) Close() error {
	var err error

	if closeErr := m.storage.Close(); closeErr != nil {
		err = closeErr
	}

	if closeErr := m.metadata.Close(); closeErr != nil {
		if err != nil {
			err = fmt.Errorf("%w; %w", err, closeErr)
		} else {
			err = closeErr
		}
	}

	return err
}
