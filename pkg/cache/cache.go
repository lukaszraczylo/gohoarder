// Package cache implements the unified cache manager that coordinates
// metadata, storage, scanning, and singleflight for upstream packages.
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/events"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/lukaszraczylo/gohoarder/pkg/uuid"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
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
	storage     storage.StorageBackend
	metadata    metadata.MetadataStore
	scanner     ScannerInterface
	analytics   AnalyticsInterface
	broadcaster events.Broadcaster
	stopCh      chan struct{}
	sf          singleflight.Group
	config      Config
	cleanupWG   sync.WaitGroup
	mu          sync.RWMutex
	bcMu        sync.RWMutex
	closeOnce   sync.Once
	evicting    bool
}

// SetBroadcaster wires an events.Broadcaster onto the manager so cache
// lifecycle events (cached / downloaded) are published. Pass nil to
// disable broadcasting. Safe to call after construction; concurrent
// access is guarded.
func (m *Manager) SetBroadcaster(b events.Broadcaster) {
	m.bcMu.Lock()
	m.broadcaster = b
	m.bcMu.Unlock()
}

// emit publishes an event via the configured broadcaster, if any.
// Fire-and-forget: never blocks the caller. The websocket server's
// BroadcastEvent is itself non-blocking (channel-drop on overflow),
// so we call directly rather than spawning a goroutine.
func (m *Manager) emit(eventType string, payload map[string]interface{}) {
	m.bcMu.RLock()
	b := m.broadcaster
	m.bcMu.RUnlock()
	if b == nil {
		return
	}
	b.BroadcastEvent(eventType, payload)
}

// Config holds cache manager configuration
type Config struct {
	DefaultTTL        time.Duration // Default TTL for cached packages
	CleanupInterval   time.Duration // How often to run cleanup
	EvictionThreshold float64       // Trigger eviction when usage > threshold (0.0-1.0)
	MaxConcurrent     int           // Max concurrent upstream fetches
	MaxPackageSize    int64         // Maximum package size in bytes (0 = default 2GB)
}

// CacheEntry represents a cached package
type CacheEntry struct {
	Data         io.ReadCloser
	Package      *metadata.Package
	UpstreamURL  string
	CacheControl string
	FromCache    bool
}

// FetchResult carries the outcome of an upstream fetch closure. In addition
// to the response body, it communicates auth state so the cache manager can
// persist RequiresAuth/AuthProvider on the stored package. The downstream
// security gate reads entry.Package.RequiresAuth, so this state must be stored
// in the database (not just set on the ephemeral cache entry).
type FetchResult struct {
	// Data is the response body. Caller closes it (or Get closes it after store).
	Data io.ReadCloser
	// UpstreamURL is the upstream URL the body came from.
	UpstreamURL string
	// AuthProvider identifies the auth system (e.g. github, gitlab, custom).
	AuthProvider string
	// RequiresAuth is true when the upstream indicated the package is behind
	// authentication (e.g. HTTP 401/403, or a private registry that demanded
	// credentials).
	RequiresAuth bool
}

// FetchFunc fetches a package from upstream and reports auth state.
type FetchFunc func(context.Context) (*FetchResult, error)

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

	if config.MaxPackageSize == 0 {
		config.MaxPackageSize = 2 * 1024 * 1024 * 1024 // 2GB default
	}

	manager := &Manager{
		storage:   storage,
		metadata:  metadata,
		scanner:   scanner,
		analytics: analytics,
		config:    config,
		stopCh:    make(chan struct{}),
	}

	// Start background cleanup worker
	manager.cleanupWG.Add(1)
	go manager.cleanupWorker()

	return manager, nil

}

func (m *Manager) Get(ctx context.Context, registry, name, version string, fetchFunc FetchFunc) (*CacheEntry, error) {
	// Use singleflight to deduplicate concurrent requests
	key := fmt.Sprintf("%s/%s/%s", registry, name, version)

	result, err, _ := m.sf.Do(key, func() (interface{}, error) {
		// getOrFetch returns a CacheEntry with Data == nil. Each caller
		// re-opens its own storage reader below to avoid sharing a
		// single io.ReadCloser across concurrent waiters.
		return m.getOrFetch(ctx, registry, name, version, fetchFunc)
	})

	if err != nil {
		return nil, err
	}

	entry := result.(*CacheEntry)
	if entry == nil || entry.Package == nil {
		return nil, errors.New(errors.ErrCodeStorageFailure, "cache entry missing package metadata")
	}

	// Open a fresh ReadCloser per caller from storage.
	data, err := m.storage.Get(ctx, entry.Package.StorageKey)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to retrieve cached package")
	}

	// Return a copy so concurrent waiters don't share the Data field.
	return &CacheEntry{
		Data:         data,
		Package:      entry.Package,
		UpstreamURL:  entry.UpstreamURL,
		CacheControl: entry.CacheControl,
		FromCache:    entry.FromCache,
	}, nil
}

// getOrFetch implements the actual get-or-fetch logic
func (m *Manager) getOrFetch(ctx context.Context, registry, name, version string, fetchFunc FetchFunc) (*CacheEntry, error) {
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
			// Probe storage by opening then immediately closing the reader.
			// Singleflight callers can't share a live ReadCloser; each caller in
			// Get() opens its own reader after the singleflight returns.
			data, getErr := m.storage.Get(ctx, pkg.StorageKey)
			if getErr == nil {
				_ = data.Close() // #nosec G104 -- probe only; Get() reopens per caller

				// Cache hit!
				metrics.RecordCacheHit(registry)

				// Update download count (log errors for debugging)
				if updErr := m.metadata.UpdateDownloadCount(ctx, registry, name, version); updErr != nil {
					log.Warn().
						Err(updErr).
						Str("registry", registry).
						Str("package", name).
						Str("version", version).
						Msg("Failed to update download count - package may not exist in database")

					// Try to save package to database if it doesn't exist
					// This handles the case where storage has files but database was migrated/reset
					if saveErr := m.metadata.SavePackage(ctx, pkg); saveErr != nil {
						log.Error().
							Err(saveErr).
							Str("registry", registry).
							Str("package", name).
							Str("version", version).
							Msg("Failed to save package to database")
					} else {
						// Retry download count update after saving package
						if retryErr := m.metadata.UpdateDownloadCount(ctx, registry, name, version); retryErr != nil {
							log.Error().
								Err(retryErr).
								Str("registry", registry).
								Str("package", name).
								Str("version", version).
								Msg("Failed to update download count even after saving package")
						}
					}
				}

				// Track download in analytics if enabled
				if m.analytics != nil {
					m.trackDownload(registry, name, version, pkg.Size)
				}

				// Check for vulnerabilities if scanner is enabled. Metadata
				// entries (index pages, lists, .mod/.info) are not scannable
				// packages, so skip them to avoid a bogus "clean" verdict and
				// the extra database round-trip.
				isMetadataEntry := version == "list" || version == "page" || version == "latest" || version == "metadata" ||
					strings.HasSuffix(name, ".mod") || strings.HasSuffix(name, ".info")
				if m.scanner != nil && !isMetadataEntry {
					blocked, reason, vulnErr := m.scanner.CheckVulnerabilities(ctx, registry, name, version)
					if vulnErr != nil {
						log.Warn().Err(vulnErr).Str("package", name).Msg("Failed to check vulnerabilities")
					}
					if blocked {
						return nil, errors.New(errors.ErrCodeSecurityViolation, reason)
					}
				}

				// Broadcast cache-hit serve event. Fire-and-forget; the
				// underlying transport is non-blocking. Only emitted on
				// the cache-hit path — the miss-then-fetch path is
				// covered by EventPackageCached emitted from store().
				m.emit(string(websocket.EventPackageDownloaded), map[string]interface{}{
					"registry":  registry,
					"name":      name,
					"version":   version,
					"cache_hit": true,
				})

				// Data is intentionally nil; Get() opens a fresh reader per caller.
				return &CacheEntry{
					Package:   pkg,
					Data:      nil,
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
	fr, err := fetchFunc(ctx)
	if err != nil {
		metrics.RecordUpstreamRequest(registry, "error")
		return nil, errors.Wrap(err, errors.ErrCodeUpstreamFailure, "failed to fetch from upstream")
	}
	if fr == nil || fr.Data == nil {
		return nil, errors.New(errors.ErrCodeUpstreamFailure, "upstream fetch returned no data")
	}
	data := fr.Data
	defer func() { _ = data.Close() }() // #nosec G104 -- Cleanup, error not critical

	metrics.RecordUpstreamRequest(registry, "success")

	// Store in cache (this will also trigger background scan). Auth state is
	// plumbed through so the persisted package carries RequiresAuth.
	storedPkg, err := m.store(ctx, registry, name, version, data, fr.UpstreamURL, fr.RequiresAuth, fr.AuthProvider)
	if err != nil {
		return nil, err
	}

	// Skip security scan wait for metadata entries (index pages, lists, etc.)
	// Also skip Go module metadata files (.mod, .info)
	isMetadataEntry := version == "list" || version == "page" || version == "latest" || version == "metadata" ||
		strings.HasSuffix(name, ".mod") || strings.HasSuffix(name, ".info")

	// Wait briefly for initial scan to complete if scanner is enabled
	// This prevents serving vulnerable packages on first request.
	// SECURITY: timeouts MUST fail closed — never serve unscanned content.
	if m.scanner != nil && !isMetadataEntry {
		// Wait up to 30 seconds for scan to complete
		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

	scanWait:
		for {
			select {
			case <-scanCtx.Done():
				// Fail closed: do NOT serve unscanned packages on timeout/cancel.
				// Package remains cached; subsequent requests can retry once
				// the scan completes.
				log.Warn().
					Str("package", name).
					Str("version", version).
					Msg("Scan timeout - refusing to serve unscanned package (fail-closed)")
				return nil, errors.New(errors.ErrCodeServiceUnavailable, "package scan in progress, retry shortly")

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
				break scanWait
			}
		}
	}

	// Track download count for first-time download (cache miss)
	// This ensures download count increments regardless of cache hit/miss
	if err := m.metadata.UpdateDownloadCount(ctx, registry, name, version); err != nil {
		log.Warn().
			Err(err).
			Str("registry", registry).
			Str("package", name).
			Str("version", version).
			Msg("Failed to update download count for newly cached package")
	}

	// Track download in analytics if enabled
	if m.analytics != nil {
		m.trackDownload(registry, name, version, storedPkg.Size)
	}

	// Data is intentionally nil; Get() opens a fresh reader per caller.
	return &CacheEntry{
		Package:     storedPkg,
		UpstreamURL: fr.UpstreamURL,
		FromCache:   false,
	}, nil
}

// store stores a package in cache
func (m *Manager) store(ctx context.Context, registry, name, version string, data io.ReadCloser, upstreamURL string, requiresAuth bool, authProvider string) (*metadata.Package, error) {
	// Generate storage key
	storageKey := m.generateStorageKey(registry, name, version)

	// Stream upstream to a temp file while computing checksums, instead of
	// buffering the full payload in memory (avoids OOM on large packages,
	// e.g. the default 2 GB MaxPackageSize). The temp file also becomes the
	// scan source for backends that can't expose a local path, so the payload
	// is never held twice in RAM.
	maxSize := m.config.MaxPackageSize
	if maxSize <= 0 {
		maxSize = 2 * 1024 * 1024 * 1024 // 2GB safety floor
	}

	tempFile, err := os.CreateTemp(os.TempDir(), "gohoarder-store-*")
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeUpstreamFailure, "failed to create temp file for upstream data")
	}
	tempPath := tempFile.Name()
	// Temp file is removed when store() returns, unless ownership is handed
	// to a scan goroutine (remote backends reuse it for scanning).
	scanOwnsTemp := false
	defer func() {
		if !scanOwnsTemp {
			_ = os.Remove(tempPath) // #nosec G104 -- cleanup
		}
	}()

	// Compute SHA256 as the payload is streamed to the temp file. Cap at
	// maxSize+1 so we can detect overflow without reading unbounded data.
	hash := sha256.New()
	limited := io.LimitReader(data, maxSize+1)
	written, err := io.Copy(io.MultiWriter(tempFile, hash), limited)
	if err != nil {
		_ = tempFile.Close() // #nosec G104 -- cleanup
		return nil, errors.Wrap(err, errors.ErrCodeUpstreamFailure, "failed to read upstream data")
	}
	if written > maxSize {
		_ = tempFile.Close() // #nosec G104 -- cleanup
		return nil, errors.New(errors.ErrCodePayloadTooLarge,
			fmt.Sprintf("upstream package exceeds max size (%d bytes)", maxSize))
	}
	checksumSHA256 := fmt.Sprintf("%x", hash.Sum(nil))
	size := written

	// Check quota before storing
	quota, err := m.storage.GetQuota(ctx)
	if err == nil && quota.Limit > 0 {
		if quota.Used+size > quota.Limit {
			// Trigger eviction
			if evictErr := m.evict(ctx, size); evictErr != nil {
				_ = tempFile.Close() // #nosec G104 -- cleanup
				return nil, errors.QuotaExceeded(quota.Limit)
			}
		}
	}

	// Seek temp file back to start and stream it to the storage backend.
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		_ = tempFile.Close() // #nosec G104 -- cleanup
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to seek temp file")
	}

	// Store in storage backend
	opts := &storage.PutOptions{
		ChecksumSHA256: checksumSHA256,
	}

	if err := m.storage.Put(ctx, storageKey, tempFile, opts); err != nil {
		_ = tempFile.Close() // #nosec G104 -- cleanup
		return nil, err
	}
	_ = tempFile.Close() // #nosec G104 -- cleanup; scan may still read the file

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
		RequiresAuth:   requiresAuth,
		AuthProvider:   authProvider,
		CachedAt:       now,
		LastAccessed:   now,
		ExpiresAt:      &expiresAt,
		DownloadCount:  0,
		Metadata:       make(map[string]string),
	}

	// Persist metadata for ALL entries (including metadata pages and Go .mod/.info).
	// Skipping persistence for metadata entries caused unconditional upstream re-fetch
	// on every metadata request. SavePackage upserts safely; the metadata-entry flag
	// below is still used to skip security scanning (these are not scannable packages).
	//
	// TRADEOFF: metadata pages share the cache's DefaultTTL and are not refreshed
	// based on upstream Cache-Control. Plumbing per-response TTL from registry handlers
	// is out of scope here and tracked separately.
	isMetadataEntry := version == "list" || version == "page" || version == "latest" || version == "metadata" ||
		strings.HasSuffix(name, ".mod") || strings.HasSuffix(name, ".info")
	if err := m.metadata.SavePackage(ctx, pkg); err != nil {
		// Clean up storage if metadata save fails
		_ = m.storage.Delete(ctx, storageKey) // #nosec G104 -- Cleanup, error logged
		return nil, err
	}

	// Broadcast cache-store event. The scan_status reflects the
	// initial state ("pending" if scanning is enabled and applicable;
	// "skipped" for metadata entries; "disabled" when scanner is nil).
	scanStatus := "disabled"
	if m.scanner != nil {
		if isMetadataEntry {
			scanStatus = "skipped"
		} else {
			scanStatus = "pending"
		}
	}
	m.emit(string(websocket.EventPackageCached), map[string]interface{}{
		"registry":    registry,
		"name":        name,
		"version":     version,
		"size":        size,
		"scan_status": scanStatus,
	})

	// Scan package if scanner is enabled (run in background to not block cache operations)
	// Skip scanning metadata entries (index pages, lists, etc.)
	if m.scanner != nil && !isMetadataEntry {
		// Decide synchronously whether the streaming temp file must outlive
		// store(). Remote backends (no GetLocalPath) reuse it as the scan
		// source; local backends scan from GetLocalPath and don't need it.
		_, hasLocalPath := m.storage.(interface {
			GetLocalPath(ctx context.Context, key string) (string, error)
		})
		if !hasLocalPath {
			scanOwnsTemp = true
		}

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
				// Remote storage (S3, SMB, etc.) — reuse the temp file store()
				// already wrote during streaming. This avoids re-uploading the
				// payload into another temp file and avoids holding it in RAM.
				filePath = tempPath
				cleanupFunc = func() { _ = os.Remove(tempPath) } // #nosec G104 -- Cleanup
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

// cleanupWorker runs periodic cleanup of expired packages.
// Exits when stopCh is closed (via Close()).
func (m *Manager) cleanupWorker() {
	defer m.cleanupWG.Done()

	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			ctx := context.Background()
			m.cleanup(ctx)
		}
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

// Close closes the cache manager.
// Stops the cleanup worker, then closes storage and metadata backends.
// Safe to call multiple times.
func (m *Manager) Close() error {
	var err error

	// Stop cleanup worker (idempotent via sync.Once).
	m.closeOnce.Do(func() {
		close(m.stopCh)
		m.cleanupWG.Wait()
	})

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
