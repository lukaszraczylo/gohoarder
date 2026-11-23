// Package cache implements the unified cache manager that coordinates
// metadata, storage, scanning, and singleflight for upstream packages.
package cache

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	hoarderconfig "github.com/lukaszraczylo/gohoarder/pkg/config"
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
	bgCtx       context.Context // cancelled by Close; parent of background scans
	bgCancel    context.CancelFunc
	sf          singleflight.Group
	config      Config
	cleanupWG   sync.WaitGroup
	bcMu        sync.RWMutex
	closeOnce   sync.Once
	evictMu     sync.Mutex // serialises LRU eviction; a second caller waits and re-checks its quota
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
	Now               func() time.Time         // Clock; nil means time.Now
	TTLOverrides      map[string]time.Duration // Per-registry metadata freshness TTL; falls back to DefaultTTL
	DefaultTTL        time.Duration            // Freshness TTL for metadata entries
	CleanupInterval   time.Duration            // How often to run cleanup
	IdleTTL           time.Duration            // Remove entries not requested for this long (0 = off)
	DeletedRetention  time.Duration            // Hard-delete soft-deleted rows older than this (0 = keep forever)
	EvictionThreshold float64                  // Trigger eviction when usage > threshold (0.0-1.0)
	MaxConcurrent     int                      // Max concurrent upstream fetches
	MaxPackageSize    int64                    // Maximum package size in bytes (0 = default 2GB)
	ScanWaitTimeout   time.Duration            // How long the first download waits for its scan (0 = 30s)
	FailClosed        bool                     // Refuse a package whose scan did not finish in time
}

const defaultScanWaitTimeout = 30 * time.Second

// cleanupBatchSize bounds how many rows one cleanup query reads.
const cleanupBatchSize = metadata.DefaultBatchSize

// maxPurgeBatches bounds the soft-delete purge of one cleanup pass; the next pass continues.
const maxPurgeBatches = 100

// getAttempts bounds how often Get re-resolves an entry whose blob vanished.
const getAttempts = 2

// Eviction metric reasons.
const (
	evictReasonTTL  = "ttl"
	evictReasonIdle = "idle"
)

// scannerToggle is implemented by scanners that can be switched off.
type scannerToggle interface {
	Enabled() bool
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
	// ReleaseVersion is the user-facing version when the cache key version is not one (PyPI file names).
	ReleaseVersion string
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

	// A scanner that is switched off never records a result, so waiting for
	// one would stall every first download until the wait times out.
	if toggle, ok := scanner.(scannerToggle); ok && !toggle.Enabled() {
		scanner = nil
	}

	// Scanner is optional - can be nil if security scanning is disabled
	if scanner != nil {
		log.Info().Msg("Cache manager initialized with security scanning enabled")
	}

	// Analytics is optional - can be nil if analytics tracking is disabled
	if analytics != nil {
		log.Info().Msg("Cache manager initialized with analytics tracking enabled")
	}

	if config.Now == nil {
		config.Now = time.Now
	}

	if config.DefaultTTL == 0 {
		config.DefaultTTL = hoarderconfig.DefaultMetadataTTL
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

	if config.ScanWaitTimeout == 0 {
		config.ScanWaitTimeout = defaultScanWaitTimeout
	}

	if config.MaxPackageSize == 0 {
		config.MaxPackageSize = 2 * 1024 * 1024 * 1024 // 2GB default
	}

	bgCtx, bgCancel := context.WithCancel(context.Background())
	manager := &Manager{
		bgCtx:     bgCtx,
		bgCancel:  bgCancel,
		storage:   storage,
		metadata:  metadata,
		scanner:   scanner,
		analytics: analytics,
		config:    config,
		stopCh:    make(chan struct{}),
	}

	// Rows cached before idle eviction existed carry an age-based expiry.
	manager.clearArtifactExpiry(bgCtx)

	// Start background cleanup worker
	manager.cleanupWG.Add(1)
	go manager.cleanupWorker()

	return manager, nil

}

func (m *Manager) Get(ctx context.Context, registry, name, version string, fetchFunc FetchFunc) (*CacheEntry, error) {
	// Use singleflight to deduplicate concurrent requests
	key := fmt.Sprintf("%s/%s/%s", registry, name, version)

	var openErr error
	// A purge can delete the blob between the cache-hit probe and the open
	// below. The second pass sees the miss and fetches again.
	for attempt := 0; attempt < getAttempts; attempt++ {
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
			openErr = err
			continue
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

	return nil, errors.Wrap(openErr, errors.ErrCodeStorageFailure, "failed to retrieve cached package")
}

// getOrFetch implements the actual get-or-fetch logic
func (m *Manager) getOrFetch(ctx context.Context, registry, name, version string, fetchFunc FetchFunc) (*CacheEntry, error) {
	// Check metadata first
	pkg, err := m.metadata.GetPackage(ctx, registry, name, version)
	if err == nil {
		// Package found in metadata, check if expired
		if pkg.ExpiresAt != nil && m.now().After(*pkg.ExpiresAt) {
			log.Debug().Str("package", name).Str("version", version).Msg("Package expired, re-fetching")
			metrics.RecordCacheEviction(evictReasonTTL)
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
				isMetadataEntry := metadata.IsMetadataEntry(registry, name, version)
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
				m.emit(string(websocket.EventPackageDownloaded), withReleaseVersion(map[string]interface{}{
					"registry":  registry,
					"name":      name,
					"version":   version,
					"cache_hit": true,
				}, pkg.ReleaseVersion))

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
	storedPkg, err := m.store(ctx, registry, name, version, fr.ReleaseVersion, data, fr.UpstreamURL, fr.RequiresAuth, fr.AuthProvider)
	if err != nil {
		return nil, err
	}

	// Skip security scan wait for metadata entries (index pages, lists, etc.)
	// Also skip Go module metadata files (.mod, .info)
	isMetadataEntry := metadata.IsMetadataEntry(registry, name, version)

	// Wait briefly for initial scan to complete if scanner is enabled
	// This prevents serving vulnerable packages on first request.
	// A wait that times out serves the package unless FailClosed is set; the
	// scan keeps running and records its result for later requests.
	if m.scanner != nil && !isMetadataEntry {
		scanCtx, cancel := context.WithTimeout(ctx, m.config.ScanWaitTimeout)
		defer cancel()

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

	scanWait:
		for {
			select {
			case <-scanCtx.Done():
				if ctx.Err() == nil && !m.config.FailClosed {
					log.Warn().
						Str("package", name).
						Str("version", version).
						Msg("Scan wait timed out - serving package, scan continues in background")
					break scanWait
				}
				log.Warn().
					Str("package", name).
					Str("version", version).
					Msg("Scan wait ended - refusing to serve unscanned package (fail-closed)")
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
func (m *Manager) store(ctx context.Context, registry, name, version, releaseVersion string, data io.ReadCloser, upstreamURL string, requiresAuth bool, authProvider string) (*metadata.Package, error) {
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
	now := m.now()
	isMetadataEntry := metadata.IsMetadataEntry(registry, name, version)

	// Artifacts are immutable, so only idle eviction removes them; metadata
	// entries must refresh and keep a freshness expiry.
	var expiresAt *time.Time
	if isMetadataEntry {
		exp := now.Add(m.metadataTTL(registry))
		expiresAt = &exp
	}

	pkg := &metadata.Package{
		ID:             uuid.New().String(),
		Registry:       registry,
		Name:           name,
		Version:        version,
		ReleaseVersion: releaseVersion,
		StorageKey:     storageKey,
		Size:           size,
		ChecksumSHA256: checksumSHA256,
		UpstreamURL:    upstreamURL,
		RequiresAuth:   requiresAuth,
		AuthProvider:   authProvider,
		CachedAt:       now,
		LastAccessed:   now,
		ExpiresAt:      expiresAt,
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
	m.emit(string(websocket.EventPackageCached), withReleaseVersion(map[string]interface{}{
		"registry":    registry,
		"name":        name,
		"version":     version,
		"size":        size,
		"scan_status": scanStatus,
	}, releaseVersion))

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
			scanCtx := m.bgCtx
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

// ScanFile returns a local file holding a cached package, for a scan retry. Backends with a
// local path serve it directly; others are copied to a temp file that cleanup removes.
func (m *Manager) ScanFile(ctx context.Context, registry, name, version string) (string, func(), error) {
	pkg, err := m.metadata.GetPackage(ctx, registry, name, version)
	if err != nil {
		return "", nil, err
	}
	if local, ok := m.storage.(storage.LocalPathProvider); ok {
		path, pathErr := local.GetLocalPath(ctx, pkg.StorageKey)
		return path, func() {}, pathErr
	}
	rc, err := m.storage.Get(ctx, pkg.StorageKey)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = rc.Close() }()
	tmp, err := os.CreateTemp(os.TempDir(), "gohoarder-rescan-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) } // #nosec G104 -- cleanup
	if _, err := io.Copy(tmp, rc); err != nil {
		_ = tmp.Close() // #nosec G104 -- cleanup
		cleanup()
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp.Name(), cleanup, nil
}

// Delete removes a package from cache
func (m *Manager) Delete(ctx context.Context, registry, name, version string) error {
	pkg, err := m.metadata.GetPackage(ctx, registry, name, version)
	if err != nil {
		return err
	}

	return m.deletePackage(ctx, pkg)
}

// metadataTTL returns the freshness window for a registry's metadata entries.
func (m *Manager) metadataTTL(registry string) time.Duration {
	if ttl, ok := m.config.TTLOverrides[registry]; ok {
		return ttl
	}
	return m.config.DefaultTTL
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
	m.evictMu.Lock()
	defer m.evictMu.Unlock()

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

		deleted := 0
		for _, pkg := range packages {
			if err := m.deletePackage(ctx, pkg); err != nil {
				log.Warn().Err(err).Str("package", pkg.Name).Msg("Failed to evict package")
				continue
			}

			deleted++
			freed += pkg.Size
			metrics.RecordCacheEviction("lru")

			if freed >= needed {
				break
			}
		}

		if len(packages) < opts.Limit || deleted == 0 {
			break // No more packages, or the same rows would be listed again
		}
	}

	log.Info().Int64("freed", freed).Msg("Eviction completed")
	return nil
}

// cleanupWorker runs periodic cleanup of expired and idle packages.
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
			m.cleanup(m.bgCtx)
		}
	}
}

func (m *Manager) now() time.Time {
	return m.config.Now()
}

// clearArtifactExpiry drops the age-based expiry that older versions set on artifacts.
func (m *Manager) clearArtifactExpiry(ctx context.Context) {
	cleared, err := m.metadata.ClearArtifactExpiry(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to clear artifact expiry")
		return
	}
	if cleared > 0 {
		log.Info().Int64("count", cleared).Msg("Cleared age-based expiry from cached artifacts")
	}
}

// purgeResult totals the packages one purge pass removed.
type purgeResult struct {
	bytes int64
	count int
}

// purge deletes packages in bounded batches until the list query runs dry.
// stillDue re-checks each package just before deletion so one requested after
// the batch was read is kept.
func (m *Manager) purge(
	ctx context.Context,
	reason string,
	list func(limit int) ([]*metadata.Package, error),
	stillDue func(*metadata.Package) bool,
) purgeResult {
	var res purgeResult
	seen := make(map[string]struct{})

	for ctx.Err() == nil {
		batch, err := list(cleanupBatchSize)
		if err != nil {
			log.Error().Err(err).Str("reason", reason).Msg("Failed to list packages for cleanup")
			return res
		}

		unseen := 0
		for _, pkg := range batch {
			key := m.generateStorageKey(pkg.Registry, pkg.Name, pkg.Version)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			unseen++

			current, err := m.metadata.GetPackage(ctx, pkg.Registry, pkg.Name, pkg.Version)
			if err != nil || current == nil || !stillDue(current) {
				continue
			}
			if err := m.deletePackage(ctx, current); err != nil {
				log.Warn().Err(err).Str("package", pkg.Name).Str("reason", reason).Msg("Failed to clean up package")
				continue
			}
			res.count++
			res.bytes += current.Size
			metrics.RecordCacheEviction(reason)
		}

		// A short batch is the last one; a batch of only repeats means every
		// remaining row failed to delete.
		if len(batch) < cleanupBatchSize || unseen == 0 {
			return res
		}
	}
	return res
}

// cleanup removes metadata entries past their freshness expiry and, when
// IdleTTL is set, every package not requested within IdleTTL.
func (m *Manager) cleanup(ctx context.Context) {
	start := m.now()
	log.Debug().Msg("Starting cleanup worker")

	m.clearArtifactExpiry(ctx)

	expired := m.purge(ctx, evictReasonTTL,
		func(limit int) ([]*metadata.Package, error) {
			return m.metadata.ListExpiredPackages(ctx, start, limit)
		},
		func(p *metadata.Package) bool { return p.ExpiresAt != nil && p.ExpiresAt.Before(start) })

	var idle purgeResult
	if m.config.IdleTTL > 0 {
		cutoff := start.Add(-m.config.IdleTTL)
		idle = m.purge(ctx, evictReasonIdle,
			func(limit int) ([]*metadata.Package, error) {
				return m.metadata.ListIdlePackages(ctx, cutoff, limit)
			},
			func(p *metadata.Package) bool { return p.LastAccessed.Before(cutoff) })
	}

	purged := m.purgeDeleted(ctx, start)

	log.Info().
		Int("expired", expired.count).
		Int("idle", idle.count).
		Int64("bytes_freed", expired.bytes+idle.bytes).
		Dur("idle_ttl", m.config.IdleTTL).
		Int64("purged_deleted", purged).
		Dur("deleted_retention", m.config.DeletedRetention).
		Msg("Cleanup completed")
}

// purgeDeleted hard-deletes soft-deleted rows past DeletedRetention in bounded
// batches and returns how many it removed.
func (m *Manager) purgeDeleted(ctx context.Context, now time.Time) int64 {
	if m.config.DeletedRetention <= 0 {
		return 0
	}
	cutoff := now.Add(-m.config.DeletedRetention)
	var total int64
	for i := 0; i < maxPurgeBatches && ctx.Err() == nil; i++ {
		n, err := m.metadata.PurgeDeletedPackages(ctx, cutoff, cleanupBatchSize)
		if err != nil {
			log.Error().Err(err).Msg("Failed to purge soft-deleted packages")
			break
		}
		total += n
		if n < cleanupBatchSize {
			break
		}
	}
	return total
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
		m.bgCancel()
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

// withReleaseVersion adds release_version to an event payload when the cache key is not a release version.
func withReleaseVersion(payload map[string]interface{}, releaseVersion string) map[string]interface{} {
	if releaseVersion != "" {
		payload["release_version"] = releaseVersion
	}
	return payload
}
