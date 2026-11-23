package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// RescanWorker handles periodic re-scanning of cached packages
type RescanWorker struct {
	metadataStore metadata.MetadataStore
	manager       *Manager
	stopCh        chan struct{}
	stopOnce      sync.Once
	interval      time.Duration
	activeWindow  time.Duration
	concurrency   int
}

// RescanOption tunes a RescanWorker.
type RescanOption func(*RescanWorker)

// WithActiveWindow skips packages not accessed within window (0 = scan all).
func WithActiveWindow(window time.Duration) RescanOption {
	return func(w *RescanWorker) { w.activeWindow = window }
}

// WithConcurrency sets the scans run in parallel within a cycle; values below 1 mean 1.
func WithConcurrency(n int) RescanOption {
	return func(w *RescanWorker) {
		if n < 1 {
			n = 1
		}
		w.concurrency = n
	}
}

// NewRescanWorker creates a new rescan worker
func NewRescanWorker(manager *Manager, metadataStore metadata.MetadataStore, interval time.Duration, opts ...RescanOption) *RescanWorker {
	w := &RescanWorker{
		manager:       manager,
		metadataStore: metadataStore,
		interval:      interval,
		concurrency:   1,
		stopCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Start begins the periodic re-scanning process
func (w *RescanWorker) Start(ctx context.Context) {
	if !w.manager.enabled || w.interval == 0 {
		log.Info().Msg("Rescan worker disabled")
		return
	}

	log.Info().
		Dur("interval", w.interval).
		Msg("Starting package rescan worker")

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run initial scan immediately on startup
	log.Info().Msg("Running initial package scan on startup")
	w.rescanPackages(ctx)
	log.Info().
		Dur("next_scan", w.interval).
		Msg("Initial scan complete, next scan scheduled")

	for {
		select {
		case <-ticker.C:
			w.rescanPackages(ctx)
		case <-w.stopCh:
			log.Info().Msg("Rescan worker stopped")
			return
		case <-ctx.Done():
			log.Info().Msg("Rescan worker stopped (context cancelled)")
			return
		}
	}
}

// Stop stops the rescan worker. Safe to call multiple times.
func (w *RescanWorker) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopCh)
	})
}

// rescanCounts tallies one rescan cycle; workers update it concurrently.
type rescanCounts struct {
	scanned      atomic.Int64
	failed       atomic.Int64
	skipMetadata atomic.Int64
	skipIdle     atomic.Int64
	skipFresh    atomic.Int64
	skipNoSource atomic.Int64
}

// rescanPackages re-scans packages that need updating
func (w *RescanWorker) rescanPackages(ctx context.Context) {
	log.Info().Msg("Starting package rescan cycle - checking all packages for scan status")

	packages, err := w.metadataStore.ListPackages(ctx, &metadata.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages for rescan")
		return
	}

	var counts rescanCounts
	jobs := make(chan *metadata.Package)
	var wg sync.WaitGroup
	for i := 0; i < w.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				w.rescanOne(ctx, pkg, &counts)
			}
		}()
	}

dispatch:
	for _, pkg := range packages {
		if metadata.IsMetadataEntry(pkg.Registry, pkg.Name, pkg.Version) {
			counts.skipMetadata.Add(1)
			continue
		}
		if w.idle(pkg) {
			counts.skipIdle.Add(1)
			continue
		}
		select {
		case jobs <- pkg:
		case <-ctx.Done():
			break dispatch
		case <-w.stopCh:
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()

	log.Info().
		Int("total", len(packages)).
		Int64("scanned", counts.scanned.Load()).
		Int64("failed", counts.failed.Load()).
		Int64("skipped_metadata", counts.skipMetadata.Load()).
		Int64("skipped_idle", counts.skipIdle.Load()).
		Int64("skipped_fresh", counts.skipFresh.Load()).
		Int64("skipped_no_source", counts.skipNoSource.Load()).
		Int("concurrency", w.concurrency).
		Dur("active_window", w.activeWindow).
		Msg("Rescan cycle completed")
}

// idle reports whether a package was last served longer ago than the active window.
// A zero LastAccessed is unknown, so the package is scanned.
func (w *RescanWorker) idle(pkg *metadata.Package) bool {
	if w.activeWindow <= 0 || pkg.LastAccessed.IsZero() {
		return false
	}
	return time.Since(pkg.LastAccessed) > w.activeWindow
}

// rescanOne scans a single package when its result is missing or stale.
func (w *RescanWorker) rescanOne(ctx context.Context, pkg *metadata.Package, counts *rescanCounts) {
	needsRescan, err := w.needsRescan(ctx, pkg)
	if err != nil {
		log.Error().
			Err(err).
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("Failed to check rescan status")
		counts.failed.Add(1)
		return
	}

	if !needsRescan {
		log.Debug().
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Bool("security_scanned", pkg.SecurityScanned).
			Msg("Package does not need rescanning, skipping")
		counts.skipFresh.Add(1)
		return
	}

	log.Info().
		Str("registry", pkg.Registry).
		Str("package", pkg.Name).
		Str("version", pkg.Version).
		Msg("Package needs rescanning")

	if pkg.StorageKey == "" {
		log.Warn().
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("Package has no storage key, skipping rescan")
		counts.failed.Add(1)
		return
	}

	source := w.manager.currentFileSource()
	if source == nil {
		log.Debug().
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("No file source configured, skipping rescan")
		counts.skipNoSource.Add(1)
		return
	}

	filePath, cleanup, err := source(ctx, pkg.Registry, pkg.Name, pkg.Version)
	if err != nil {
		log.Warn().
			Err(err).
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Str("storage_key", pkg.StorageKey).
			Msg("Failed to read package file, skipping rescan")
		counts.failed.Add(1)
		return
	}

	err = w.manager.ScanPackage(ctx, pkg.Registry, pkg.Name, pkg.Version, filePath)
	cleanup()
	if err != nil {
		log.Error().
			Err(err).
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("Failed to rescan package")
		counts.failed.Add(1)
		return
	}

	counts.scanned.Add(1)
}

// needsRescan checks if a package needs to be rescanned
func (w *RescanWorker) needsRescan(ctx context.Context, pkg *metadata.Package) (bool, error) {
	// Get latest scan result
	scanResult, err := w.metadataStore.GetScanResult(ctx, pkg.Registry, pkg.Name, pkg.Version)
	if err != nil {
		// No scan result - needs scanning
		log.Debug().
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("Package has no scan result, needs scanning")
		return true, nil
	}

	// If package is not marked as scanned but has scan result, it's a stale state - rescan
	if !pkg.SecurityScanned {
		log.Info().
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("Package has scan result but security_scanned flag is false, needs update")
		return true, nil
	}

	// Check if scan is older than rescan interval
	timeSinceLastScan := time.Since(scanResult.ScannedAt)
	if timeSinceLastScan >= w.interval {
		return true, nil
	}

	return false, nil
}
