package scanner

import (
	"context"
	"sync"
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
}

// NewRescanWorker creates a new rescan worker
func NewRescanWorker(manager *Manager, metadataStore metadata.MetadataStore, interval time.Duration) *RescanWorker {
	return &RescanWorker{
		manager:       manager,
		metadataStore: metadataStore,
		interval:      interval,
		stopCh:        make(chan struct{}),
	}
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

// rescanPackages re-scans packages that need updating
func (w *RescanWorker) rescanPackages(ctx context.Context) {
	log.Info().Msg("Starting package rescan cycle - checking all packages for scan status")

	// Get all packages
	packages, err := w.metadataStore.ListPackages(ctx, &metadata.ListOptions{})
	if err != nil {
		log.Error().Err(err).Msg("Failed to list packages for rescan")
		return
	}

	scanned := 0
	skipped := 0
	failed := 0

	for _, pkg := range packages {
		// Skip metadata entries (npm metadata pages, pypi pages, etc.)
		if pkg.Version == "list" || pkg.Version == "latest" || pkg.Version == "metadata" || pkg.Version == "page" {
			skipped++
			continue
		}

		// Check if package needs rescanning
		needsRescan, err := w.needsRescan(ctx, pkg)
		if err != nil {
			log.Error().
				Err(err).
				Str("package", pkg.Name).
				Str("version", pkg.Version).
				Msg("Failed to check rescan status")
			failed++
			continue
		}

		if !needsRescan {
			log.Debug().
				Str("package", pkg.Name).
				Str("version", pkg.Version).
				Bool("security_scanned", pkg.SecurityScanned).
				Msg("Package does not need rescanning, skipping")
			skipped++
			continue
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
			failed++
			continue
		}

		source := w.manager.currentFileSource()
		if source == nil {
			log.Debug().
				Str("registry", pkg.Registry).
				Str("package", pkg.Name).
				Str("version", pkg.Version).
				Msg("No file source configured, skipping rescan")
			skipped++
			continue
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
			failed++
			continue
		}

		// Perform the actual scan
		err = w.manager.ScanPackage(ctx, pkg.Registry, pkg.Name, pkg.Version, filePath)
		cleanup()
		if err != nil {
			log.Error().
				Err(err).
				Str("registry", pkg.Registry).
				Str("package", pkg.Name).
				Str("version", pkg.Version).
				Msg("Failed to rescan package")
			failed++
			continue
		}

		scanned++
	}

	log.Info().
		Int("total", len(packages)).
		Int("scanned", scanned).
		Int("skipped", skipped).
		Int("failed", failed).
		Msg("Rescan cycle completed")
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
