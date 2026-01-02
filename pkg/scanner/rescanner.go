package scanner

import (
	"context"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// RescanWorker handles periodic re-scanning of cached packages
type RescanWorker struct {
	manager       *Manager
	metadataStore metadata.MetadataStore
	interval      time.Duration
	stopCh        chan struct{}
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

	// Run initial scan immediately
	w.rescanPackages(ctx)

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

// Stop stops the rescan worker
func (w *RescanWorker) Stop() {
	close(w.stopCh)
}

// rescanPackages re-scans packages that need updating
func (w *RescanWorker) rescanPackages(ctx context.Context) {
	log.Info().Msg("Starting package rescan cycle")

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
			skipped++
			continue
		}

		// Rescan the package
		// Note: We need the file path - we'll need to reconstruct it or get it from storage
		// For now, we'll just log and skip actual rescanning
		log.Info().
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Str("version", pkg.Version).
			Msg("Package needs rescanning")

		// TODO: Implement actual rescanning by:
		// 1. Retrieving package file from storage
		// 2. Scanning it
		// This would require access to storage backend

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
		return true, nil
	}

	// Check if scan is older than rescan interval
	timeSinceLastScan := time.Since(scanResult.ScannedAt)
	if timeSinceLastScan >= w.interval {
		return true, nil
	}

	return false, nil
}
