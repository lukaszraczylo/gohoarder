// Package prewarming runs background workers that pre-fetch hot packages
// to reduce first-request latency.
package prewarming

import (
	"context"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/rs/zerolog/log"
)

// LatestVersion asks the Fetcher to resolve the newest release itself.
const LatestVersion = "latest"

const (
	fetchTimeout     = 5 * time.Minute
	trendingPackages = 50
)

// Fetcher pulls an artifact through the proxy path, so it is cached and scanned like a client request.
type Fetcher interface {
	Fetch(ctx context.Context, pkg PackageInfo) error
}

// Popularity ranks packages by recent demand.
type Popularity interface {
	GetTopPackages(limit int) []analytics.PopularPackage
	GetTrendingPackages(limit int) []analytics.PopularPackage
}

// PackageInfo represents a package to pre-warm
type PackageInfo struct {
	Registry string
	Name     string
	Version  string
	Priority int
}

// Worker handles background pre-warming of popular packages
type Worker struct {
	popularity    Popularity
	fetcher       Fetcher
	cancel        context.CancelFunc
	runCtx        context.Context
	wg            sync.WaitGroup
	mu            sync.Mutex
	interval      time.Duration
	maxConcurrent int
	topPackages   int
	enabled       bool
}

// Config holds pre-warming worker configuration
type Config struct {
	Popularity    Popularity
	Fetcher       Fetcher
	Interval      time.Duration
	MaxConcurrent int
	TopPackages   int
	Enabled       bool
}

// NewWorker creates a new pre-warming worker
func NewWorker(cfg Config) *Worker {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 5
	}
	if cfg.TopPackages <= 0 {
		cfg.TopPackages = 100
	}

	worker := &Worker{
		popularity:    cfg.Popularity,
		fetcher:       cfg.Fetcher,
		interval:      cfg.Interval,
		maxConcurrent: cfg.MaxConcurrent,
		topPackages:   cfg.TopPackages,
		enabled:       cfg.Enabled,
	}

	if cfg.Enabled {
		log.Info().
			Dur("interval", cfg.Interval).
			Int("max_concurrent", cfg.MaxConcurrent).
			Msg("Pre-warming worker initialized")
	} else {
		log.Info().Msg("Pre-warming worker disabled")
	}

	return worker
}

// Start begins the pre-warming worker; it is a no-op when disabled or already started.
func (w *Worker) Start(ctx context.Context) {
	if !w.enabled {
		log.Debug().Msg("Pre-warming worker is disabled, not starting")
		return
	}
	if w.fetcher == nil || w.popularity == nil {
		log.Warn().Msg("Pre-warming worker has no fetcher or popularity source, not starting")
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.runCtx = runCtx
	w.wg.Add(1)
	go w.run(runCtx)
	log.Info().Msg("Pre-warming worker started")
}

// run is the main worker loop
func (w *Worker) run(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.prewarmPopularPackages(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Pre-warming worker stopped")
			return
		case <-ticker.C:
			w.prewarmPopularPackages(ctx)
		}
	}
}

// prewarmPopularPackages fetches and caches popular packages
func (w *Worker) prewarmPopularPackages(ctx context.Context) {
	log.Info().Msg("Starting pre-warming cycle")

	// Get popular packages from analytics
	popularPackages := w.popularity.GetTopPackages(w.topPackages)
	if len(popularPackages) == 0 {
		log.Debug().Msg("No popular packages found for pre-warming")
		return
	}

	// Get trending packages for additional candidates
	trendingPackages := w.popularity.GetTrendingPackages(trendingPackages)

	// Combine and deduplicate
	packages := w.combinePackages(popularPackages, trendingPackages)

	log.Info().
		Int("packages", len(packages)).
		Msg("Identified packages for pre-warming")

	// Create work queue
	workChan := make(chan PackageInfo, len(packages))
	for _, pkg := range packages {
		workChan <- PackageInfo{
			Registry: pkg.Registry,
			Name:     pkg.Name,
			Version:  LatestVersion,
			Priority: int(pkg.Downloads),
		}
	}
	close(workChan)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < w.maxConcurrent; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			w.processPackages(ctx, workerID, workChan)
		}(i)
	}

	wg.Wait()
	log.Info().Msg("Pre-warming cycle completed")
}

// processPackages processes packages from the work queue
func (w *Worker) processPackages(ctx context.Context, workerID int, workChan <-chan PackageInfo) {
	for pkg := range workChan {
		select {
		case <-ctx.Done():
			return
		default:
			_ = w.prewarmPackage(ctx, pkg, workerID) // logged inside
		}
	}
}

// prewarmPackage fetches a single package through the proxy path
func (w *Worker) prewarmPackage(ctx context.Context, pkg PackageInfo, workerID int) error {
	log.Debug().
		Int("worker", workerID).
		Str("registry", pkg.Registry).
		Str("package", pkg.Name).
		Str("version", pkg.Version).
		Msg("Pre-warming package")

	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	if err := w.fetcher.Fetch(reqCtx, pkg); err != nil {
		log.Error().
			Err(err).
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Msg("Failed to pre-warm package")
		return err
	}

	log.Info().
		Str("registry", pkg.Registry).
		Str("package", pkg.Name).
		Str("version", pkg.Version).
		Msg("Pre-warmed package")
	return nil
}

// combinePackages merges popular and trending packages, removing duplicates
func (w *Worker) combinePackages(popular, trending []analytics.PopularPackage) []analytics.PopularPackage {
	seen := make(map[string]bool)
	result := make([]analytics.PopularPackage, 0, len(popular)+len(trending))

	for _, pkg := range popular {
		key := pkg.Registry + ":" + pkg.Name
		if !seen[key] {
			result = append(result, pkg)
			seen[key] = true
		}
	}

	for _, pkg := range trending {
		key := pkg.Registry + ":" + pkg.Name
		if !seen[key] {
			result = append(result, pkg)
			seen[key] = true
		}
	}

	return result
}

// Stop stops the worker and waits for it; it is safe on a nil, disabled or never-started worker.
func (w *Worker) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()
	if cancel != nil {
		log.Info().Msg("Stopping pre-warming worker")
		cancel()
	}
	w.wg.Wait()
}

// TriggerPrewarm runs one cycle in the background. The cycle outlives ctx, which is
// usually a request context, and ends when the worker stops.
func (w *Worker) TriggerPrewarm(ctx context.Context) {
	if !w.enabled || w.fetcher == nil || w.popularity == nil {
		log.Warn().Msg("Cannot trigger pre-warm: worker is disabled or unconfigured")
		return
	}

	log.Info().Msg("Manual pre-warming triggered")
	w.mu.Lock()
	cycleCtx := w.runCtx
	w.mu.Unlock()
	if cycleCtx == nil {
		cycleCtx = context.WithoutCancel(ctx)
	}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		w.prewarmPopularPackages(cycleCtx)
	}()
}

// PrewarmPackage pre-warms a specific package
func (w *Worker) PrewarmPackage(ctx context.Context, registry, name, version string) error {
	if !w.enabled || w.fetcher == nil {
		log.Warn().Msg("Pre-warming worker is disabled or unconfigured")
		return nil
	}

	pkg := PackageInfo{
		Registry: registry,
		Name:     name,
		Version:  version,
		Priority: 100,
	}

	return w.prewarmPackage(ctx, pkg, 0)
}

// GetStatus returns the current status of the pre-warming worker
func (w *Worker) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"enabled":        w.enabled,
		"interval":       w.interval.String(),
		"max_concurrent": w.maxConcurrent,
	}
}
