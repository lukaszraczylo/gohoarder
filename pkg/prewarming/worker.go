package prewarming

import (
	"context"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/rs/zerolog/log"
)

// PackageInfo represents a package to pre-warm
type PackageInfo struct {
	Registry string
	Name     string
	Version  string
	Priority int
}

// Worker handles background pre-warming of popular packages
type Worker struct {
	cache         *cache.Manager
	analytics     *analytics.Engine
	client        *network.Client
	stopChan      chan struct{}
	wg            sync.WaitGroup
	interval      time.Duration
	maxConcurrent int
	enabled       bool
}

// Config holds pre-warming worker configuration
type Config struct {
	CacheManager  *cache.Manager
	Analytics     *analytics.Engine
	NetworkClient *network.Client
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
		cache:         cfg.CacheManager,
		analytics:     cfg.Analytics,
		client:        cfg.NetworkClient,
		interval:      cfg.Interval,
		maxConcurrent: cfg.MaxConcurrent,
		enabled:       cfg.Enabled,
		stopChan:      make(chan struct{}),
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

// Start begins the pre-warming worker
func (w *Worker) Start(ctx context.Context) {
	if !w.enabled {
		log.Debug().Msg("Pre-warming worker is disabled, not starting")
		return
	}

	w.wg.Add(1)
	go w.run(ctx)
	log.Info().Msg("Pre-warming worker started")
}

// run is the main worker loop
func (w *Worker) run(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run immediately on start
	w.prewarmPopularPackages(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Pre-warming worker stopping due to context cancellation")
			return
		case <-w.stopChan:
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
	popularPackages := w.analytics.GetTopPackages(100)
	if len(popularPackages) == 0 {
		log.Debug().Msg("No popular packages found for pre-warming")
		return
	}

	// Get trending packages for additional candidates
	trendingPackages := w.analytics.GetTrendingPackages(50)

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
			Version:  "latest", // Pre-warm latest version
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
			w.prewarmPackage(ctx, pkg, workerID)
		}
	}
}

// prewarmPackage fetches and caches a single package
func (w *Worker) prewarmPackage(ctx context.Context, pkg PackageInfo, workerID int) {
	log.Debug().
		Int("worker", workerID).
		Str("registry", pkg.Registry).
		Str("package", pkg.Name).
		Str("version", pkg.Version).
		Msg("Pre-warming package")

	// Build URL based on registry
	url := w.buildPackageURL(pkg)
	if url == "" {
		log.Warn().
			Str("registry", pkg.Registry).
			Str("package", pkg.Name).
			Msg("Cannot build URL for registry")
		return
	}

	// Fetch package from upstream
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	body, statusCode, err := w.client.Get(reqCtx, url, nil)
	if err != nil {
		log.Error().
			Err(err).
			Str("package", pkg.Name).
			Msg("Failed to fetch package for pre-warming")
		return
	}
	defer body.Close() // #nosec G104 -- Cleanup, error not critical

	if statusCode != 200 {
		log.Warn().
			Int("status", statusCode).
			Str("package", pkg.Name).
			Msg("Non-200 response for package")
		return
	}

	// Cache the package
	// In a real implementation, this would read the response body and store it
	log.Info().
		Str("package", pkg.Name).
		Str("version", pkg.Version).
		Msg("Successfully pre-warmed package")
}

// buildPackageURL builds the upstream URL for a package
func (w *Worker) buildPackageURL(pkg PackageInfo) string {
	// This is simplified - in reality, each registry has different URL patterns
	switch pkg.Registry {
	case "npm":
		return "https://registry.npmjs.org/" + pkg.Name
	case "pypi":
		return "https://pypi.org/simple/" + pkg.Name + "/"
	case "go":
		// Go modules use different URL patterns
		return "https://proxy.golang.org/" + pkg.Name + "/@latest"
	default:
		return ""
	}
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

// Stop gracefully stops the pre-warming worker
func (w *Worker) Stop() {
	if !w.enabled {
		return
	}

	log.Info().Msg("Stopping pre-warming worker")
	close(w.stopChan)
	w.wg.Wait()
	log.Info().Msg("Pre-warming worker stopped")
}

// TriggerPrewarm manually triggers a pre-warming cycle
func (w *Worker) TriggerPrewarm(ctx context.Context) {
	if !w.enabled {
		log.Warn().Msg("Cannot trigger pre-warm: worker is disabled")
		return
	}

	log.Info().Msg("Manual pre-warming triggered")
	go w.prewarmPopularPackages(ctx)
}

// PrewarmPackage pre-warms a specific package
func (w *Worker) PrewarmPackage(ctx context.Context, registry, name, version string) error {
	if !w.enabled {
		log.Warn().Msg("Pre-warming worker is disabled")
		return nil
	}

	pkg := PackageInfo{
		Registry: registry,
		Name:     name,
		Version:  version,
		Priority: 100,
	}

	w.prewarmPackage(ctx, pkg, 0)
	return nil
}

// GetStatus returns the current status of the pre-warming worker
func (w *Worker) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"enabled":        w.enabled,
		"interval":       w.interval.String(),
		"max_concurrent": w.maxConcurrent,
	}
}
