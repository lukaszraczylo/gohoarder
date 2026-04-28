// Package analytics tracks and analyzes package download events with
// in-memory aggregation and periodic background flushing.
package analytics

import (
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PackageDownload represents a package download event
type PackageDownload struct {
	Timestamp time.Time
	Registry  string
	Name      string
	Version   string
	ClientIP  string
	UserAgent string
	BytesSize int64
}

// PackageStats holds statistics for a package
type PackageStats struct {
	LastDownload   time.Time
	FirstSeen      time.Time
	Registry       string
	Name           string
	TotalDownloads int64
	UniqueVersions int
	BytesServed    int64
}

// TrendData represents trend information over time
type TrendData struct {
	Period    time.Duration
	Downloads int64
	Packages  int
}

// PopularPackage represents a popular package entry
type PopularPackage struct {
	Registry        string
	Name            string
	Downloads       int64
	RecentDownloads int64   // Downloads in last 7 days
	Trend           float64 // Growth rate
}

// Engine tracks and analyzes package downloads.
//
// Lock ordering: never hold both downloadsMu and statsMu at the same time.
// Code paths must acquire only one of the two; if they need both views, they
// must take a snapshot under the first lock and release it before taking the
// second.
type Engine struct {
	stats       map[string]*PackageStats
	flushTicker *time.Ticker
	stopChan    chan struct{}
	doneChan    chan struct{}
	downloads   []PackageDownload
	maxEvents   int
	downloadsMu sync.RWMutex
	statsMu     sync.RWMutex
	closeOnce   sync.Once
}

// Config holds analytics engine configuration
type Config struct {
	MaxEvents     int
	FlushInterval time.Duration
}

// NewEngine creates a new analytics engine
func NewEngine(cfg Config) *Engine {
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 10000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Minute
	}

	engine := &Engine{
		downloads:   make([]PackageDownload, 0, cfg.MaxEvents),
		stats:       make(map[string]*PackageStats),
		maxEvents:   cfg.MaxEvents,
		flushTicker: time.NewTicker(cfg.FlushInterval),
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
	}

	// Load existing stats from metadata store
	engine.loadStats()

	// Start background flush goroutine
	go engine.flushLoop()

	log.Info().
		Int("max_events", cfg.MaxEvents).
		Dur("flush_interval", cfg.FlushInterval).
		Msg("Analytics engine started")

	return engine
}

// TrackDownload records a package download event.
//
// Locks are taken sequentially (never nested) to avoid the lock-ordering
// inversion between downloadsMu and statsMu that exists elsewhere in the
// engine: append to the buffer under downloadsMu, release it, then update
// stats under statsMu.
func (e *Engine) TrackDownload(download PackageDownload) {
	// Append to buffer and decide whether buffer is full.
	e.downloadsMu.Lock()
	e.downloads = append(e.downloads, download)
	bufferFull := len(e.downloads) >= e.maxEvents
	e.downloadsMu.Unlock()

	// Update in-memory stats outside downloadsMu to keep the two locks
	// strictly disjoint.
	e.updateStats(download)

	// Flush if buffer is full. The flush goroutine acquires downloadsMu
	// itself; we must not hold any lock when spawning it.
	if bufferFull {
		go e.flush()
	}

	log.Debug().
		Str("registry", download.Registry).
		Str("package", download.Name).
		Str("version", download.Version).
		Msg("Download tracked")
}

// updateStats updates in-memory statistics
func (e *Engine) updateStats(download PackageDownload) {
	e.statsMu.Lock()
	defer e.statsMu.Unlock()

	key := download.Registry + ":" + download.Name
	stats, exists := e.stats[key]
	if !exists {
		stats = &PackageStats{
			Registry:  download.Registry,
			Name:      download.Name,
			FirstSeen: download.Timestamp,
		}
		e.stats[key] = stats
	}

	stats.TotalDownloads++
	stats.BytesServed += download.BytesSize
	stats.LastDownload = download.Timestamp

	// Track unique versions (simplified)
	stats.UniqueVersions++
}

// GetPackageStats returns statistics for a specific package
func (e *Engine) GetPackageStats(registry, name string) (*PackageStats, bool) {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()

	key := registry + ":" + name
	stats, exists := e.stats[key]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid race conditions
	statsCopy := *stats
	return &statsCopy, true
}

// GetTopPackages returns the most downloaded packages
func (e *Engine) GetTopPackages(limit int) []PopularPackage {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()

	packages := make([]PopularPackage, 0, len(e.stats))
	for _, stats := range e.stats {
		packages = append(packages, PopularPackage{
			Registry:  stats.Registry,
			Name:      stats.Name,
			Downloads: stats.TotalDownloads,
		})
	}

	// Sort by downloads descending
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Downloads > packages[j].Downloads
	})

	if limit > 0 && limit < len(packages) {
		packages = packages[:limit]
	}

	return packages
}

// GetTrendingPackages returns packages with growing popularity.
//
// The implementation takes a snapshot of stats under statsMu, releases it,
// and only then queries the downloads buffer. This preserves the invariant
// that downloadsMu and statsMu are never held simultaneously.
func (e *Engine) GetTrendingPackages(limit int) []PopularPackage {
	// Snapshot stats under statsMu only.
	type statsSnapshot struct {
		registry  string
		name      string
		downloads int64
	}
	e.statsMu.RLock()
	snapshot := make([]statsSnapshot, 0, len(e.stats))
	for _, stats := range e.stats {
		snapshot = append(snapshot, statsSnapshot{
			registry:  stats.Registry,
			name:      stats.Name,
			downloads: stats.TotalDownloads,
		})
	}
	e.statsMu.RUnlock()

	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)

	packages := make([]PopularPackage, 0, len(snapshot))
	for _, s := range snapshot {
		// Calculate recent downloads (last 7 days). Acquires downloadsMu
		// only; statsMu is no longer held here.
		recent := e.getRecentDownloads(s.registry, s.name, sevenDaysAgo)

		// Calculate trend (simple growth rate)
		trend := 0.0
		if s.downloads > 0 {
			trend = float64(recent) / float64(s.downloads) * 100
		}

		packages = append(packages, PopularPackage{
			Registry:        s.registry,
			Name:            s.name,
			Downloads:       s.downloads,
			RecentDownloads: recent,
			Trend:           trend,
		})
	}

	// Sort by trend descending
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Trend > packages[j].Trend
	})

	if limit > 0 && limit < len(packages) {
		packages = packages[:limit]
	}

	return packages
}

// getRecentDownloads counts downloads since a given time
func (e *Engine) getRecentDownloads(registry, name string, since time.Time) int64 {
	e.downloadsMu.RLock()
	defer e.downloadsMu.RUnlock()

	count := int64(0)
	for _, download := range e.downloads {
		if download.Registry == registry &&
			download.Name == name &&
			download.Timestamp.After(since) {
			count++
		}
	}
	return count
}

// GetTrends returns download trends over different time periods
func (e *Engine) GetTrends() []TrendData {
	e.downloadsMu.RLock()
	defer e.downloadsMu.RUnlock()

	now := time.Now()
	periods := []time.Duration{
		1 * time.Hour,
		24 * time.Hour,
		7 * 24 * time.Hour,
		30 * 24 * time.Hour,
	}

	trends := make([]TrendData, len(periods))
	for i, period := range periods {
		since := now.Add(-period)
		downloads := int64(0)
		packages := make(map[string]bool)

		for _, download := range e.downloads {
			if download.Timestamp.After(since) {
				downloads++
				packages[download.Registry+":"+download.Name] = true
			}
		}

		trends[i] = TrendData{
			Period:    period,
			Downloads: downloads,
			Packages:  len(packages),
		}
	}

	return trends
}

// GetTotalStats returns overall statistics
func (e *Engine) GetTotalStats() map[string]interface{} {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()

	totalDownloads := int64(0)
	totalBytes := int64(0)
	registries := make(map[string]int64)

	for _, stats := range e.stats {
		totalDownloads += stats.TotalDownloads
		totalBytes += stats.BytesServed
		registries[stats.Registry]++
	}

	return map[string]interface{}{
		"total_packages":  len(e.stats),
		"total_downloads": totalDownloads,
		"total_bytes":     totalBytes,
		"registries":      registries,
	}
}

// flushLoop periodically flushes download events to metadata store.
// Closes doneChan after the final flush so Close can wait for it.
func (e *Engine) flushLoop() {
	defer close(e.doneChan)
	for {
		select {
		case <-e.flushTicker.C:
			e.flush()
		case <-e.stopChan:
			e.flush() // Final flush
			return
		}
	}
}

// flush persists download events to metadata store
func (e *Engine) flush() {
	e.downloadsMu.Lock()
	downloads := e.downloads
	e.downloads = make([]PackageDownload, 0, e.maxEvents)
	e.downloadsMu.Unlock()

	if len(downloads) == 0 {
		return
	}

	log.Debug().
		Int("events", len(downloads)).
		Msg("Flushing analytics events")

	// In a real implementation, this would persist to the metadata store
	// For now, we just clear the buffer
	// TODO: Add actual persistence when metadata store supports analytics tables
}

// loadStats loads existing statistics from metadata store
func (e *Engine) loadStats() {
	// TODO: Load stats from metadata store when analytics tables are implemented
	log.Debug().Msg("Loading analytics stats from metadata store")
}

// Close stops the analytics engine. Safe to call multiple times.
//
// Shutdown sequence:
//  1. signal stopChan (sync.Once-guarded so we never close twice)
//  2. stop the ticker
//  3. wait for flushLoop to drain and run its final flush via doneChan
//
// We do not call flush() directly here — flushLoop owns the final flush, so
// there is exactly one flush at shutdown.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		close(e.stopChan)
		e.flushTicker.Stop()
		<-e.doneChan
		log.Info().Msg("Analytics engine stopped")
	})
}

// GetRegistryStats returns per-registry statistics
func (e *Engine) GetRegistryStats(registry string) map[string]interface{} {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()

	totalPackages := 0
	totalDownloads := int64(0)
	totalBytes := int64(0)

	for _, stats := range e.stats {
		if stats.Registry == registry {
			totalPackages++
			totalDownloads += stats.TotalDownloads
			totalBytes += stats.BytesServed
		}
	}

	return map[string]interface{}{
		"registry":        registry,
		"total_packages":  totalPackages,
		"total_downloads": totalDownloads,
		"total_bytes":     totalBytes,
	}
}

// SearchPackages finds packages matching a query
func (e *Engine) SearchPackages(query string, limit int) []PackageStats {
	e.statsMu.RLock()
	defer e.statsMu.RUnlock()

	results := make([]PackageStats, 0)
	for _, stats := range e.stats {
		// Simple substring search
		if contains(stats.Name, query) {
			results = append(results, *stats)
		}
		if len(results) >= limit {
			break
		}
	}

	// Sort by downloads
	sort.Slice(results, func(i, j int) bool {
		return results[i].TotalDownloads > results[j].TotalDownloads
	})

	return results
}

// contains performs a case-insensitive substring search
func contains(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return len(sLower) >= len(substrLower) &&
		findSubstring(sLower, substrLower)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
