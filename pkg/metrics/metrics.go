package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"handler", "method", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gohoarder_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"handler", "method"},
	)

	// Cache metrics
	CacheRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_cache_requests_total",
			Help: "Total number of cache requests",
		},
		[]string{"status", "handler"}, // hit, miss, error
	)

	CacheSizeBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gohoarder_cache_size_bytes",
			Help: "Current cache size in bytes",
		},
		[]string{"backend"},
	)

	CacheItemsTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gohoarder_cache_items_total",
			Help: "Total number of cached items",
		},
		[]string{"handler"},
	)

	CacheEvictions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_cache_evictions_total",
			Help: "Total number of cache evictions",
		},
		[]string{"reason"}, // ttl, lru, manual
	)

	// Storage metrics
	StorageOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_storage_operations_total",
			Help: "Total number of storage operations",
		},
		[]string{"backend", "operation", "status"}, // get, put, delete
	)

	StorageQuotaBytes = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gohoarder_storage_quota_bytes",
			Help: "Storage quota in bytes per project",
		},
		[]string{"project"},
	)

	// Upstream metrics
	UpstreamRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_upstream_requests_total",
			Help: "Total number of upstream requests",
		},
		[]string{"registry", "status"},
	)

	UpstreamDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gohoarder_upstream_duration_seconds",
			Help:    "Upstream request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"registry"},
	)

	// Security metrics
	SecurityScans = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_security_scans_total",
			Help: "Total number of security scans",
		},
		[]string{"scanner", "result"}, // clean, blocked, error
	)

	VulnerabilitiesFound = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gohoarder_vulnerabilities_found_total",
			Help: "Total number of vulnerabilities found",
		},
		[]string{"severity"}, // low, medium, high, critical
	)

	// Circuit breaker metrics
	CircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gohoarder_circuit_breaker_state",
			Help: "Circuit breaker state (0=closed, 1=open, 2=half-open)",
		},
		[]string{"name"},
	)
)

// Handler returns the Prometheus HTTP handler
func Handler() http.Handler {
	return promhttp.Handler()
}

// RecordCacheHit records a cache hit
func RecordCacheHit(handler string) {
	CacheRequests.WithLabelValues("hit", handler).Inc()
}

// RecordCacheMiss records a cache miss
func RecordCacheMiss(handler string) {
	CacheRequests.WithLabelValues("miss", handler).Inc()
}

// UpdateCacheSize updates the cache size metric
func UpdateCacheSize(backend string, bytes int64) {
	CacheSizeBytes.WithLabelValues(backend).Set(float64(bytes))
}

// RecordCacheEviction records a cache eviction
func RecordCacheEviction(reason string) {
	CacheEvictions.WithLabelValues(reason).Inc()
}

// RecordStorageOperation records a storage operation
func RecordStorageOperation(backend, operation, status string) {
	StorageOperations.WithLabelValues(backend, operation, status).Inc()
}

// RecordUpstreamRequest records an upstream request
func RecordUpstreamRequest(registry, status string) {
	UpstreamRequests.WithLabelValues(registry, status).Inc()
}

// UpdateCircuitBreakerState updates the circuit breaker state
func UpdateCircuitBreakerState(name string, state int) {
	CircuitBreakerState.WithLabelValues(name).Set(float64(state))
}
