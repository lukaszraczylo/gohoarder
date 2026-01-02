package common

import (
	"context"
	"net/http"
	"time"
)

// ProxyHandler defines the common interface for all registry proxies
type ProxyHandler interface {
	http.Handler // ServeHTTP(w http.ResponseWriter, r *http.Request)

	// GetRegistry returns the registry type (npm, pypi, go)
	GetRegistry() string

	// Health checks if the proxy can reach its upstream
	Health(ctx context.Context) error
}

// Stats represents proxy statistics
type Stats struct {
	Registry        string
	TotalRequests   int64
	CacheHits       int64
	CacheMisses     int64
	UpstreamErrors  int64
	AvgResponseTime time.Duration
	LastUpdated     time.Time
}
