package server

import (
	"fmt"
	"net/http"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/health"
	"github.com/lukaszraczylo/gohoarder/pkg/logger"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
)

// Server wraps http.Server with configuration
type Server struct {
	*http.Server
	config        *config.Config
	healthChecker *health.Checker
}

// New creates a new HTTP server
func New(cfg *config.Config, healthChecker *health.Checker) (*Server, error) {
	mux := http.NewServeMux()

	// Register routes
	registerRoutes(mux, cfg, healthChecker)

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      logger.Middleware(mux),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return &Server{
		Server:        srv,
		config:        cfg,
		healthChecker: healthChecker,
	}, nil
}

// registerRoutes registers all HTTP routes
func registerRoutes(mux *http.ServeMux, cfg *config.Config, healthChecker *health.Checker) {
	// Health endpoints
	mux.HandleFunc("/health", healthChecker.HealthHandler())
	mux.HandleFunc("/health/ready", healthChecker.ReadyHandler())

	// Metrics endpoint
	mux.Handle("/metrics", metrics.Handler())

	// API endpoints
	mux.HandleFunc("/api/v1/info", handleInfo(cfg))

	// Package manager proxy endpoints (placeholders for now)
	if cfg.Handlers.Go.Enabled {
		mux.HandleFunc("/go/", handleGoProxy())
	}
	if cfg.Handlers.NPM.Enabled {
		mux.HandleFunc("/npm/", handleNPMProxy())
	}
	if cfg.Handlers.PyPI.Enabled {
		mux.HandleFunc("/pypi/", handlePyPIProxy())
	}

	// Root endpoint
	mux.HandleFunc("/", handleRoot())
}

// handleInfo returns server information
func handleInfo(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := map[string]interface{}{
			"name":    "GoHoarder",
			"version": "dev",
			"handlers": map[string]bool{
				"go":   cfg.Handlers.Go.Enabled,
				"npm":  cfg.Handlers.NPM.Enabled,
				"pypi": cfg.Handlers.PyPI.Enabled,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"success":true,"data":%v}`, toJSON(info))
	}
}

// handleGoProxy handles Go module proxy requests
func handleGoProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement Go proxy handler
		http.Error(w, `{"success":false,"error":{"code":"NOT_IMPLEMENTED","message":"Go proxy not yet implemented"}}`, http.StatusNotImplemented)
	}
}

// handleNPMProxy handles NPM registry requests
func handleNPMProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement NPM proxy handler
		http.Error(w, `{"success":false,"error":{"code":"NOT_IMPLEMENTED","message":"NPM proxy not yet implemented"}}`, http.StatusNotImplemented)
	}
}

// handlePyPIProxy handles PyPI requests
func handlePyPIProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement PyPI proxy handler
		http.Error(w, `{"success":false,"error":{"code":"NOT_IMPLEMENTED","message":"PyPI proxy not yet implemented"}}`, http.StatusNotImplemented)
	}
}

// handleRoot handles root path
func handleRoot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"success":true,"data":{"message":"GoHoarder - Universal Package Cache Proxy","docs":"https://github.com/lukaszraczylo/gohoarder"}}`)
	}
}

// toJSON is a simple JSON encoder (replace with proper implementation)
func toJSON(v interface{}) string {
	// Simplified for now - proper implementation would use goccy/go-json
	return fmt.Sprintf("%v", v)
}
