package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/cdn"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/health"
	"github.com/lukaszraczylo/gohoarder/pkg/lock"
	"github.com/lukaszraczylo/gohoarder/pkg/logger"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	metafile "github.com/lukaszraczylo/gohoarder/pkg/metadata/file"
	metasqlite "github.com/lukaszraczylo/gohoarder/pkg/metadata/sqlite"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/lukaszraczylo/gohoarder/pkg/prewarming"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/goproxy"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/npm"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/pypi"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
	"github.com/rs/zerolog/log"
)

// App represents the main application
type App struct {
	config          *config.Config
	server          *http.Server
	healthChecker   *health.Checker
	cache           *cache.Manager
	storage         storage.StorageBackend
	metadata        metadata.Store
	authManager     *auth.Manager
	networkClient   *network.Client
	scanManager     *scanner.Manager
	rescanWorker    *scanner.RescanWorker
	analyticsEngine *analytics.Engine
	wsServer        *websocket.Server
	prewarmWorker   *prewarming.Worker
	lockManager     *lock.Manager
	cdnMiddleware   *cdn.Middleware
}

// New creates a new application instance
func New(cfg *config.Config) (*App, error) {
	app := &App{
		config: cfg,
	}

	// Initialize components
	if err := app.initializeComponents(); err != nil {
		return nil, err
	}

	// Setup HTTP server and routes
	if err := app.setupServer(); err != nil {
		return nil, err
	}

	return app, nil
}

// initializeComponents initializes all application components
func (a *App) initializeComponents() error {
	var err error

	// Initialize storage backend
	log.Info().Str("backend", a.config.Storage.Backend).Msg("Initializing storage backend")
	switch a.config.Storage.Backend {
	case "filesystem":
		a.storage, err = filesystem.New(a.config.Storage.Path, a.config.Cache.MaxSizeBytes)
	default:
		a.storage, err = filesystem.New(a.config.Storage.Path, a.config.Cache.MaxSizeBytes)
	}
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize metadata store
	log.Info().Str("backend", a.config.Metadata.Backend).Msg("Initializing metadata store")
	switch a.config.Metadata.Backend {
	case "sqlite":
		a.metadata, err = metasqlite.New(metasqlite.Config{
			Path: a.config.Metadata.Connection,
		})
	case "file":
		a.metadata, err = metafile.New(metafile.Config{
			Path: a.config.Metadata.Connection,
		})
	default:
		a.metadata, err = metasqlite.New(metasqlite.Config{
			Path: "gohoarder.db",
		})
	}
	if err != nil {
		return fmt.Errorf("failed to initialize metadata: %w", err)
	}

	// Initialize scanner manager first (before cache)
	log.Info().Msg("Initializing security scanner")
	a.scanManager, err = scanner.New(a.config.Security, a.metadata)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	// Initialize cache manager with scanner
	log.Info().Msg("Initializing cache manager")
	a.cache, err = cache.New(a.storage, a.metadata, a.scanManager, cache.Config{
		DefaultTTL:      a.config.Cache.DefaultTTL,
		CleanupInterval: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Initialize network client
	log.Info().Msg("Initializing network client")
	a.networkClient = network.NewClient(network.Config{
		Timeout:    5 * time.Minute,
		MaxRetries: 3,
		RetryDelay: 1 * time.Second,
		RateLimit:  100,
		RateBurst:  10,
		CircuitBreaker: network.CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: 5,
			SuccessThreshold: 2,
			Timeout:          30 * time.Second,
		},
		UserAgent: "GoHoarder/1.0",
	})

	// Initialize authentication manager
	log.Info().Msg("Initializing authentication manager")
	a.authManager = auth.New()

	// Initialize rescan worker if enabled
	if a.config.Security.Enabled && a.config.Security.RescanInterval > 0 {
		log.Info().Dur("interval", a.config.Security.RescanInterval).Msg("Initializing package rescan worker")
		a.rescanWorker = scanner.NewRescanWorker(a.scanManager, a.metadata, a.config.Security.RescanInterval)
	}

	// Initialize analytics engine
	log.Info().Msg("Initializing analytics engine")
	a.analyticsEngine = analytics.NewEngine(analytics.Config{
		MaxEvents:     10000,
		FlushInterval: 5 * time.Minute,
	})

	// Initialize WebSocket server
	log.Info().Msg("Initializing WebSocket server")
	a.wsServer = websocket.NewServer(websocket.Config{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins in development
		},
	})

	// Initialize pre-warming worker
	log.Info().Msg("Initializing pre-warming worker")
	a.prewarmWorker = prewarming.NewWorker(prewarming.Config{
		Enabled:       false, // Disabled by default
		Interval:      1 * time.Hour,
		MaxConcurrent: 5,
		CacheManager:  a.cache,
		Analytics:     a.analyticsEngine,
		NetworkClient: a.networkClient,
	})

	// Initialize CDN middleware
	log.Info().Msg("Initializing CDN middleware")
	a.cdnMiddleware = cdn.NewMiddleware(cdn.Config{
		DefaultCacheControl: cdn.CacheControl{
			Public:  true,
			MaxAge:  3600,
			SMaxAge: 7200,
		},
		EnableETag: true,
		EnableVary: true,
	})

	// Initialize health checker
	a.healthChecker = health.New()
	a.healthChecker.AddCheck("storage", func(ctx context.Context) (health.Status, string) {
		if err := a.storage.Health(ctx); err != nil {
			return health.StatusUnhealthy, err.Error()
		}
		return health.StatusHealthy, ""
	})
	a.healthChecker.AddCheck("metadata", func(ctx context.Context) (health.Status, string) {
		if err := a.metadata.Health(ctx); err != nil {
			return health.StatusUnhealthy, err.Error()
		}
		return health.StatusHealthy, ""
	})
	a.healthChecker.AddCheck("cache", func(ctx context.Context) (health.Status, string) {
		return health.StatusHealthy, "" // Cache is always healthy if initialized
	})
	a.healthChecker.AddCheck("scanner", func(ctx context.Context) (health.Status, string) {
		if a.config.Security.Enabled {
			if err := a.scanManager.Health(ctx); err != nil {
				return health.StatusUnhealthy, err.Error()
			}
		}
		return health.StatusHealthy, ""
	})

	log.Info().Msg("All components initialized successfully")
	return nil
}

// setupServer sets up the HTTP server and routes
func (a *App) setupServer() error {
	mux := http.NewServeMux()

	// Health and metrics endpoints
	mux.HandleFunc("/health", a.healthChecker.HealthHandler())
	mux.HandleFunc("/health/ready", a.healthChecker.ReadyHandler())
	mux.Handle("/metrics", metrics.Handler())

	// WebSocket endpoint
	mux.HandleFunc("/ws", a.wsServer.HandleWebSocket)

	// API endpoints
	mux.HandleFunc("/api/packages/", a.handlePackages) // Handles packages and vulnerabilities
	mux.HandleFunc("/api/stats", a.handleStats)
	mux.HandleFunc("/api/info", a.handleInfo)

	// Admin endpoints (bypass management)
	mux.HandleFunc("/api/admin/bypasses/", a.handleBypassByID)  // Must come before /api/admin/bypasses
	mux.HandleFunc("/api/admin/bypasses", a.handleAdminBypasses)

	// Proxy handlers
	goProxyHandler := goproxy.New(a.cache, a.networkClient, goproxy.Config{
		Upstream: "https://proxy.golang.org",
		SumDBURL: "https://sum.golang.org",
	})
	mux.Handle("/go/", http.StripPrefix("/go", goProxyHandler))

	npmProxyHandler := npm.New(a.cache, a.networkClient, npm.Config{
		Upstream: "https://registry.npmjs.org",
	})
	mux.Handle("/npm/", http.StripPrefix("/npm", npmProxyHandler))

	pypiProxyHandler := pypi.New(a.cache, a.networkClient, pypi.Config{
		Upstream: "https://pypi.org/simple",
	})
	mux.Handle("/pypi/", http.StripPrefix("/pypi", pypiProxyHandler))

	// Serve frontend static files
	frontendDir := "frontend/dist"
	if _, err := os.Stat(frontendDir); err == nil {
		log.Info().Str("dir", frontendDir).Msg("Serving frontend static files")
		fs := http.FileServer(http.Dir(frontendDir))
		mux.Handle("/", fs)
	} else {
		log.Warn().Msg("Frontend dist directory not found, frontend won't be served")
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `
				<html>
				<head><title>GoHoarder</title></head>
				<body>
					<h1>GoHoarder Package Cache Proxy</h1>
					<p>Frontend not built. Build with: <code>cd frontend && npm run build</code></p>
					<h2>Available Endpoints:</h2>
					<ul>
						<li><a href="/health">Health Check</a></li>
						<li><a href="/metrics">Metrics</a></li>
						<li><a href="/api/stats">Statistics API</a></li>
					</ul>
				</body>
				</html>
			`)
		})
	}

	// Wrap with logging middleware
	handler := logger.Middleware(mux)

	// Create HTTP server
	a.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port),
		Handler:      handler,
		ReadTimeout:  a.config.Server.ReadTimeout,
		WriteTimeout: a.config.Server.WriteTimeout,
	}

	log.Info().
		Str("addr", a.server.Addr).
		Msg("HTTP server configured")

	return nil
}

// Run starts the application
func (a *App) Run() error {
	ctx := context.Background()

	// Start WebSocket server
	a.wsServer.Start(ctx)

	// Start pre-warming worker
	a.prewarmWorker.Start(ctx)

	// Start rescan worker if enabled
	if a.rescanWorker != nil {
		go a.rescanWorker.Start(ctx)
	}

	// Start HTTP server in goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Info().
			Str("addr", a.server.Addr).
			Msg("Starting HTTP server")
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigChan:
		log.Info().
			Str("signal", sig.String()).
			Msg("Shutdown signal received")
	}

	// Graceful shutdown
	return a.Shutdown()
}

// Shutdown gracefully shuts down the application
func (a *App) Shutdown() error {
	log.Info().Msg("Starting graceful shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop HTTP server
	if err := a.server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Error shutting down HTTP server")
	}

	// Stop pre-warming worker
	a.prewarmWorker.Stop()

	// Stop rescan worker if running
	if a.rescanWorker != nil {
		a.rescanWorker.Stop()
	}

	// Close analytics engine
	a.analyticsEngine.Close()

	// Close storage
	if err := a.storage.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing storage")
	}

	// Close metadata store
	if err := a.metadata.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing metadata store")
	}

	// Close lock manager if initialized
	if a.lockManager != nil {
		if err := a.lockManager.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing lock manager")
		}
	}

	log.Info().Msg("Shutdown complete")
	return nil
}
