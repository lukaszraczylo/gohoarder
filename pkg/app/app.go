package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/cdn"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/health"
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
	"github.com/lukaszraczylo/gohoarder/pkg/storage/s3"
	"github.com/lukaszraczylo/gohoarder/pkg/storage/smb"
	"github.com/lukaszraczylo/gohoarder/pkg/vcs"
	"github.com/lukaszraczylo/gohoarder/pkg/websocket"
	"github.com/rs/zerolog/log"
)

// App represents the main application
type App struct {
	config          *config.Config
	app             *fiber.App
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
	case "s3":
		a.storage, err = s3.New(s3.Config{
			Region:          a.config.Storage.S3.Region,
			Bucket:          a.config.Storage.S3.Bucket,
			Prefix:          a.config.Storage.S3.Prefix,
			AccessKeyID:     a.config.Storage.S3.AccessKeyID,
			SecretAccessKey: a.config.Storage.S3.SecretAccessKey,
			Endpoint:        a.config.Storage.S3.Endpoint,
			ForcePathStyle:  a.config.Storage.S3.ForcePathStyle,
			MaxSizeBytes:    a.config.Cache.MaxSizeBytes,
		})
	case "smb":
		a.storage, err = smb.New(smb.Config{
			Host:         a.config.Storage.SMB.Host,
			Port:         445, // Default SMB port
			Share:        a.config.Storage.SMB.Share,
			Path:         a.config.Storage.Path,
			Username:     a.config.Storage.SMB.Username,
			Password:     a.config.Storage.SMB.Password,
			Domain:       a.config.Storage.SMB.Domain,
			MaxSizeBytes: a.config.Cache.MaxSizeBytes,
			PoolSize:     5, // Default connection pool size
		})
	default:
		log.Warn().
			Str("backend", a.config.Storage.Backend).
			Msg("Unknown storage backend, defaulting to filesystem")
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
			Path:    a.config.Metadata.Connection,
			WALMode: a.config.Metadata.SQLite.WALMode,
		})
	case "file":
		a.metadata, err = metafile.New(metafile.Config{
			Path: a.config.Metadata.Connection,
		})
	default:
		a.metadata, err = metasqlite.New(metasqlite.Config{
			Path:    "gohoarder.db",
			WALMode: false, // Default to DELETE mode for compatibility
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

	// Initialize analytics engine first (needed by cache)
	log.Info().Msg("Initializing analytics engine")
	a.analyticsEngine = analytics.NewEngine(analytics.Config{
		MaxEvents:     10000,
		FlushInterval: 5 * time.Minute,
	})

	// Initialize cache manager with scanner and analytics
	log.Info().Msg("Initializing cache manager")
	a.cache, err = cache.New(a.storage, a.metadata, a.scanManager, a.analyticsEngine, cache.Config{
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
		a.rescanWorker = scanner.NewRescanWorker(a.scanManager, a.metadata, a.storage, a.config.Security.RescanInterval)
	}

	// Initialize WebSocket server
	log.Info().Msg("Initializing WebSocket server")
	a.wsServer = websocket.NewServer(websocket.Config{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(_ *http.Request) bool {
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

// setupServer sets up the Fiber server and routes
func (a *App) setupServer() error {
	// Create Fiber app
	a.app = fiber.New(fiber.Config{
		ReadTimeout:  a.config.Server.ReadTimeout,
		WriteTimeout: a.config.Server.WriteTimeout,
		ServerHeader: "GoHoarder",
		AppName:      "GoHoarder v1.0",
	})

	// Health and metrics endpoints (adapted from net/http)
	a.app.Get("/health", adaptor.HTTPHandlerFunc(a.healthChecker.HealthHandler()))
	a.app.Get("/health/ready", adaptor.HTTPHandlerFunc(a.healthChecker.ReadyHandler()))
	a.app.Get("/metrics", adaptor.HTTPHandler(metrics.Handler()))

	// WebSocket endpoint (adapted from net/http)
	a.app.Get("/ws", adaptor.HTTPHandlerFunc(a.wsServer.HandleWebSocket))

	// API endpoints
	a.app.Get("/api/config", a.handleConfig)
	a.app.All("/api/packages/*", a.handlePackages) // Handles packages and vulnerabilities
	a.app.Get("/api/stats", a.handleStats)
	a.app.Get("/api/stats/timeseries", a.handleTimeSeriesStats)
	a.app.Get("/api/info", a.handleInfo)

	// Analytics endpoints
	a.app.Get("/api/analytics/top", a.handleAnalyticsTopPackages)
	a.app.Get("/api/analytics/trending", a.handleAnalyticsTrendingPackages)
	a.app.Get("/api/analytics/trends", a.handleAnalyticsTrends)
	a.app.Get("/api/analytics/total", a.handleAnalyticsTotalStats)
	a.app.Get("/api/analytics/registry/:registry", a.handleAnalyticsRegistryStats)
	a.app.Get("/api/analytics/package/:registry/:name", a.handleAnalyticsPackageStats)
	a.app.Get("/api/analytics/search", a.handleAnalyticsSearch)

	// Admin endpoints (bypass management)
	a.app.All("/api/admin/bypasses/:id?", a.requireAdmin, a.handleAdminBypasses)

	// Admin endpoints (pre-warming)
	a.app.Get("/api/admin/prewarming/status", a.requireAdmin, a.handlePrewarmingStatus)
	a.app.Post("/api/admin/prewarming/trigger", a.requireAdmin, a.handlePrewarmingTrigger)
	a.app.Post("/api/admin/prewarming/package", a.requireAdmin, a.handlePrewarmingPackage)

	// Admin endpoints (API key management)
	a.app.Post("/api/admin/keys", a.requireAdmin, a.handleGenerateAPIKey)
	a.app.Get("/api/admin/keys", a.requireAdmin, a.handleListAPIKeys)
	a.app.Delete("/api/admin/keys/:key_id", a.requireAdmin, a.handleRevokeAPIKey)

	// Proxy handlers (adapted from net/http)
	// Load git credentials if configured
	var credStore *vcs.CredentialStore
	if a.config.Handlers.Go.GitCredentialsFile != "" {
		credStore = vcs.NewCredentialStore()
		if err := credStore.LoadFromFile(a.config.Handlers.Go.GitCredentialsFile); err != nil {
			log.Error().
				Err(err).
				Str("file", a.config.Handlers.Go.GitCredentialsFile).
				Msg("Failed to load git credentials, continuing without pattern-based credentials")
		} else if err := credStore.ValidateConfig(); err != nil {
			log.Error().
				Err(err).
				Str("file", a.config.Handlers.Go.GitCredentialsFile).
				Msg("Invalid git credentials configuration, continuing without pattern-based credentials")
			credStore = nil
		}
	}

	// Go proxy with CDN caching
	goProxyHandler := goproxy.New(a.cache, a.networkClient, goproxy.Config{
		Upstream:  "https://proxy.golang.org",
		SumDBURL:  "https://sum.golang.org",
		CredStore: credStore,
	})
	goProxyWithCDN := a.cdnMiddleware.Handler(http.StripPrefix("/go", goProxyHandler))
	a.app.All("/go/*", adaptor.HTTPHandler(goProxyWithCDN))

	// NPM proxy with CDN caching
	npmProxyHandler := npm.New(a.cache, a.networkClient, npm.Config{
		Upstream: "https://registry.npmjs.org",
	})
	npmProxyWithCDN := a.cdnMiddleware.Handler(http.StripPrefix("/npm", npmProxyHandler))
	a.app.All("/npm/*", adaptor.HTTPHandler(npmProxyWithCDN))

	// PyPI proxy with CDN caching
	pypiProxyHandler := pypi.New(a.cache, a.networkClient, pypi.Config{
		Upstream: "https://pypi.org/simple",
	})
	pypiProxyWithCDN := a.cdnMiddleware.Handler(http.StripPrefix("/pypi", pypiProxyHandler))
	a.app.All("/pypi/*", adaptor.HTTPHandler(pypiProxyWithCDN))

	// Serve frontend static files
	frontendDir := "frontend/dist"
	if _, err := os.Stat(frontendDir); err == nil {
		log.Info().Str("dir", frontendDir).Msg("Serving frontend static files")
		a.app.Static("/", frontendDir)
	} else {
		log.Warn().Msg("Frontend dist directory not found, frontend won't be served")
		a.app.Get("/", func(c *fiber.Ctx) error {
			return c.Type("html").SendString(`
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

	log.Info().
		Str("addr", fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port)).
		Msg("Fiber server configured")

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

	// Start download data aggregation worker (runs every hour)
	go a.startAggregationWorker(ctx)

	// Start Fiber server in goroutine
	errChan := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port)
		log.Info().
			Str("addr", addr).
			Msg("Starting Fiber server")
		if err := a.app.Listen(addr); err != nil {
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

	// Stop Fiber server
	if err := a.app.Shutdown(); err != nil {
		log.Error().Err(err).Msg("Error shutting down Fiber server")
	}

	// Stop pre-warming worker
	a.prewarmWorker.Stop()

	// Stop rescan worker if running
	if a.rescanWorker != nil {
		a.rescanWorker.Stop()
	}

	// Close analytics engine
	a.analyticsEngine.Close() // #nosec G104 -- Cleanup, error not critical

	// Close storage
	if err := a.storage.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing storage")
	}

	// Close metadata store
	if err := a.metadata.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing metadata store")
	}

	log.Info().Msg("Shutdown complete")
	return nil
}

// startAggregationWorker runs download data aggregation periodically
func (a *App) startAggregationWorker(ctx context.Context) {
	log.Info().Msg("Starting download data aggregation worker (runs every hour)")

	// Run immediately on startup
	if err := a.metadata.AggregateDownloadData(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to run initial download data aggregation")
	}

	// Then run every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Aggregation worker stopped")
			return
		case <-ticker.C:
			if err := a.metadata.AggregateDownloadData(ctx); err != nil {
				log.Error().Err(err).Msg("Failed to aggregate download data")
			}
		}
	}
}
