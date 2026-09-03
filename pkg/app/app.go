// Package app wires the GoHoarder HTTP application together: config,
// storage, metadata, scanners, and route handlers.
package app

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
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
	metagorm "github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/lukaszraczylo/gohoarder/pkg/prewarming"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/goproxy"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/npm"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/pypi"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem"
	nfsstore "github.com/lukaszraczylo/gohoarder/pkg/storage/nfs"
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

// New creates a new application instance.
// The local receiver is named "a" to avoid shadowing the package name "app".
func New(cfg *config.Config) (*App, error) {
	a := &App{
		config: cfg,
	}

	// Initialize components
	if err := a.initializeComponents(); err != nil {
		return nil, err
	}

	// Setup HTTP server and routes
	if err := a.setupServer(); err != nil {
		return nil, err
	}

	return a, nil
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
	case "nfs":
		// SyncWrites defaults to true (durable). Pointer-bool lets operators
		// opt out via explicit `sync_writes: false` in config.
		syncWrites := true
		if a.config.Storage.NFS.SyncWrites != nil {
			syncWrites = *a.config.Storage.NFS.SyncWrites
		}
		a.storage, err = nfsstore.New(nfsstore.Config{
			Path:       a.config.Storage.Path,
			MaxSize:    a.config.Cache.MaxSizeBytes,
			SyncWrites: syncWrites,
		}, log.Logger)
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
		// Use GORM for SQLite
		a.metadata, err = metagorm.NewV2(metagorm.Config{
			Driver:          "sqlite",
			DSN:             metagorm.BuildSQLiteDSN(a.config.Metadata.SQLite.Path, a.config.Metadata.SQLite.WALMode),
			MaxOpenConns:    getOrDefault(a.config.Metadata.MaxOpenConns, 25),
			MaxIdleConns:    getOrDefault(a.config.Metadata.MaxIdleConns, 5),
			ConnMaxLifetime: time.Duration(getOrDefault(a.config.Metadata.ConnMaxLifetime, 3600)) * time.Second,
			LogLevel:        getOrDefaultStr(a.config.Metadata.LogLevel, "warn"),
		})

	case "postgresql", "postgres":
		// Use GORM for PostgreSQL
		dsn := metagorm.BuildPostgresDSN(
			a.config.Metadata.PostgreSQL.Host,
			a.config.Metadata.PostgreSQL.Port,
			a.config.Metadata.PostgreSQL.User,
			a.config.Metadata.PostgreSQL.Password,
			a.config.Metadata.PostgreSQL.Database,
			getOrDefaultStr(a.config.Metadata.PostgreSQL.SSLMode, "disable"),
		)
		a.metadata, err = metagorm.NewV2(metagorm.Config{
			Driver:          "postgres",
			DSN:             dsn,
			MaxOpenConns:    getOrDefault(a.config.Metadata.MaxOpenConns, 25),
			MaxIdleConns:    getOrDefault(a.config.Metadata.MaxIdleConns, 5),
			ConnMaxLifetime: time.Duration(getOrDefault(a.config.Metadata.ConnMaxLifetime, 3600)) * time.Second,
			LogLevel:        getOrDefaultStr(a.config.Metadata.LogLevel, "warn"),
		})

	case "mysql", "mariadb":
		// Use GORM for MySQL/MariaDB
		dsn := metagorm.BuildMySQLDSN(
			a.config.Metadata.MySQL.Host,
			a.config.Metadata.MySQL.Port,
			a.config.Metadata.MySQL.User,
			a.config.Metadata.MySQL.Password,
			a.config.Metadata.MySQL.Database,
			getOrDefaultStr(a.config.Metadata.MySQL.Charset, "utf8mb4"),
		)
		a.metadata, err = metagorm.NewV2(metagorm.Config{
			Driver:          "mysql",
			DSN:             dsn,
			MaxOpenConns:    getOrDefault(a.config.Metadata.MaxOpenConns, 25),
			MaxIdleConns:    getOrDefault(a.config.Metadata.MaxIdleConns, 5),
			ConnMaxLifetime: time.Duration(getOrDefault(a.config.Metadata.ConnMaxLifetime, 3600)) * time.Second,
			LogLevel:        getOrDefaultStr(a.config.Metadata.LogLevel, "warn"),
		})

	case "file":
		// Keep file backend as-is for file-based metadata
		a.metadata, err = metafile.New(metafile.Config{
			Path: a.config.Metadata.Connection,
		})

	default:
		// Default to SQLite with GORM
		log.Warn().Str("backend", a.config.Metadata.Backend).Msg("Unknown metadata backend, defaulting to SQLite with GORM")
		a.metadata, err = metagorm.NewV2(metagorm.Config{
			Driver:   "sqlite",
			DSN:      metagorm.BuildSQLiteDSN("gohoarder.db", false),
			LogLevel: "warn",
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

	// Initialize cache manager with scanner and analytics. MaxPackageSize is
	// taken from Security.Scanners.Static (the static analyser already exposes
	// this knob and it doubles as a cache hard cap).
	log.Info().Msg("Initializing cache manager")
	cleanupInterval := a.config.Cache.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = 5 * time.Minute
	}
	a.cache, err = cache.New(a.storage, a.metadata, a.scanManager, a.analyticsEngine, cache.Config{
		DefaultTTL:      a.config.Cache.DefaultTTL,
		CleanupInterval: cleanupInterval,
		MaxPackageSize:  a.config.Security.Scanners.Static.MaxPackageSize,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Initialize network client. Pull values from cfg.Network where set;
	// fall back to existing literals so unset fields preserve current
	// behaviour. cfg.Network.* uses different semantic names (per-IP rate,
	// retry struct, etc.) so we map explicitly rather than blindly assign.
	log.Info().Msg("Initializing network client")
	netTimeout := a.config.Network.ReadTimeout
	if netTimeout == 0 {
		netTimeout = 5 * time.Minute
	}
	maxRetries := a.config.Network.Retry.MaxAttempts
	if maxRetries == 0 {
		maxRetries = 3
	}
	retryDelay := a.config.Network.Retry.InitialBackoff
	if retryDelay == 0 {
		retryDelay = 1 * time.Second
	}
	rateLimit := float64(a.config.Network.RateLimit.PerIP)
	if rateLimit == 0 {
		rateLimit = 100
	}
	rateBurst := a.config.Network.RateLimit.BurstSize
	if rateBurst == 0 {
		rateBurst = 10
	}
	cbThreshold := a.config.Network.CircuitBreaker.Threshold
	if cbThreshold == 0 {
		cbThreshold = 5
	}
	cbTimeout := a.config.Network.CircuitBreaker.Timeout
	if cbTimeout == 0 {
		cbTimeout = 30 * time.Second
	}
	a.networkClient = network.NewClient(network.Config{
		Timeout:    netTimeout,
		MaxRetries: maxRetries,
		RetryDelay: retryDelay,
		RateLimit:  rateLimit,
		RateBurst:  rateBurst,
		CircuitBreaker: network.CircuitBreakerConfig{
			Enabled:          true,
			FailureThreshold: cbThreshold,
			SuccessThreshold: 2,
			Timeout:          cbTimeout,
		},
		UserAgent: "GoHoarder/1.0",
	})

	// Initialize authentication manager. NewWithStore persists keys via the
	// metadata layer; Load hydrates the in-memory cache from prior state.
	// Bootstrap creates an admin from env on first boot when no admin exists.
	log.Info().Msg("Initializing authentication manager")
	authCfg := auth.Config{BcryptCost: a.config.Auth.BcryptCost}
	a.authManager = auth.NewWithStore(authCfg, a.metadata)
	loadCtx, loadCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := a.authManager.Load(loadCtx); err != nil {
		// Empty key set is recoverable: log and continue rather than fail boot.
		log.Warn().Err(err).Msg("Failed to load API keys from metadata store; starting with empty key set")
	}
	loadCancel()
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := auth.BootstrapAdminFromEnv(bootCtx, a.metadata, authCfg); err != nil {
		log.Warn().Err(err).Msg("Failed to bootstrap admin API key from environment")
	}
	bootCancel()

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
		CheckOrigin:     buildCheckOrigin(a.config.Server.AllowedOrigins),
	})

	// Wire WebSocket server as the broadcaster for cache + scanner so
	// lifecycle events (cached/downloaded/scan_*) reach connected clients.
	// websocket.Server satisfies events.Broadcaster via BroadcastEvent.
	a.cache.SetBroadcaster(a.wsServer)
	a.scanManager.SetBroadcaster(a.wsServer)

	// Initialize pre-warming worker. Operator-controlled via cfg.Prewarming;
	// defaults are baked into config.Default() so unset fields stay sane.
	log.Info().Msg("Initializing pre-warming worker")
	a.prewarmWorker = prewarming.NewWorker(prewarming.Config{
		Enabled:       a.config.Prewarming.Enabled,
		Interval:      a.config.Prewarming.Interval,
		MaxConcurrent: a.config.Prewarming.MaxConcurrent,
		TopPackages:   a.config.Prewarming.TopPackages,
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
				// Scanner failures (e.g., API rate limits) shouldn't mark server as unhealthy
				// Server can still serve cached packages, just can't scan new ones
				return health.StatusDegraded, err.Error()
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

	// Auth middleware factories. Built once, reused on every gated route.
	// When auth is disabled the variables stay nil and we skip wiring; routes
	// are mounted bare to preserve backward-compatible public access.
	authEnabled := a.config.Auth.Enabled
	var (
		mwAuth     fiber.Handler
		mwAdmin    fiber.Handler
		mwOptional fiber.Handler
	)
	if authEnabled {
		mwAuth = RequireAuth(a.authManager)
		mwAdmin = RequireRole(a.authManager, string(auth.RoleAdmin))
		mwOptional = OptionalAuth(a.authManager)
		_ = mwOptional // reserved for future endpoints with anonymous fallback
	}

	// Health endpoints — ALWAYS public (k8s liveness/readiness probes).
	a.app.Get("/health", adaptor.HTTPHandlerFunc(a.healthChecker.HealthHandler()))
	a.app.Get("/health/ready", adaptor.HTTPHandlerFunc(a.healthChecker.ReadyHandler()))

	// Metrics endpoint — public by default, optionally auth-gated.
	if authEnabled && a.config.Metrics.RequireAuth {
		a.app.Get("/metrics", mwAuth, adaptor.HTTPHandler(metrics.Handler()))
	} else {
		a.app.Get("/metrics", adaptor.HTTPHandler(metrics.Handler()))
	}

	// WebSocket endpoint — gated when auth enabled. Clients must send the
	// API key via Authorization or X-API-Key on the upgrade request.
	if authEnabled {
		a.app.Get("/ws", mwAuth, adaptor.HTTPHandlerFunc(a.wsServer.HandleWebSocket))
	} else {
		a.app.Get("/ws", adaptor.HTTPHandlerFunc(a.wsServer.HandleWebSocket))
	}

	// API endpoints. Read endpoints require any valid key; package DELETE
	// requires admin (split route from the All() so role-check runs only on
	// destructive verbs). The combined handler still dispatches by method.
	if authEnabled {
		a.app.Get("/api/config", mwAuth, a.handleConfig)
		a.app.Get("/api/packages/*", mwAuth, a.handlePackages)
		a.app.Delete("/api/packages/*", mwAdmin, a.handlePackages)
		a.app.All("/api/packages/*", mwAuth, a.handlePackages) // OPTIONS, preflight, vulnerabilities
		a.app.Get("/api/stats", mwAuth, a.handleStats)
		a.app.Get("/api/stats/timeseries", mwAuth, a.handleTimeSeriesStats)
		a.app.Get("/api/info", mwAuth, a.handleInfo)

		a.app.Get("/api/analytics/top", mwAuth, a.handleAnalyticsTopPackages)
		a.app.Get("/api/analytics/trending", mwAuth, a.handleAnalyticsTrendingPackages)
		a.app.Get("/api/analytics/trends", mwAuth, a.handleAnalyticsTrends)
		a.app.Get("/api/analytics/total", mwAuth, a.handleAnalyticsTotalStats)
		a.app.Get("/api/analytics/registry/:registry", mwAuth, a.handleAnalyticsRegistryStats)
		a.app.Get("/api/analytics/package/:registry/:name", mwAuth, a.handleAnalyticsPackageStats)
		a.app.Get("/api/analytics/search", mwAuth, a.handleAnalyticsSearch)
	} else {
		a.app.Get("/api/config", a.handleConfig)
		a.app.All("/api/packages/*", a.handlePackages)
		a.app.Get("/api/stats", a.handleStats)
		a.app.Get("/api/stats/timeseries", a.handleTimeSeriesStats)
		a.app.Get("/api/info", a.handleInfo)

		a.app.Get("/api/analytics/top", a.handleAnalyticsTopPackages)
		a.app.Get("/api/analytics/trending", a.handleAnalyticsTrendingPackages)
		a.app.Get("/api/analytics/trends", a.handleAnalyticsTrends)
		a.app.Get("/api/analytics/total", a.handleAnalyticsTotalStats)
		a.app.Get("/api/analytics/registry/:registry", a.handleAnalyticsRegistryStats)
		a.app.Get("/api/analytics/package/:registry/:name", a.handleAnalyticsPackageStats)
		a.app.Get("/api/analytics/search", a.handleAnalyticsSearch)
	}

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

	// Per-registry proxies. Mounted only when the corresponding handler is
	// enabled in config. Each Upstream falls back to the canonical URL if
	// unset so partially-configured deployments keep working.
	if a.config.Handlers.Go.Enabled {
		goUpstream := a.config.Handlers.Go.UpstreamProxy
		if goUpstream == "" {
			goUpstream = "https://proxy.golang.org"
		}
		sumDB := a.config.Handlers.Go.ChecksumDB
		if sumDB == "" {
			sumDB = "https://sum.golang.org"
		}
		goProxyHandler := goproxy.New(a.cache, a.networkClient, goproxy.Config{
			Upstream:  goUpstream,
			SumDBURL:  sumDB,
			CredStore: credStore,
		})
		goProxyWithCDN := a.cdnMiddleware.Handler(http.StripPrefix("/go", goProxyHandler))
		if authEnabled {
			a.app.All("/go/*", mwAuth, adaptor.HTTPHandler(goProxyWithCDN))
		} else {
			a.app.All("/go/*", adaptor.HTTPHandler(goProxyWithCDN))
		}
	}

	if a.config.Handlers.NPM.Enabled {
		npmUpstream := a.config.Handlers.NPM.UpstreamRegistry
		if npmUpstream == "" {
			npmUpstream = "https://registry.npmjs.org"
		}
		npmProxyHandler := npm.New(a.cache, a.networkClient, npm.Config{
			Upstream: npmUpstream,
		})
		npmProxyWithCDN := a.cdnMiddleware.Handler(http.StripPrefix("/npm", npmProxyHandler))
		if authEnabled {
			a.app.All("/npm/*", mwAuth, adaptor.HTTPHandler(npmProxyWithCDN))
		} else {
			a.app.All("/npm/*", adaptor.HTTPHandler(npmProxyWithCDN))
		}
	}

	if a.config.Handlers.PyPI.Enabled {
		pypiUpstream := a.config.Handlers.PyPI.SimpleAPIURL
		if pypiUpstream == "" {
			pypiUpstream = "https://pypi.org/simple"
		}
		pypiProxyHandler := pypi.New(a.cache, a.networkClient, pypi.Config{
			Upstream: pypiUpstream,
		})
		pypiProxyWithCDN := a.cdnMiddleware.Handler(http.StripPrefix("/pypi", pypiProxyHandler))
		if authEnabled {
			a.app.All("/pypi/*", mwAuth, adaptor.HTTPHandler(pypiProxyWithCDN))
		} else {
			a.app.All("/pypi/*", adaptor.HTTPHandler(pypiProxyWithCDN))
		}
	}

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

	// Start periodic stats broadcaster (every 30s) so connected WS clients
	// see live counter updates without polling.
	go a.startStatsBroadcaster(ctx)

	// Start Fiber server in goroutine. Branch on TLS to pick Listen vs ListenTLS.
	errChan := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port)
		if a.config.Server.TLS.Enabled {
			log.Info().
				Str("addr", addr).
				Str("cert_file", a.config.Server.TLS.CertFile).
				Msg("Starting Fiber server with TLS")
			if err := a.app.ListenTLS(addr, a.config.Server.TLS.CertFile, a.config.Server.TLS.KeyFile); err != nil {
				errChan <- err
			}
			return
		}
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

	// Drain async auth writes (LastUsedAt updates) before closing metadata.
	if a.authManager != nil {
		a.authManager.Close()
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

// startStatsBroadcaster periodically pulls aggregate cache stats and pushes
// them onto the WebSocket broadcast channel so connected dashboards see
// live counters without polling. Lightweight: a single GetStats call every
// 30s, drop-on-overflow at the WS layer.
func (a *App) startStatsBroadcaster(ctx context.Context) {
	if a.wsServer == nil {
		return
	}
	const interval = 30 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	emit := func() {
		statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		stats, err := a.cache.GetStats(statsCtx, "")
		if err != nil {
			log.Debug().Err(err).Msg("stats broadcaster: GetStats failed")
			return
		}
		a.wsServer.BroadcastEvent("stats_update", map[string]interface{}{
			"stats":     stats,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	}

	// Emit once immediately so newly-connected clients see fresh data.
	emit()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stats broadcaster stopped")
			return
		case <-ticker.C:
			emit()
		}
	}
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

// getOrDefault returns the value if it's non-zero, otherwise returns the default
func getOrDefault(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	}
	return value
}

// getOrDefaultStr returns the value if it's non-empty, otherwise returns the default
func getOrDefaultStr(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// buildCheckOrigin returns a websocket Origin validator.
//
// Behaviour:
//   - allowed entries may be exact origins ("https://app.example.com")
//     or wildcard host patterns ("https://*.example.com").
//   - when allowed is empty, only same-origin upgrades are permitted: the
//     Origin host must match the Host header of the incoming request.
//   - requests with no Origin header are accepted (non-browser clients).
//
// We deliberately do NOT default to allow-all to avoid Cross-Site WebSocket
// Hijacking (CSWSH).
func buildCheckOrigin(allowed []string) func(*http.Request) bool {
	// Pre-parse allowlist once.
	type originRule struct {
		scheme   string
		host     string // exact host, or "" if hostSuffix is set
		hostGlob string // suffix match including leading "."
	}
	rules := make([]originRule, 0, len(allowed))
	for _, raw := range allowed {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			log.Warn().Str("entry", raw).Msg("Ignoring invalid AllowedOrigins entry")
			continue
		}
		r := originRule{scheme: strings.ToLower(u.Scheme)}
		host := strings.ToLower(u.Host)
		if strings.HasPrefix(host, "*.") {
			// "*.example.com" → match any subdomain plus the apex.
			r.hostGlob = host[1:] // ".example.com"
		} else {
			r.host = host
		}
		rules = append(rules, r)
	}

	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Non-browser clients (e.g., CLI, server-to-server) omit Origin.
			return true
		}
		ou, err := url.Parse(origin)
		if err != nil || ou.Scheme == "" || ou.Host == "" {
			log.Warn().Str("origin", origin).Msg("Rejecting WebSocket upgrade: malformed Origin header")
			return false
		}
		originScheme := strings.ToLower(ou.Scheme)
		originHost := strings.ToLower(ou.Host)

		// Empty allowlist → same-origin only.
		if len(rules) == 0 {
			return strings.EqualFold(originHost, r.Host)
		}

		for _, rule := range rules {
			if rule.scheme != originScheme {
				continue
			}
			if rule.host != "" && rule.host == originHost {
				return true
			}
			if rule.hostGlob != "" {
				// Match apex (".example.com" → "example.com") and any subdomain.
				apex := strings.TrimPrefix(rule.hostGlob, ".")
				if originHost == apex || strings.HasSuffix(originHost, rule.hostGlob) {
					return true
				}
			}
		}
		log.Warn().
			Str("origin", origin).
			Str("host", r.Host).
			Msg("Rejecting WebSocket upgrade: Origin not in allowlist")
		return false
	}
}
