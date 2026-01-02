package config

import (
	"fmt"
	"time"
)

// Config is the main configuration struct
type Config struct {
	Server   ServerConfig   `mapstructure:"server" json:"server"`
	Storage  StorageConfig  `mapstructure:"storage" json:"storage"`
	Metadata MetadataConfig `mapstructure:"metadata" json:"metadata"`
	Cache    CacheConfig    `mapstructure:"cache" json:"cache"`
	Security SecurityConfig `mapstructure:"security" json:"security"`
	Auth     AuthConfig     `mapstructure:"auth" json:"auth"`
	Network  NetworkConfig  `mapstructure:"network" json:"network"`
	Logging  LoggingConfig  `mapstructure:"logging" json:"logging"`
	Handlers HandlersConfig `mapstructure:"handlers" json:"handlers"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host" json:"host"`
	Port         int           `mapstructure:"port" json:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" json:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" json:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" json:"idle_timeout"`
	TLS          TLSConfig     `mapstructure:"tls" json:"tls"`
}

// TLSConfig contains TLS/HTTPS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" json:"enabled"`
	CertFile string `mapstructure:"cert_file" json:"cert_file"`
	KeyFile  string `mapstructure:"key_file" json:"key_file"`
}

// StorageConfig contains storage backend configuration
type StorageConfig struct {
	Backend    string                 `mapstructure:"backend" json:"backend"` // filesystem, s3, smb, nfs
	Path       string                 `mapstructure:"path" json:"path"`
	Filesystem FilesystemConfig       `mapstructure:"filesystem" json:"filesystem"`
	S3         S3Config               `mapstructure:"s3" json:"s3"`
	SMB        SMBConfig              `mapstructure:"smb" json:"smb"`
	Options    map[string]interface{} `mapstructure:"options" json:"options"`
}

// FilesystemConfig contains local filesystem storage configuration
type FilesystemConfig struct {
	BasePath string `mapstructure:"base_path" json:"base_path"`
}

// S3Config contains S3-compatible storage configuration
type S3Config struct {
	Endpoint        string `mapstructure:"endpoint" json:"endpoint"`
	Region          string `mapstructure:"region" json:"region"`
	Bucket          string `mapstructure:"bucket" json:"bucket"`
	AccessKeyID     string `mapstructure:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key" json:"-"` // Don't serialize secrets
	UseSSL          bool   `mapstructure:"use_ssl" json:"use_ssl"`
}

// SMBConfig contains SMB/CIFS storage configuration
type SMBConfig struct {
	Host     string `mapstructure:"host" json:"host"`
	Share    string `mapstructure:"share" json:"share"`
	Username string `mapstructure:"username" json:"username"`
	Password string `mapstructure:"password" json:"-"` // Don't serialize secrets
	Domain   string `mapstructure:"domain" json:"domain"`
}

// MetadataConfig contains metadata store configuration
type MetadataConfig struct {
	Backend    string           `mapstructure:"backend" json:"backend"` // sqlite, postgresql, file
	Connection string           `mapstructure:"connection" json:"connection"`
	SQLite     SQLiteConfig     `mapstructure:"sqlite" json:"sqlite"`
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql" json:"postgresql"`
}

// SQLiteConfig contains SQLite-specific configuration
type SQLiteConfig struct {
	Path    string `mapstructure:"path" json:"path"`
	WALMode bool   `mapstructure:"wal_mode" json:"wal_mode"`
}

// PostgreSQLConfig contains PostgreSQL-specific configuration
type PostgreSQLConfig struct {
	Host     string `mapstructure:"host" json:"host"`
	Port     int    `mapstructure:"port" json:"port"`
	Database string `mapstructure:"database" json:"database"`
	User     string `mapstructure:"user" json:"user"`
	Password string `mapstructure:"password" json:"-"` // Don't serialize secrets
	SSLMode  string `mapstructure:"ssl_mode" json:"ssl_mode"`
}

// CacheConfig contains cache management configuration
type CacheConfig struct {
	DefaultTTL      time.Duration            `mapstructure:"default_ttl" json:"default_ttl"`
	CleanupInterval time.Duration            `mapstructure:"cleanup_interval" json:"cleanup_interval"`
	MaxSizeBytes    int64                    `mapstructure:"max_size_bytes" json:"max_size_bytes"`
	PerProjectQuota int64                    `mapstructure:"per_project_quota" json:"per_project_quota"`
	TTLOverrides    map[string]time.Duration `mapstructure:"ttl_overrides" json:"ttl_overrides"` // Per ecosystem
}

// SecurityConfig contains security scanning configuration
type SecurityConfig struct {
	Enabled           bool                    `mapstructure:"enabled" json:"enabled"`
	ScanOnDownload    bool                    `mapstructure:"scan_on_download" json:"scan_on_download"`       // Scan packages on first download
	RescanInterval    time.Duration           `mapstructure:"rescan_interval" json:"rescan_interval"`         // How often to re-scan (e.g., 24h, 168h for weekly)
	BlockOnSeverity   string                  `mapstructure:"block_on_severity" json:"block_on_severity"`     // none, low, medium, high, critical
	BlockThresholds   VulnerabilityThresholds `mapstructure:"block_thresholds" json:"block_thresholds"`       // Max vulns per severity before blocking
	UpdateDBOnStartup bool                    `mapstructure:"update_db_on_startup" json:"update_db_on_startup"` // Update vulnerability databases on startup
	AllowedPackages   []string                `mapstructure:"allowed_packages" json:"allowed_packages"`       // Packages that bypass security checks (format: "registry/name@version" or "registry/name")
	IgnoredCVEs       []string                `mapstructure:"ignored_cves" json:"ignored_cves"`               // CVE IDs to ignore globally (e.g., "CVE-2021-23337")
	Scanners          ScannersConfig          `mapstructure:"scanners" json:"scanners"`
}

// VulnerabilityThresholds defines max allowed vulnerabilities per severity
type VulnerabilityThresholds struct {
	Critical int `mapstructure:"critical" json:"critical"` // Max critical vulns (0 = block any)
	High     int `mapstructure:"high" json:"high"`         // Max high vulns
	Medium   int `mapstructure:"medium" json:"medium"`     // Max medium vulns
	Low      int `mapstructure:"low" json:"low"`           // Max low vulns (-1 = unlimited)
}

// ScannersConfig contains individual scanner configurations
type ScannersConfig struct {
	Trivy        TrivyConfig        `mapstructure:"trivy" json:"trivy"`
	OSV          OSVConfig          `mapstructure:"osv" json:"osv"`
	Static       StaticConfig       `mapstructure:"static" json:"static"`
	Grype        GrypeConfig        `mapstructure:"grype" json:"grype"`
	Govulncheck  GovulncheckConfig  `mapstructure:"govulncheck" json:"govulncheck"`
	NpmAudit     NpmAuditConfig     `mapstructure:"npm_audit" json:"npm_audit"`
	PipAudit     PipAuditConfig     `mapstructure:"pip_audit" json:"pip_audit"`
	GHSA         GHSAConfig         `mapstructure:"ghsa" json:"ghsa"`
}

// TrivyConfig contains Trivy scanner configuration
type TrivyConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
	CacheDB string        `mapstructure:"cache_db" json:"cache_db"`
}

// OSVConfig contains OSV scanner configuration
type OSVConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	APIURL  string        `mapstructure:"api_url" json:"api_url"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// StaticConfig contains static analysis configuration
type StaticConfig struct {
	Enabled         bool     `mapstructure:"enabled" json:"enabled"`
	MaxPackageSize  int64    `mapstructure:"max_package_size" json:"max_package_size"`
	CheckChecksums  bool     `mapstructure:"check_checksums" json:"check_checksums"`
	BlockSuspicious bool     `mapstructure:"block_suspicious" json:"block_suspicious"`
	AllowedLicenses []string `mapstructure:"allowed_licenses" json:"allowed_licenses"`
}

// GrypeConfig contains Grype scanner configuration
type GrypeConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// GovulncheckConfig contains govulncheck scanner configuration
type GovulncheckConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// NpmAuditConfig contains npm audit scanner configuration
type NpmAuditConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// PipAuditConfig contains pip-audit scanner configuration
type PipAuditConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
}

// GHSAConfig contains GitHub Advisory Database scanner configuration
type GHSAConfig struct {
	Enabled bool          `mapstructure:"enabled" json:"enabled"`
	Timeout time.Duration `mapstructure:"timeout" json:"timeout"`
	Token   string        `mapstructure:"token" json:"-"` // GitHub token for higher rate limits (don't serialize)
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	Enabled       bool          `mapstructure:"enabled" json:"enabled"`
	KeyExpiration time.Duration `mapstructure:"key_expiration" json:"key_expiration"`
	BcryptCost    int           `mapstructure:"bcrypt_cost" json:"bcrypt_cost"`
	AuditLog      bool          `mapstructure:"audit_log" json:"audit_log"`
}

// NetworkConfig contains network resilience configuration
type NetworkConfig struct {
	ConnectTimeout  time.Duration        `mapstructure:"connect_timeout" json:"connect_timeout"`
	ReadTimeout     time.Duration        `mapstructure:"read_timeout" json:"read_timeout"`
	WriteTimeout    time.Duration        `mapstructure:"write_timeout" json:"write_timeout"`
	MaxIdleConns    int                  `mapstructure:"max_idle_conns" json:"max_idle_conns"`
	MaxConnsPerHost int                  `mapstructure:"max_conns_per_host" json:"max_conns_per_host"`
	RateLimit       RateLimitConfig      `mapstructure:"rate_limit" json:"rate_limit"`
	CircuitBreaker  CircuitBreakerConfig `mapstructure:"circuit_breaker" json:"circuit_breaker"`
	Retry           RetryConfig          `mapstructure:"retry" json:"retry"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	PerAPIKey int `mapstructure:"per_api_key" json:"per_api_key"`
	PerIP     int `mapstructure:"per_ip" json:"per_ip"`
	BurstSize int `mapstructure:"burst_size" json:"burst_size"`
}

// CircuitBreakerConfig contains circuit breaker configuration
type CircuitBreakerConfig struct {
	Threshold     int           `mapstructure:"threshold" json:"threshold"`
	Timeout       time.Duration `mapstructure:"timeout" json:"timeout"`
	ResetInterval time.Duration `mapstructure:"reset_interval" json:"reset_interval"`
}

// RetryConfig contains retry policy configuration
type RetryConfig struct {
	MaxAttempts    int           `mapstructure:"max_attempts" json:"max_attempts"`
	InitialBackoff time.Duration `mapstructure:"initial_backoff" json:"initial_backoff"`
	MaxBackoff     time.Duration `mapstructure:"max_backoff" json:"max_backoff"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level" json:"level"`   // debug, info, warn, error
	Format string `mapstructure:"format" json:"format"` // json, pretty
}

// HandlersConfig contains package manager handler configurations
type HandlersConfig struct {
	Go   GoHandlerConfig   `mapstructure:"go" json:"go"`
	NPM  NPMHandlerConfig  `mapstructure:"npm" json:"npm"`
	PyPI PyPIHandlerConfig `mapstructure:"pypi" json:"pypi"`
}

// GoHandlerConfig contains Go proxy configuration
type GoHandlerConfig struct {
	Enabled            bool   `mapstructure:"enabled" json:"enabled"`
	UpstreamProxy      string `mapstructure:"upstream_proxy" json:"upstream_proxy"`
	ChecksumDB         string `mapstructure:"checksum_db" json:"checksum_db"`
	VerifyChecksums    bool   `mapstructure:"verify_checksums" json:"verify_checksums"`
	GitCredentialsFile string `mapstructure:"git_credentials_file" json:"git_credentials_file"` // Path to git credentials JSON file
}

// NPMHandlerConfig contains NPM registry configuration
type NPMHandlerConfig struct {
	Enabled          bool   `mapstructure:"enabled" json:"enabled"`
	UpstreamRegistry string `mapstructure:"upstream_registry" json:"upstream_registry"`
}

// PyPIHandlerConfig contains PyPI configuration
type PyPIHandlerConfig struct {
	Enabled      bool   `mapstructure:"enabled" json:"enabled"`
	UpstreamURL  string `mapstructure:"upstream_url" json:"upstream_url"`
	SimpleAPIURL string `mapstructure:"simple_api_url" json:"simple_api_url"`
}

// Default returns a configuration with sensible defaults
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  5 * time.Minute,
			WriteTimeout: 5 * time.Minute,
			IdleTimeout:  2 * time.Minute,
			TLS: TLSConfig{
				Enabled: false,
			},
		},
		Storage: StorageConfig{
			Backend: "filesystem",
			Path:    "/var/cache/gohoarder",
			Filesystem: FilesystemConfig{
				BasePath: "/var/cache/gohoarder",
			},
		},
		Metadata: MetadataConfig{
			Backend:    "sqlite",
			Connection: "file:gohoarder.db?cache=shared&mode=rwc",
			SQLite: SQLiteConfig{
				Path:    "gohoarder.db",
				WALMode: true,
			},
		},
		Cache: CacheConfig{
			DefaultTTL:      7 * 24 * time.Hour,
			CleanupInterval: 1 * time.Hour,
			MaxSizeBytes:    500 * 1024 * 1024 * 1024, // 500GB
			PerProjectQuota: 50 * 1024 * 1024 * 1024,  // 50GB
			TTLOverrides: map[string]time.Duration{
				"npm": 7 * 24 * time.Hour,
				"pip": 7 * 24 * time.Hour,
				"go":  7 * 24 * time.Hour,
			},
		},
		Security: SecurityConfig{
			Enabled:         false,
			BlockOnSeverity: "high",
			Scanners: ScannersConfig{
				Trivy: TrivyConfig{
					Enabled: false,
					Timeout: 5 * time.Minute,
					CacheDB: "/var/lib/trivy",
				},
				OSV: OSVConfig{
					Enabled: false,
					APIURL:  "https://api.osv.dev",
					Timeout: 30 * time.Second,
				},
				Static: StaticConfig{
					Enabled:         true,
					MaxPackageSize:  2 * 1024 * 1024 * 1024, // 2GB
					CheckChecksums:  true,
					BlockSuspicious: false,
				},
				Grype: GrypeConfig{
					Enabled: false,
					Timeout: 5 * time.Minute,
				},
				Govulncheck: GovulncheckConfig{
					Enabled: false,
					Timeout: 5 * time.Minute,
				},
				NpmAudit: NpmAuditConfig{
					Enabled: false,
					Timeout: 2 * time.Minute,
				},
				PipAudit: PipAuditConfig{
					Enabled: false,
					Timeout: 2 * time.Minute,
				},
				GHSA: GHSAConfig{
					Enabled: false,
					Timeout: 30 * time.Second,
					Token:   "",
				},
			},
		},
		Auth: AuthConfig{
			Enabled:       true,
			KeyExpiration: 0, // Never expire
			BcryptCost:    10,
			AuditLog:      true,
		},
		Network: NetworkConfig{
			ConnectTimeout:  10 * time.Second,
			ReadTimeout:     5 * time.Minute,
			WriteTimeout:    5 * time.Minute,
			MaxIdleConns:    100,
			MaxConnsPerHost: 10,
			RateLimit: RateLimitConfig{
				PerAPIKey: 1000,
				PerIP:     100,
				BurstSize: 50,
			},
			CircuitBreaker: CircuitBreakerConfig{
				Threshold:     5,
				Timeout:       30 * time.Second,
				ResetInterval: 60 * time.Second,
			},
			Retry: RetryConfig{
				MaxAttempts:    3,
				InitialBackoff: 1 * time.Second,
				MaxBackoff:     30 * time.Second,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Handlers: HandlersConfig{
			Go: GoHandlerConfig{
				Enabled:         true,
				UpstreamProxy:   "https://proxy.golang.org",
				ChecksumDB:      "https://sum.golang.org",
				VerifyChecksums: true,
			},
			NPM: NPMHandlerConfig{
				Enabled:          true,
				UpstreamRegistry: "https://registry.npmjs.org",
			},
			PyPI: PyPIHandlerConfig{
				Enabled:      true,
				UpstreamURL:  "https://pypi.org",
				SimpleAPIURL: "https://pypi.org/simple",
			},
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}

	// Validate storage backend
	validStorageBackends := map[string]bool{"filesystem": true, "s3": true, "smb": true, "nfs": true}
	if !validStorageBackends[c.Storage.Backend] {
		return fmt.Errorf("storage.backend must be one of: filesystem, s3, smb, nfs; got %s", c.Storage.Backend)
	}

	// Validate metadata backend
	validMetadataBackends := map[string]bool{"sqlite": true, "postgresql": true, "file": true}
	if !validMetadataBackends[c.Metadata.Backend] {
		return fmt.Errorf("metadata.backend must be one of: sqlite, postgresql, file; got %s", c.Metadata.Backend)
	}

	// Validate cache
	if c.Cache.DefaultTTL < 0 {
		return fmt.Errorf("cache.default_ttl cannot be negative")
	}
	if c.Cache.MaxSizeBytes < 0 {
		return fmt.Errorf("cache.max_size_bytes cannot be negative")
	}

	// Validate security
	validSeverities := map[string]bool{"none": true, "low": true, "medium": true, "high": true, "critical": true}
	if !validSeverities[c.Security.BlockOnSeverity] {
		return fmt.Errorf("security.block_on_severity must be one of: none, low, medium, high, critical; got %s", c.Security.BlockOnSeverity)
	}

	// Validate logging level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("logging.level must be one of: debug, info, warn, error; got %s", c.Logging.Level)
	}

	// Validate logging format
	validFormats := map[string]bool{"json": true, "pretty": true}
	if !validFormats[c.Logging.Format] {
		return fmt.Errorf("logging.format must be one of: json, pretty; got %s", c.Logging.Format)
	}

	// Validate auth
	if c.Auth.BcryptCost < 4 || c.Auth.BcryptCost > 31 {
		return fmt.Errorf("auth.bcrypt_cost must be between 4 and 31, got %d", c.Auth.BcryptCost)
	}

	return nil
}
