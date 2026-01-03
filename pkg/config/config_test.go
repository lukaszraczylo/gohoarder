package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ConfigTestSuite struct {
	suite.Suite
	tempDir string
}

func TestConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}

func (s *ConfigTestSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "gohoarder-config-test-*")
	s.Require().NoError(err)
}

func (s *ConfigTestSuite) TearDownTest() {
	_ = os.RemoveAll(s.tempDir) // #nosec G104 -- Cleanup
}

func (s *ConfigTestSuite) TestDefault() {
	cfg := Default()
	s.NotNil(cfg)
	s.Equal("0.0.0.0", cfg.Server.Host)
	s.Equal(8080, cfg.Server.Port)
	s.Equal("filesystem", cfg.Storage.Backend)
	s.Equal("sqlite", cfg.Metadata.Backend)
	s.NoError(cfg.Validate())
}

func (s *ConfigTestSuite) TestValidate() {
	tests := []struct {
		modify      func(*Config)
		name        string
		errorSubstr string
		expectError bool
	}{
		{
			name:        "valid_config",
			modify:      func(c *Config) {},
			expectError: false,
		},
		{
			name: "invalid_port_too_low",
			modify: func(c *Config) {
				c.Server.Port = 0
			},
			expectError: true,
			errorSubstr: "port must be between",
		},
		{
			name: "invalid_port_too_high",
			modify: func(c *Config) {
				c.Server.Port = 70000
			},
			expectError: true,
			errorSubstr: "port must be between",
		},
		{
			name: "invalid_storage_backend",
			modify: func(c *Config) {
				c.Storage.Backend = "invalid"
			},
			expectError: true,
			errorSubstr: "storage.backend must be one of",
		},
		{
			name: "invalid_metadata_backend",
			modify: func(c *Config) {
				c.Metadata.Backend = "mongodb"
			},
			expectError: true,
			errorSubstr: "metadata.backend must be one of",
		},
		{
			name: "negative_ttl",
			modify: func(c *Config) {
				c.Cache.DefaultTTL = -1 * time.Hour
			},
			expectError: true,
			errorSubstr: "cannot be negative",
		},
		{
			name: "negative_cache_size",
			modify: func(c *Config) {
				c.Cache.MaxSizeBytes = -100
			},
			expectError: true,
			errorSubstr: "cannot be negative",
		},
		{
			name: "invalid_severity",
			modify: func(c *Config) {
				c.Security.BlockOnSeverity = "super-high"
			},
			expectError: true,
			errorSubstr: "block_on_severity must be one of",
		},
		{
			name: "invalid_log_level",
			modify: func(c *Config) {
				c.Logging.Level = "verbose"
			},
			expectError: true,
			errorSubstr: "logging.level must be one of",
		},
		{
			name: "invalid_log_format",
			modify: func(c *Config) {
				c.Logging.Format = "xml"
			},
			expectError: true,
			errorSubstr: "logging.format must be one of",
		},
		{
			name: "invalid_bcrypt_cost_too_low",
			modify: func(c *Config) {
				c.Auth.BcryptCost = 3
			},
			expectError: true,
			errorSubstr: "bcrypt_cost must be between",
		},
		{
			name: "invalid_bcrypt_cost_too_high",
			modify: func(c *Config) {
				c.Auth.BcryptCost = 32
			},
			expectError: true,
			errorSubstr: "bcrypt_cost must be between",
		},
		{
			name: "valid_s3_backend",
			modify: func(c *Config) {
				c.Storage.Backend = "s3"
			},
			expectError: false,
		},
		{
			name: "valid_postgresql_backend",
			modify: func(c *Config) {
				c.Metadata.Backend = "postgresql"
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			cfg := Default()
			tt.modify(cfg)
			err := cfg.Validate()

			if tt.expectError {
				s.Error(err)
				if tt.errorSubstr != "" {
					s.Contains(err.Error(), tt.errorSubstr)
				}
			} else {
				s.NoError(err)
			}
		})
	}
}

func (s *ConfigTestSuite) TestLoad() {
	tests := []struct {
		envVars     map[string]string
		validate    func(*Config)
		name        string
		configYAML  string
		expectError bool
	}{
		{
			name: "valid_yaml_config",
			configYAML: `
server:
  host: 127.0.0.1
  port: 9000
storage:
  backend: filesystem
  path: /custom/path
logging:
  level: debug
  format: pretty
`,
			expectError: false,
			validate: func(cfg *Config) {
				s.Equal("127.0.0.1", cfg.Server.Host)
				s.Equal(9000, cfg.Server.Port)
				s.Equal("/custom/path", cfg.Storage.Path)
				s.Equal("debug", cfg.Logging.Level)
				s.Equal("pretty", cfg.Logging.Format)
			},
		},
		{
			name: "env_var_override",
			configYAML: `
server:
  port: 8080
`,
			envVars: map[string]string{
				"GOHOARDER_SERVER_PORT": "9090",
			},
			expectError: false,
			validate: func(cfg *Config) {
				s.Equal(9090, cfg.Server.Port)
			},
		},
		{
			name: "invalid_yaml",
			configYAML: `
server: [invalid
`,
			expectError: true,
		},
		{
			name: "validation_failure",
			configYAML: `
server:
  port: 100000
`,
			expectError: true,
		},
		{
			name: "complete_config",
			configYAML: `
server:
  host: 0.0.0.0
  port: 8080
  read_timeout: 300s
  write_timeout: 300s
storage:
  backend: s3
  s3:
    endpoint: s3.amazonaws.com
    region: us-east-1
    bucket: my-cache
    access_key_id: AKIAIOSFODNN7EXAMPLE
    secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
metadata:
  backend: postgresql
  postgresql:
    host: localhost
    port: 5432
    database: gohoarder
    user: postgres
    password: secret
    ssl_mode: require
cache:
  default_ttl: 168h
  max_size_bytes: 536870912000
security:
  enabled: true
  block_on_severity: high
  scanners:
    trivy:
      enabled: true
      timeout: 300s
auth:
  enabled: true
  bcrypt_cost: 12
`,
			expectError: false,
			validate: func(cfg *Config) {
				s.Equal("s3", cfg.Storage.Backend)
				s.Equal("s3.amazonaws.com", cfg.Storage.S3.Endpoint)
				s.Equal("postgresql", cfg.Metadata.Backend)
				s.Equal("localhost", cfg.Metadata.PostgreSQL.Host)
				s.True(cfg.Security.Enabled)
				s.Equal(12, cfg.Auth.BcryptCost)
			},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Write config file
			configPath := filepath.Join(s.tempDir, "config.yaml")
			err := os.WriteFile(configPath, []byte(tt.configYAML), 0644)
			s.Require().NoError(err)

			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			// Load config
			cfg, err := Load(configPath)

			if tt.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
				s.NotNil(cfg)
				if tt.validate != nil {
					tt.validate(cfg)
				}
			}
		})
	}
}

func (s *ConfigTestSuite) TestLoadMissingFile() {
	// Should return error when file explicitly specified but not found
	cfg, err := Load("/nonexistent/path/to/config.yaml")
	s.Error(err)
	s.Nil(cfg)
}

// Benchmark tests
func BenchmarkDefault(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Default()
	}
}

func BenchmarkValidate(b *testing.B) {
	cfg := Default()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cfg.Validate()
	}
}

// Table-driven edge cases
func TestConfigEdgeCases(t *testing.T) {
	tests := []struct {
		config *Config
		name   string
		valid  bool
	}{
		{
			name:   "minimal_config",
			config: &Config{Server: ServerConfig{Port: 8080}, Storage: StorageConfig{Backend: "filesystem"}, Metadata: MetadataConfig{Backend: "sqlite"}, Logging: LoggingConfig{Level: "info", Format: "json"}, Security: SecurityConfig{BlockOnSeverity: "high"}, Auth: AuthConfig{BcryptCost: 10}},
			valid:  true,
		},
		{
			name:   "zero_ttl",
			config: func() *Config { c := Default(); c.Cache.DefaultTTL = 0; return c }(),
			valid:  true, // Zero is valid (no caching)
		},
		{
			name:   "max_bcrypt_cost",
			config: func() *Config { c := Default(); c.Auth.BcryptCost = 31; return c }(),
			valid:  true,
		},
		{
			name:   "min_bcrypt_cost",
			config: func() *Config { c := Default(); c.Auth.BcryptCost = 4; return c }(),
			valid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
