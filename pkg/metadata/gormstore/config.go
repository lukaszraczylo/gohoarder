package gormstore

import (
	"fmt"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
)

// Config holds GORM store configuration
type Config struct {
	// Database connection
	Driver string // "sqlite", "postgres", "mysql"
	DSN    string // Data Source Name

	// Connection pool
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration

	// GORM settings
	LogLevel string // "silent", "error", "warn", "info"
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Driver == "" {
		return errors.New(errors.ErrCodeInvalidConfig, "driver is required")
	}
	if c.DSN == "" {
		return errors.New(errors.ErrCodeInvalidConfig, "DSN is required")
	}

	// Set defaults
	if c.MaxOpenConns == 0 {
		c.MaxOpenConns = 25
	}
	if c.MaxIdleConns == 0 {
		c.MaxIdleConns = 5
	}
	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = time.Hour
	}
	if c.LogLevel == "" {
		c.LogLevel = "warn"
	}

	return nil
}

// BuildPostgresDSN builds PostgreSQL DSN from structured config
func BuildPostgresDSN(host string, port int, user, password, database, sslmode string) string {
	if sslmode == "" {
		sslmode = "disable"
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, database, sslmode)
}

// BuildMySQLDSN builds MySQL/MariaDB DSN from structured config
func BuildMySQLDSN(host string, port int, user, password, database, charset string) string {
	if charset == "" {
		charset = "utf8mb4"
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=True&loc=Local",
		user, password, host, port, database, charset)
}

// BuildSQLiteDSN builds SQLite DSN with pragmas
func BuildSQLiteDSN(path string, walMode bool) string {
	if path == "" {
		path = "gohoarder.db"
	}
	if walMode {
		return fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_cache_size=2000", path)
	}
	return fmt.Sprintf("%s?_journal_mode=DELETE&_busy_timeout=5000&_synchronous=NORMAL", path)
}
