package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type MigrationConfig struct {
	Driver   string
	DSN      string
	Timeout  time.Duration
	Action   string // migrate, rollback, rollback-to, list
	TargetID string // For rollback-to
	LogLevel string
}

func main() {
	cfg := MigrationConfig{}

	flag.StringVar(&cfg.Driver, "driver", os.Getenv("DB_DRIVER"), "Database driver (postgres, mysql, sqlite)")
	flag.StringVar(&cfg.DSN, "dsn", os.Getenv("DATABASE_URL"), "Database connection string")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Minute, "Migration timeout")
	flag.StringVar(&cfg.Action, "action", "migrate", "Action: migrate, rollback, rollback-to, list")
	flag.StringVar(&cfg.TargetID, "target", "", "Target migration ID (for rollback-to)")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, error")
	flag.Parse()

	// Setup logging
	setupLogging(cfg.LogLevel)

	log.Info().
		Str("driver", cfg.Driver).
		Str("action", cfg.Action).
		Msg("Starting database migration")

	if err := RunMigration(cfg); err != nil {
		log.Fatal().Err(err).Msg("Migration failed")
	}

	log.Info().Msg("Migration completed successfully")
}

func setupLogging(level string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func RunMigration(cfg MigrationConfig) error {
	// Validate config
	if cfg.Driver == "" {
		return fmt.Errorf("driver is required (set DB_DRIVER or --driver)")
	}
	if cfg.DSN == "" {
		return fmt.Errorf("DSN is required (set DATABASE_URL or --dsn)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Connect to database
	db, err := connectToDatabase(cfg.Driver, cfg.DSN)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}
	defer sqlDB.Close()

	// Wait for database to be ready
	if err := waitForDB(ctx, sqlDB, 60*time.Second); err != nil {
		return fmt.Errorf("database not ready: %w", err)
	}

	// Initialize gormigrate with custom options
	opts := gormigrate.DefaultOptions
	opts.TableName = "gohoarder_migrations"
	m := gormigrate.New(db, opts, gormstore.GetMigrations())

	log.Info().
		Str("table", "gohoarder_migrations").
		Msg("Migration tracking table initialized")

	// Execute action
	switch cfg.Action {
	case "migrate":
		return runMigrate(m)
	case "rollback":
		return runRollback(m)
	case "rollback-to":
		if cfg.TargetID == "" {
			return fmt.Errorf("target migration ID required for rollback-to")
		}
		return runRollbackTo(m, cfg.TargetID)
	case "list":
		return listMigrations(db)
	default:
		return fmt.Errorf("unknown action: %s (use: migrate, rollback, rollback-to, list)", cfg.Action)
	}
}

func connectToDatabase(driver, dsn string) (*gorm.DB, error) {
	// Configure GORM logger using standard library log
	gormLogger := logger.New(
		stdlog.New(os.Stdout, "\r\n", stdlog.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Info,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	var dialector gorm.Dialector
	switch driver {
	case "sqlite":
		dialector = sqlite.Open(dsn)
	case "postgres", "postgresql":
		dialector = postgres.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported driver: %s", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: false, // Migrations should be transactional
		PrepareStmt:            true,
	})

	if err != nil {
		return nil, err
	}

	return db, nil
}

func waitForDB(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	attempt := 0

	for {
		attempt++
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for database after %d attempts", attempt)
		}

		if err := db.PingContext(ctx); err == nil {
			log.Info().
				Int("attempts", attempt).
				Msg("Database is ready")
			return nil
		}

		log.Debug().
			Int("attempt", attempt).
			Msg("Waiting for database...")
		time.Sleep(2 * time.Second)
	}
}

func runMigrate(m *gormigrate.Gormigrate) error {
	log.Info().Msg("Running migrations...")

	if err := m.Migrate(); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Info().Msg("✓ All migrations applied successfully")
	return nil
}

func runRollback(m *gormigrate.Gormigrate) error {
	log.Warn().Msg("Rolling back last migration...")

	if err := m.RollbackLast(); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	log.Info().Msg("✓ Rollback completed")
	return nil
}

func runRollbackTo(m *gormigrate.Gormigrate, targetID string) error {
	log.Warn().
		Str("target_id", targetID).
		Msg("Rolling back to migration...")

	if err := m.RollbackTo(targetID); err != nil {
		return fmt.Errorf("rollback to %s failed: %w", targetID, err)
	}

	log.Info().
		Str("target_id", targetID).
		Msg("✓ Rollback completed")
	return nil
}

func listMigrations(db *gorm.DB) error {
	log.Info().Msg("Applied migrations:")

	type Migration struct {
		ID string
	}

	var migrations []Migration
	if err := db.Table("gohoarder_migrations").Find(&migrations).Error; err != nil {
		return fmt.Errorf("failed to list migrations: %w", err)
	}

	if len(migrations) == 0 {
		log.Info().Msg("  (no migrations applied yet)")
		return nil
	}

	for _, m := range migrations {
		log.Info().Str("id", m.ID).Msg("  ✓")
	}

	log.Info().
		Int("total", len(migrations)).
		Msg("Applied migrations")

	return nil
}
