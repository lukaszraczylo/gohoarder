package commands

import (
	"fmt"

	"github.com/lukaszraczylo/gohoarder/internal/version"
	"github.com/lukaszraczylo/gohoarder/pkg/app"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	configPath string
)

// ServeCmd starts the HTTP server
var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the GoHoarder server",
	Long:  "Start the HTTP server to serve as a package cache proxy",
	RunE:  runServe,
}

func init() {
	ServeCmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to config file")
}

func runServe(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	if err := logger.Init(logger.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
	}); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	log.Info().
		Str("version", version.Version).
		Str("commit", version.GitCommit).
		Msg("Starting GoHoarder")

	// Create and run application
	application, err := app.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create application: %w", err)
	}

	// Run application (blocks until shutdown)
	if err := application.Run(); err != nil {
		return fmt.Errorf("application error: %w", err)
	}

	return nil
}
