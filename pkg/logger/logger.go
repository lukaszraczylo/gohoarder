package logger

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Config contains logger configuration
type Config struct {
	Level  string // debug, info, warn, error
	Format string // json, pretty
}

// Init initializes the global logger
func Init(cfg Config) error {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Set time format
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	// Set format
	if cfg.Format == "pretty" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05.000"})
	} else {
		// JSON format (default for production)
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}

	return nil
}

// Get returns the global logger
func Get() *zerolog.Logger {
	return &log.Logger
}

// WithFields returns a logger with additional fields
func WithFields(fields map[string]interface{}) *zerolog.Logger {
	logger := log.Logger
	for k, v := range fields {
		logger = logger.With().Interface(k, v).Logger()
	}
	return &logger
}

// WithRequestID returns a logger with request ID
func WithRequestID(requestID string) *zerolog.Logger {
	logger := log.With().Str("request_id", requestID).Logger()
	return &logger
}
