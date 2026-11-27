package grype

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	defaultDBUpdateInterval = 6 * time.Hour
	// grype's own limits are 30s for the update check and 5m for the download.
	dbUpdateTimeout = 10 * time.Minute
	// Far past dbUpdateTimeout, so only a download whose grype process died is removed.
	abandonedAfter = time.Hour

	downloadPrefix = "grype-db-download"
	// go-getter, which grype downloads through, stages the archive in the temp dir.
	getterPrefix = "getter"
)

// RefreshDatabase updates the database every interval until stop closes. immediate runs
// the first update at once; otherwise it waits one interval. interval 0 means 6h.
func (s *Scanner) RefreshDatabase(stop <-chan struct{}, interval time.Duration, immediate bool) {
	if interval <= 0 {
		interval = defaultDBUpdateInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stop
		cancel()
	}()

	if immediate {
		s.refreshOnce(ctx)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.refreshOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Scanner) refreshOnce(ctx context.Context) {
	if err := s.UpdateDatabase(ctx); err != nil {
		log.Error().Err(err).Str("scanner", ScannerName).Msg("Scheduled Grype database update failed")
	}
}

// dbCacheDir mirrors grype's db.cache-dir default and its GRYPE_DB_CACHE_DIR override.
func dbCacheDir() (string, error) {
	if dir := os.Getenv("GRYPE_DB_CACHE_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "grype", "db"), nil
}

// removeAbandonedDownloads deletes database downloads last touched before cutoff. A grype
// process killed mid-download never removes its staging dirs.
func removeAbandonedDownloads(cutoff time.Time) {
	if dir, err := dbCacheDir(); err != nil {
		log.Warn().Err(err).Str("scanner", ScannerName).Msg("Cannot locate the Grype database cache")
	} else {
		removeStaleDirs(dir, downloadPrefix, cutoff)
	}
	removeStaleDirs(os.TempDir(), getterPrefix, cutoff)
}

func removeStaleDirs(dir, prefix string, cutoff time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn().Err(err).Str("dir", dir).Msg("Cannot list dir for abandoned Grype downloads")
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Cannot remove abandoned Grype download")
			continue
		}
		log.Info().Str("path", path).Msg("Removed abandoned Grype download")
	}
}
