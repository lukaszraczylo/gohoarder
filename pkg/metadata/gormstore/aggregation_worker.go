package gormstore

import (
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// AggregationWorker handles background aggregation of download statistics
type AggregationWorker struct {
	db       *gorm.DB
	stopChan chan struct{}
	ticker   *time.Ticker
}

// NewAggregationWorker creates a new aggregation worker
func NewAggregationWorker(db *gorm.DB) *AggregationWorker {
	return &AggregationWorker{
		db:       db,
		stopChan: make(chan struct{}),
		ticker:   time.NewTicker(1 * time.Hour), // Run every hour
	}
}

// Start begins the aggregation worker
func (w *AggregationWorker) Start() {
	log.Info().Msg("Starting aggregation worker")

	// Run immediately on start
	if err := w.AggregateHourly(); err != nil {
		log.Error().Err(err).Msg("Failed to run initial hourly aggregation")
	}

	for {
		select {
		case <-w.ticker.C:
			if err := w.AggregateHourly(); err != nil {
				log.Error().Err(err).Msg("Failed to aggregate hourly stats")
			}

			// Check if it's time for daily aggregation (run at midnight)
			now := time.Now()
			if now.Hour() == 0 {
				if err := w.AggregateDaily(); err != nil {
					log.Error().Err(err).Msg("Failed to aggregate daily stats")
				}
			}

		case <-w.stopChan:
			log.Info().Msg("Stopping aggregation worker")
			w.ticker.Stop()
			return
		}
	}
}

// Stop stops the aggregation worker
func (w *AggregationWorker) Stop() {
	close(w.stopChan)
}

// AggregateHourly aggregates download events into hourly stats
func (w *AggregationWorker) AggregateHourly() error {
	startTime := time.Now()
	log.Debug().Msg("Starting hourly aggregation")

	// Get dialect name
	dialectName := w.db.Dialector.Name()

	// Calculate cutoff time (aggregate events older than 5 minutes to avoid partial data)
	cutoff := time.Now().Add(-5 * time.Minute).Truncate(time.Hour)

	return w.db.Transaction(func(tx *gorm.DB) error {
		var aggregateSQL string

		switch dialectName {
		case "postgres":
			// PostgreSQL: Use date_trunc for time bucketing
			aggregateSQL = `
				INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
				SELECT
					de.registry_id,
					de.package_id,
					date_trunc('hour', de.downloaded_at) AS time_bucket,
					COUNT(*) AS download_count,
					COUNT(DISTINCT de.ip_address) AS unique_ips,
					COUNT(*) FILTER (WHERE de.authenticated = true) AS auth_downloads,
					NOW() AS created_at,
					NOW() AS updated_at
				FROM download_events de
				WHERE de.downloaded_at < ?
				GROUP BY de.registry_id, de.package_id, time_bucket
				ON CONFLICT (registry_id, COALESCE(package_id, 0), time_bucket)
				DO UPDATE SET
					download_count = download_stats_hourly.download_count + EXCLUDED.download_count,
					unique_ips = GREATEST(download_stats_hourly.unique_ips, EXCLUDED.unique_ips),
					auth_downloads = download_stats_hourly.auth_downloads + EXCLUDED.auth_downloads,
					updated_at = NOW()
			`

		case "mysql":
			// MySQL: Use DATE_FORMAT for time bucketing
			aggregateSQL = `
				INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
				SELECT
					de.registry_id,
					de.package_id,
					DATE_FORMAT(de.downloaded_at, '%Y-%m-%d %H:00:00') AS time_bucket,
					COUNT(*) AS download_count,
					COUNT(DISTINCT de.ip_address) AS unique_ips,
					SUM(CASE WHEN de.authenticated = true THEN 1 ELSE 0 END) AS auth_downloads,
					NOW() AS created_at,
					NOW() AS updated_at
				FROM download_events de
				WHERE de.downloaded_at < ?
				GROUP BY de.registry_id, de.package_id, time_bucket
				ON DUPLICATE KEY UPDATE
					download_count = download_stats_hourly.download_count + VALUES(download_count),
					unique_ips = GREATEST(download_stats_hourly.unique_ips, VALUES(unique_ips)),
					auth_downloads = download_stats_hourly.auth_downloads + VALUES(auth_downloads),
					updated_at = NOW()
			`

		default: // SQLite
			// SQLite: Use strftime for time bucketing
			// Note: SQLite doesn't support UPSERT as elegantly, need to handle separately
			aggregateSQL = `
				INSERT OR REPLACE INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
				SELECT
					de.registry_id,
					de.package_id,
					strftime('%Y-%m-%d %H:00:00', de.downloaded_at) AS time_bucket,
					COUNT(*) AS download_count,
					COUNT(DISTINCT de.ip_address) AS unique_ips,
					SUM(CASE WHEN de.authenticated = 1 THEN 1 ELSE 0 END) AS auth_downloads,
					datetime('now') AS created_at,
					datetime('now') AS updated_at
				FROM download_events de
				WHERE de.downloaded_at < ?
				GROUP BY de.registry_id, de.package_id, time_bucket
			`
		}

		// Execute aggregation
		if err := tx.Exec(aggregateSQL, cutoff).Error; err != nil {
			return err
		}

		// Delete aggregated events (older than 24 hours to keep recent data for debugging)
		deleteOlder := time.Now().Add(-24 * time.Hour)
		deleteResult := tx.Exec("DELETE FROM download_events WHERE downloaded_at < ?", deleteOlder)
		if deleteResult.Error != nil {
			return deleteResult.Error
		}

		// Also update package-level stats (NULL package_id = registry totals)
		var registryAggSQL string
		if dialectName == "postgres" {
			registryAggSQL = `
				INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
				SELECT
					registry_id,
					NULL as package_id,
					time_bucket,
					SUM(download_count) as download_count,
					SUM(unique_ips) as unique_ips,
					SUM(auth_downloads) as auth_downloads,
					NOW() as created_at,
					NOW() as updated_at
				FROM download_stats_hourly
				WHERE package_id IS NOT NULL
				GROUP BY registry_id, time_bucket
				ON CONFLICT (registry_id, COALESCE(package_id, 0), time_bucket)
				DO UPDATE SET
					download_count = EXCLUDED.download_count,
					unique_ips = EXCLUDED.unique_ips,
					auth_downloads = EXCLUDED.auth_downloads,
					updated_at = NOW()
			`
		} else if dialectName == "mysql" {
			registryAggSQL = `
				INSERT INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
				SELECT
					registry_id,
					NULL as package_id,
					time_bucket,
					SUM(download_count) as download_count,
					SUM(unique_ips) as unique_ips,
					SUM(auth_downloads) as auth_downloads,
					NOW() as created_at,
					NOW() as updated_at
				FROM download_stats_hourly
				WHERE package_id IS NOT NULL
				GROUP BY registry_id, time_bucket
				ON DUPLICATE KEY UPDATE
					download_count = VALUES(download_count),
					unique_ips = VALUES(unique_ips),
					auth_downloads = VALUES(auth_downloads),
					updated_at = NOW()
			`
		} else {
			// SQLite
			registryAggSQL = `
				INSERT OR REPLACE INTO download_stats_hourly (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, created_at, updated_at)
				SELECT
					registry_id,
					NULL as package_id,
					time_bucket,
					SUM(download_count) as download_count,
					SUM(unique_ips) as unique_ips,
					SUM(auth_downloads) as auth_downloads,
					datetime('now') as created_at,
					datetime('now') as updated_at
				FROM download_stats_hourly
				WHERE package_id IS NOT NULL
				GROUP BY registry_id, time_bucket
			`
		}

		if err := tx.Exec(registryAggSQL).Error; err != nil {
			log.Warn().Err(err).Msg("Failed to aggregate registry totals (continuing anyway)")
		}

		elapsed := time.Since(startTime)
		log.Info().
			Int64("deleted_events", deleteResult.RowsAffected).
			Dur("duration", elapsed).
			Msg("Completed hourly aggregation")

		return nil
	})
}

// AggregateDaily aggregates hourly stats into daily stats
func (w *AggregationWorker) AggregateDaily() error {
	startTime := time.Now()
	log.Debug().Msg("Starting daily aggregation")

	dialectName := w.db.Dialector.Name()

	// Aggregate yesterday's data
	yesterday := time.Now().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	dayEnd := yesterday.Add(24 * time.Hour)

	return w.db.Transaction(func(tx *gorm.DB) error {
		var aggregateSQL string

		switch dialectName {
		case "postgres":
			aggregateSQL = `
				INSERT INTO download_stats_daily (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, top_user_agents, created_at, updated_at)
				SELECT
					registry_id,
					package_id,
					date_trunc('day', time_bucket) AS time_bucket,
					SUM(download_count) AS download_count,
					MAX(unique_ips) AS unique_ips,
					SUM(auth_downloads) AS auth_downloads,
					'{}' AS top_user_agents,
					NOW() AS created_at,
					NOW() AS updated_at
				FROM download_stats_hourly
				WHERE time_bucket >= ? AND time_bucket < ?
				GROUP BY registry_id, package_id, date_trunc('day', time_bucket)
				ON CONFLICT (registry_id, COALESCE(package_id, 0), time_bucket)
				DO UPDATE SET
					download_count = EXCLUDED.download_count,
					unique_ips = EXCLUDED.unique_ips,
					auth_downloads = EXCLUDED.auth_downloads,
					updated_at = NOW()
			`

		case "mysql":
			aggregateSQL = `
				INSERT INTO download_stats_daily (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, top_user_agents, created_at, updated_at)
				SELECT
					registry_id,
					package_id,
					DATE_FORMAT(time_bucket, '%Y-%m-%d 00:00:00') AS time_bucket,
					SUM(download_count) AS download_count,
					MAX(unique_ips) AS unique_ips,
					SUM(auth_downloads) AS auth_downloads,
					'{}' AS top_user_agents,
					NOW() AS created_at,
					NOW() AS updated_at
				FROM download_stats_hourly
				WHERE time_bucket >= ? AND time_bucket < ?
				GROUP BY registry_id, package_id, DATE_FORMAT(time_bucket, '%Y-%m-%d 00:00:00')
				ON DUPLICATE KEY UPDATE
					download_count = VALUES(download_count),
					unique_ips = VALUES(unique_ips),
					auth_downloads = VALUES(auth_downloads),
					updated_at = NOW()
			`

		default: // SQLite
			aggregateSQL = `
				INSERT OR REPLACE INTO download_stats_daily (registry_id, package_id, time_bucket, download_count, unique_ips, auth_downloads, top_user_agents, created_at, updated_at)
				SELECT
					registry_id,
					package_id,
					date(time_bucket) AS time_bucket,
					SUM(download_count) AS download_count,
					MAX(unique_ips) AS unique_ips,
					SUM(auth_downloads) AS auth_downloads,
					'{}' AS top_user_agents,
					datetime('now') AS created_at,
					datetime('now') AS updated_at
				FROM download_stats_hourly
				WHERE time_bucket >= ? AND time_bucket < ?
				GROUP BY registry_id, package_id, date(time_bucket)
			`
		}

		if err := tx.Exec(aggregateSQL, yesterday, dayEnd).Error; err != nil {
			return err
		}

		// Delete old hourly stats (keep last 7 days)
		deleteOlder := time.Now().AddDate(0, 0, -7)
		deleteResult := tx.Exec("DELETE FROM download_stats_hourly WHERE time_bucket < ?", deleteOlder)
		if deleteResult.Error != nil {
			return deleteResult.Error
		}

		elapsed := time.Since(startTime)
		log.Info().
			Int64("deleted_hourly_stats", deleteResult.RowsAffected).
			Dur("duration", elapsed).
			Msg("Completed daily aggregation")

		return nil
	})
}

// UpdatePackageAccessCounts synchronizes package access_count from download stats
func (w *AggregationWorker) UpdatePackageAccessCounts() error {
	log.Debug().Msg("Updating package access counts")

	// Update from download_stats_hourly (sum all-time downloads per package)
	updateSQL := `
		UPDATE packages p
		SET access_count = COALESCE((
			SELECT SUM(download_count)
			FROM download_stats_hourly dsh
			WHERE dsh.package_id = p.id
		), 0)
	`

	if err := w.db.Exec(updateSQL).Error; err != nil {
		return err
	}

	log.Info().Msg("Updated package access counts")
	return nil
}
