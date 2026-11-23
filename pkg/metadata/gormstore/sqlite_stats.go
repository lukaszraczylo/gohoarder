package gormstore

import (
	"fmt"

	"gorm.io/gorm"
)

// ensureSQLiteStatsIndexes gives SQLite the unique indexes PostgreSQL gets from
// the partition manager, merging duplicate rows written before they existed.
func ensureSQLiteStatsIndexes(db *gorm.DB) error {
	var present int64
	if err := db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_stats_hourly_upsert', 'idx_stats_daily_upsert')").Scan(&present).Error; err != nil {
		return err
	}
	if present == int64(len(statsUpsertIndexes)) {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// Hourly package rows come from passes over disjoint events, so they add up.
		// Registry rows (NULL package) and daily rows are derived and recomputed by the
		// next pass; one copy of each is enough.
		const group = "d.registry_id = download_stats_hourly.registry_id AND d.package_id = download_stats_hourly.package_id AND d.time_bucket = download_stats_hourly.time_bucket"
		merge := `UPDATE download_stats_hourly SET
			download_count = (SELECT SUM(d.download_count) FROM download_stats_hourly d WHERE ` + group + `),
			auth_downloads = (SELECT SUM(d.auth_downloads) FROM download_stats_hourly d WHERE ` + group + `),
			unique_ips = (SELECT MAX(d.unique_ips) FROM download_stats_hourly d WHERE ` + group + `)
			WHERE package_id IS NOT NULL AND id = (SELECT MIN(d.id) FROM download_stats_hourly d WHERE ` + group + `)`
		if err := tx.Exec(merge).Error; err != nil {
			return fmt.Errorf("merge duplicate hourly stats rows: %w", err)
		}
		for _, table := range []string{"download_stats_hourly", "download_stats_daily"} {
			dedupe := fmt.Sprintf("DELETE FROM %[1]s WHERE id NOT IN (SELECT MIN(id) FROM %[1]s GROUP BY registry_id, COALESCE(package_id, 0), time_bucket)", table)
			if err := tx.Exec(dedupe).Error; err != nil {
				return fmt.Errorf("delete duplicate %s rows: %w", table, err)
			}
		}
		for _, stmt := range statsUpsertIndexes {
			if err := tx.Exec(stmt).Error; err != nil {
				return fmt.Errorf("create stats upsert index: %w", err)
			}
		}
		return nil
	})
}
