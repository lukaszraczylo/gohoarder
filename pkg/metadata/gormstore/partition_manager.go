package gormstore

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// PartitionManager handles automatic partition creation and cleanup for PostgreSQL
type PartitionManager struct {
	db *gorm.DB
}

// NewPartitionManager creates a new partition manager
func NewPartitionManager(db *gorm.DB) *PartitionManager {
	return &PartitionManager{db: db}
}

// EnsurePartitions ensures required partitions exist for current and future months
func (pm *PartitionManager) EnsurePartitions() error {
	// Check if we're using PostgreSQL
	if pm.db.Dialector.Name() != "postgres" {
		log.Debug().Msg("Partitioning only supported on PostgreSQL, skipping")
		return nil
	}

	log.Info().Msg("Ensuring partitions exist")

	// Create partitions for download_events
	if err := pm.ensureDownloadEventPartitions(); err != nil {
		return err
	}

	// Create partitions for audit_log
	if err := pm.ensureAuditLogPartitions(); err != nil {
		return err
	}

	// Set up automatic partition creation
	if err := pm.createPartitionFunction(); err != nil {
		log.Warn().Err(err).Msg("Failed to create partition function (may already exist)")
	}

	return nil
}

// ensureDownloadEventPartitions creates download_events partitions
func (pm *PartitionManager) ensureDownloadEventPartitions() error {
	// Check if table is already partitioned
	var isPartitioned bool
	err := pm.db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM pg_partitioned_table
			WHERE partrelid = 'download_events'::regclass
		)
	`).Scan(&isPartitioned).Error

	if err != nil {
		return err
	}

	if !isPartitioned {
		log.Info().Msg("Converting download_events to partitioned table")

		// Rename existing table
		if err := pm.db.Exec("ALTER TABLE IF EXISTS download_events RENAME TO download_events_old").Error; err != nil {
			log.Warn().Err(err).Msg("Could not rename old table (may not exist)")
		}

		// Create partitioned table
		createTableSQL := `
			CREATE TABLE IF NOT EXISTS download_events (
				id             BIGSERIAL,
				package_id     BIGINT NOT NULL,
				registry_id    INTEGER NOT NULL,
				downloaded_at  TIMESTAMP NOT NULL,
				user_agent     VARCHAR(512),
				ip_address     VARCHAR(45),
				authenticated  BOOLEAN NOT NULL DEFAULT FALSE,
				username       VARCHAR(255)
			) PARTITION BY RANGE (downloaded_at)
		`

		if err := pm.db.Exec(createTableSQL).Error; err != nil {
			return fmt.Errorf("failed to create partitioned table: %w", err)
		}

		log.Info().Msg("Created partitioned download_events table")
	}

	// Create partitions for past 3 months, current month, and next 3 months
	now := time.Now()
	for i := -3; i <= 3; i++ {
		month := now.AddDate(0, i, 0)
		if err := pm.createDownloadEventPartition(month); err != nil {
			log.Error().Err(err).Time("month", month).Msg("Failed to create partition")
		}
	}

	return nil
}

// createDownloadEventPartition creates a partition for a specific month
func (pm *PartitionManager) createDownloadEventPartition(month time.Time) error {
	// Truncate to start of month
	startOfMonth := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	endOfMonth := startOfMonth.AddDate(0, 1, 0)

	partitionName := fmt.Sprintf("download_events_%d_%02d", month.Year(), month.Month())

	// Check if partition already exists
	var exists bool
	err := pm.db.Raw("SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = ?)", partitionName).Scan(&exists).Error
	if err != nil {
		return err
	}

	if exists {
		log.Debug().Str("partition", partitionName).Msg("Partition already exists")
		return nil
	}

	// Create partition
	createPartitionSQL := fmt.Sprintf(`
		CREATE TABLE %s PARTITION OF download_events
		FOR VALUES FROM ('%s') TO ('%s')
	`, partitionName, startOfMonth.Format("2006-01-02"), endOfMonth.Format("2006-01-02"))

	if err := pm.db.Exec(createPartitionSQL).Error; err != nil {
		return fmt.Errorf("failed to create partition %s: %w", partitionName, err)
	}

	// Create indexes on partition
	indexSQL := []string{
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_package_idx ON %s(package_id, downloaded_at)", partitionName, partitionName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_registry_idx ON %s(registry_id)", partitionName, partitionName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_time_idx ON %s(downloaded_at)", partitionName, partitionName),
	}

	for _, sql := range indexSQL {
		if err := pm.db.Exec(sql).Error; err != nil {
			log.Warn().Err(err).Str("sql", sql).Msg("Failed to create index")
		}
	}

	log.Info().Str("partition", partitionName).Msg("Created partition")
	return nil
}

// ensureAuditLogPartitions creates audit_log partitions
func (pm *PartitionManager) ensureAuditLogPartitions() error {
	// Check if table exists
	var exists bool
	err := pm.db.Raw("SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'audit_log')").Scan(&exists).Error
	if err != nil {
		return err
	}

	if !exists {
		// Create partitioned table
		createTableSQL := `
			CREATE TABLE IF NOT EXISTS audit_log (
				id          BIGSERIAL,
				entity_type VARCHAR(50) NOT NULL,
				entity_id   BIGINT NOT NULL,
				action      VARCHAR(20) NOT NULL,
				username    VARCHAR(255) NOT NULL,
				timestamp   TIMESTAMP NOT NULL,
				changes     JSONB,
				ip_address  VARCHAR(45),
				user_agent  VARCHAR(512)
			) PARTITION BY RANGE (timestamp)
		`

		if err := pm.db.Exec(createTableSQL).Error; err != nil {
			return fmt.Errorf("failed to create audit_log table: %w", err)
		}

		log.Info().Msg("Created partitioned audit_log table")
	}

	// Create partitions for past month, current month, and next 2 months
	now := time.Now()
	for i := -1; i <= 2; i++ {
		month := now.AddDate(0, i, 0)
		if err := pm.createAuditLogPartition(month); err != nil {
			log.Error().Err(err).Time("month", month).Msg("Failed to create audit partition")
		}
	}

	return nil
}

// createAuditLogPartition creates a partition for a specific month
func (pm *PartitionManager) createAuditLogPartition(month time.Time) error {
	startOfMonth := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	endOfMonth := startOfMonth.AddDate(0, 1, 0)

	partitionName := fmt.Sprintf("audit_log_%d_%02d", month.Year(), month.Month())

	// Check if partition already exists
	var exists bool
	err := pm.db.Raw("SELECT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = ?)", partitionName).Scan(&exists).Error
	if err != nil {
		return err
	}

	if exists {
		return nil
	}

	// Create partition
	createPartitionSQL := fmt.Sprintf(`
		CREATE TABLE %s PARTITION OF audit_log
		FOR VALUES FROM ('%s') TO ('%s')
	`, partitionName, startOfMonth.Format("2006-01-02"), endOfMonth.Format("2006-01-02"))

	if err := pm.db.Exec(createPartitionSQL).Error; err != nil {
		return fmt.Errorf("failed to create partition %s: %w", partitionName, err)
	}

	// Create indexes
	indexSQL := []string{
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_entity_idx ON %s(entity_type, entity_id)", partitionName, partitionName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_user_idx ON %s(username)", partitionName, partitionName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_time_idx ON %s(timestamp)", partitionName, partitionName),
	}

	for _, sql := range indexSQL {
		if err := pm.db.Exec(sql).Error; err != nil {
			log.Warn().Err(err).Msg("Failed to create audit index")
		}
	}

	log.Info().Str("partition", partitionName).Msg("Created audit partition")
	return nil
}

// createPartitionFunction creates a PostgreSQL function for automatic partition creation
func (pm *PartitionManager) createPartitionFunction() error {
	functionSQL := `
		CREATE OR REPLACE FUNCTION create_next_month_partitions()
		RETURNS void AS $$
		DECLARE
			next_month DATE := date_trunc('month', NOW() + INTERVAL '2 months');
			partition_name TEXT;
			start_date TEXT;
			end_date TEXT;
		BEGIN
			-- Create download_events partition
			partition_name := 'download_events_' || to_char(next_month, 'YYYY_MM');
			start_date := to_char(next_month, 'YYYY-MM-DD');
			end_date := to_char(next_month + INTERVAL '1 month', 'YYYY-MM-DD');

			EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF download_events FOR VALUES FROM (%L) TO (%L)',
				partition_name, start_date, end_date);

			EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(package_id, downloaded_at)',
				partition_name || '_package_idx', partition_name);
			EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(registry_id)',
				partition_name || '_registry_idx', partition_name);

			-- Create audit_log partition
			partition_name := 'audit_log_' || to_char(next_month, 'YYYY_MM');

			EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
				partition_name, start_date, end_date);

			EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(entity_type, entity_id)',
				partition_name || '_entity_idx', partition_name);

			RAISE NOTICE 'Created partitions for %', to_char(next_month, 'YYYY-MM');
		END;
		$$ LANGUAGE plpgsql;
	`

	if err := pm.db.Exec(functionSQL).Error; err != nil {
		return err
	}

	log.Info().Msg("Created partition management function")
	return nil
}

// CleanupOldPartitions drops partitions older than the retention period
func (pm *PartitionManager) CleanupOldPartitions(retentionMonths int) error {
	if pm.db.Dialector.Name() != "postgres" {
		return nil
	}

	cutoffDate := time.Now().AddDate(0, -retentionMonths, 0)
	cutoffPartition := fmt.Sprintf("%d_%02d", cutoffDate.Year(), cutoffDate.Month())

	log.Info().
		Str("cutoff", cutoffPartition).
		Int("retention_months", retentionMonths).
		Msg("Cleaning up old partitions")

	// Find and drop old download_events partitions
	var downloadPartitions []string
	err := pm.db.Raw(`
		SELECT tablename FROM pg_tables
		WHERE tablename LIKE 'download_events_%'
		AND tablename < 'download_events_' || ?
	`, cutoffPartition).Scan(&downloadPartitions).Error

	if err != nil {
		return err
	}

	for _, partition := range downloadPartitions {
		log.Info().Str("partition", partition).Msg("Dropping old partition")
		if err := pm.db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", partition)).Error; err != nil {
			log.Error().Err(err).Str("partition", partition).Msg("Failed to drop partition")
		}
	}

	// Find and drop old audit_log partitions
	var auditPartitions []string
	err = pm.db.Raw(`
		SELECT tablename FROM pg_tables
		WHERE tablename LIKE 'audit_log_%'
		AND tablename < 'audit_log_' || ?
	`, cutoffPartition).Scan(&auditPartitions).Error

	if err != nil {
		return err
	}

	for _, partition := range auditPartitions {
		log.Info().Str("partition", partition).Msg("Dropping old audit partition")
		if err := pm.db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", partition)).Error; err != nil {
			log.Error().Err(err).Str("partition", partition).Msg("Failed to drop audit partition")
		}
	}

	return nil
}

// GetPartitionInfo returns information about current partitions
func (pm *PartitionManager) GetPartitionInfo() (map[string]interface{}, error) {
	if pm.db.Dialector.Name() != "postgres" {
		return map[string]interface{}{"status": "not_applicable"}, nil
	}

	info := make(map[string]interface{})

	// Count download_events partitions
	var downloadCount int64
	pm.db.Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename LIKE 'download_events_%'").Scan(&downloadCount)
	info["download_events_partitions"] = downloadCount

	// Count audit_log partitions
	var auditCount int64
	pm.db.Raw("SELECT COUNT(*) FROM pg_tables WHERE tablename LIKE 'audit_log_%'").Scan(&auditCount)
	info["audit_log_partitions"] = auditCount

	// Get partition sizes
	type PartitionSize struct {
		TableName string
		SizeMB    float64
	}

	var partitionSizes []PartitionSize
	pm.db.Raw(`
		SELECT
			tablename AS table_name,
			pg_total_relation_size(tablename::regclass) / 1024.0 / 1024.0 AS size_mb
		FROM pg_tables
		WHERE tablename LIKE 'download_events_%' OR tablename LIKE 'audit_log_%'
		ORDER BY size_mb DESC
		LIMIT 10
	`).Scan(&partitionSizes)

	info["largest_partitions"] = partitionSizes

	return info, nil
}
