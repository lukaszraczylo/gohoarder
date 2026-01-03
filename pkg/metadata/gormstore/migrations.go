package gormstore

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// GetMigrations returns all database migrations for gormigrate
func GetMigrations() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			ID: "202601030001",
			Migrate: func(tx *gorm.DB) error {
				// Migration: Create V2 schema
				return migrateToV2(tx)
			},
			Rollback: func(tx *gorm.DB) error {
				// Rollback: Drop V2 schema (careful!)
				return rollbackFromV2(tx)
			},
		},
		// Future migrations go here
		// {
		//     ID: "202601040001",
		//     Migrate: func(tx *gorm.DB) error {
		//         // Add new column, index, etc.
		//         return tx.Exec("ALTER TABLE packages ADD COLUMN new_field VARCHAR(255)").Error
		//     },
		//     Rollback: func(tx *gorm.DB) error {
		//         return tx.Exec("ALTER TABLE packages DROP COLUMN new_field").Error
		//     },
		// },
	}
}

// migrateToV2 creates the complete V2 schema
func migrateToV2(tx *gorm.DB) error {
	// Get dialect name for database-specific features
	dialectName := tx.Dialector.Name()

	// Step 1: Create all tables using GORM AutoMigrate
	// This handles cross-database compatibility automatically
	if err := tx.AutoMigrate(GetAllModels()...); err != nil {
		return err
	}

	// Step 2: Seed default registries
	registries := []RegistryModel{
		{Name: "npm", DisplayName: "NPM Registry", UpstreamURL: "https://registry.npmjs.org", Enabled: true, ScanByDefault: true},
		{Name: "pypi", DisplayName: "PyPI", UpstreamURL: "https://pypi.org", Enabled: true, ScanByDefault: true},
		{Name: "go", DisplayName: "Go Modules", UpstreamURL: "https://proxy.golang.org", Enabled: true, ScanByDefault: true},
	}

	for _, reg := range registries {
		// Upsert: create if not exists
		if err := tx.Where("name = ?", reg.Name).FirstOrCreate(&reg).Error; err != nil {
			return err
		}
	}

	// Step 3: Create database-specific optimizations
	if dialectName == "postgres" {
		if err := createPostgreSQLOptimizations(tx); err != nil {
			return err
		}
	} else if dialectName == "mysql" {
		if err := createMySQLOptimizations(tx); err != nil {
			return err
		}
	}

	return nil
}

// createPostgreSQLOptimizations adds PostgreSQL-specific features
func createPostgreSQLOptimizations(tx *gorm.DB) error {
	optimizations := []string{
		// Create GIN indexes for JSONB columns
		`CREATE INDEX IF NOT EXISTS idx_package_metadata_keywords_gin
		 ON package_metadata USING GIN(keywords)`,

		`CREATE INDEX IF NOT EXISTS idx_package_metadata_raw_gin
		 ON package_metadata USING GIN(raw_metadata)`,

		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_references_gin
		 ON vulnerabilities USING GIN(references)`,

		// Create partial indexes (only non-deleted records)
		`CREATE INDEX IF NOT EXISTS idx_packages_active
		 ON packages(registry_id, name, version) WHERE deleted_at IS NULL`,

		`CREATE INDEX IF NOT EXISTS idx_packages_vulnerable
		 ON packages(vulnerability_count, highest_severity)
		 WHERE vulnerability_count > 0 AND deleted_at IS NULL`,

		// Create view for vulnerable packages
		`CREATE OR REPLACE VIEW v_vulnerable_packages AS
		 SELECT
		   r.name AS registry,
		   p.name,
		   p.version,
		   p.vulnerability_count,
		   p.highest_severity,
		   p.last_scanned_at
		 FROM packages p
		 JOIN registries r ON p.registry_id = r.id
		 WHERE p.vulnerability_count > 0 AND p.deleted_at IS NULL
		 ORDER BY
		   CASE p.highest_severity
		     WHEN 'critical' THEN 1
		     WHEN 'high' THEN 2
		     WHEN 'medium' THEN 3
		     WHEN 'low' THEN 4
		     ELSE 5
		   END,
		   p.vulnerability_count DESC`,

		// Create function for automatic partition creation
		`CREATE OR REPLACE FUNCTION create_next_month_partitions()
		 RETURNS void AS $$
		 DECLARE
		   next_month DATE := date_trunc('month', NOW() + INTERVAL '2 months');
		   partition_name TEXT;
		   start_date TEXT;
		   end_date TEXT;
		 BEGIN
		   -- Download events partition
		   partition_name := 'download_events_' || to_char(next_month, 'YYYY_MM');
		   start_date := to_char(next_month, 'YYYY-MM-DD');
		   end_date := to_char(next_month + INTERVAL '1 month', 'YYYY-MM-DD');

		   EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF download_events FOR VALUES FROM (%L) TO (%L)',
		     partition_name, start_date, end_date);

		   -- Audit log partition
		   partition_name := 'audit_log_' || to_char(next_month, 'YYYY_MM');
		   EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
		     partition_name, start_date, end_date);

		   RAISE NOTICE 'Created partitions for %', to_char(next_month, 'YYYY-MM');
		 END;
		 $$ LANGUAGE plpgsql`,
	}

	for _, sql := range optimizations {
		if err := tx.Exec(sql).Error; err != nil {
			// Log warning but don't fail migration
			// Some optimizations might already exist
			continue
		}
	}

	return nil
}

// createMySQLOptimizations adds MySQL-specific features
func createMySQLOptimizations(tx *gorm.DB) error {
	optimizations := []string{
		// Create view for vulnerable packages
		`CREATE OR REPLACE VIEW v_vulnerable_packages AS
		 SELECT
		   r.name AS registry,
		   p.name,
		   p.version,
		   p.vulnerability_count,
		   p.highest_severity,
		   p.last_scanned_at
		 FROM packages p
		 JOIN registries r ON p.registry_id = r.id
		 WHERE p.vulnerability_count > 0 AND p.deleted_at IS NULL
		 ORDER BY
		   CASE p.highest_severity
		     WHEN 'critical' THEN 1
		     WHEN 'high' THEN 2
		     WHEN 'medium' THEN 3
		     WHEN 'low' THEN 4
		     ELSE 5
		   END,
		   p.vulnerability_count DESC`,
	}

	for _, sql := range optimizations {
		if err := tx.Exec(sql).Error; err != nil {
			continue
		}
	}

	return nil
}

// rollbackFromV2 drops all V2 tables (USE WITH CAUTION!)
func rollbackFromV2(tx *gorm.DB) error {
	// Drop in reverse order to respect foreign keys
	tables := []string{
		"audit_log",
		"download_stats_daily",
		"download_stats_hourly",
		"download_events",
		"cve_bypasses",
		"scan_results",
		"package_vulnerabilities",
		"vulnerabilities",
		"package_metadata",
		"packages",
		"registries",
	}

	// Drop PostgreSQL-specific objects
	if tx.Dialector.Name() == "postgres" {
		tx.Exec("DROP VIEW IF EXISTS v_vulnerable_packages")
		tx.Exec("DROP FUNCTION IF EXISTS create_next_month_partitions()")
	}

	// Drop MySQL-specific objects
	if tx.Dialector.Name() == "mysql" {
		tx.Exec("DROP VIEW IF EXISTS v_vulnerable_packages")
	}

	// Drop all tables
	for _, table := range tables {
		if err := tx.Migrator().DropTable(table); err != nil {
			// Continue even if table doesn't exist
			continue
		}
	}

	return nil
}
