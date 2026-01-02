package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	goccy_json "github.com/goccy/go-json"
	_ "modernc.org/sqlite"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
)

// SQLiteStore implements metadata.MetadataStore using SQLite
type SQLiteStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// Config holds SQLite configuration
type Config struct {
	Path         string // Database file path
	MaxOpenConns int    // Maximum open connections
	MaxIdleConns int    // Maximum idle connections
}

const schema = `
CREATE TABLE IF NOT EXISTS packages (
	id TEXT PRIMARY KEY,
	registry TEXT NOT NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	storage_key TEXT NOT NULL,
	size INTEGER NOT NULL,
	checksum_md5 TEXT,
	checksum_sha256 TEXT,
	upstream_url TEXT,
	cached_at DATETIME NOT NULL,
	last_accessed DATETIME NOT NULL,
	expires_at DATETIME,
	download_count INTEGER DEFAULT 0,
	metadata TEXT,
	security_scanned BOOLEAN DEFAULT 0,
	requires_auth BOOLEAN DEFAULT 0,
	auth_provider TEXT,
	UNIQUE(registry, name, version)
);

CREATE INDEX IF NOT EXISTS idx_packages_registry ON packages(registry);
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_cached_at ON packages(cached_at);
CREATE INDEX IF NOT EXISTS idx_packages_last_accessed ON packages(last_accessed);
CREATE INDEX IF NOT EXISTS idx_packages_expires_at ON packages(expires_at);

CREATE TABLE IF NOT EXISTS scan_results (
	id TEXT PRIMARY KEY,
	registry TEXT NOT NULL,
	package_name TEXT NOT NULL,
	package_version TEXT NOT NULL,
	scanner TEXT NOT NULL,
	scanned_at DATETIME NOT NULL,
	status TEXT NOT NULL,
	vulnerability_count INTEGER DEFAULT 0,
	vulnerabilities TEXT,
	details TEXT,
	UNIQUE(registry, package_name, package_version, scanner)
);

CREATE INDEX IF NOT EXISTS idx_scan_results_registry ON scan_results(registry);
CREATE INDEX IF NOT EXISTS idx_scan_results_package ON scan_results(package_name);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);

CREATE TABLE IF NOT EXISTS cve_bypasses (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	target TEXT NOT NULL,
	reason TEXT NOT NULL,
	created_by TEXT NOT NULL,
	created_at DATETIME NOT NULL,
	expires_at DATETIME NOT NULL,
	applies_to TEXT,
	notify_on_expiry BOOLEAN DEFAULT 0,
	active BOOLEAN DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_cve_bypasses_type ON cve_bypasses(type);
CREATE INDEX IF NOT EXISTS idx_cve_bypasses_target ON cve_bypasses(target);
CREATE INDEX IF NOT EXISTS idx_cve_bypasses_expires_at ON cve_bypasses(expires_at);
CREATE INDEX IF NOT EXISTS idx_cve_bypasses_active ON cve_bypasses(active);

CREATE TABLE IF NOT EXISTS download_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	registry TEXT NOT NULL,
	package_name TEXT NOT NULL,
	package_version TEXT NOT NULL,
	downloaded_at DATETIME NOT NULL,
	FOREIGN KEY(registry, package_name, package_version) REFERENCES packages(registry, name, version)
);

CREATE INDEX IF NOT EXISTS idx_download_events_registry ON download_events(registry);
CREATE INDEX IF NOT EXISTS idx_download_events_downloaded_at ON download_events(downloaded_at);
CREATE INDEX IF NOT EXISTS idx_download_events_package ON download_events(registry, package_name, package_version);

CREATE TABLE IF NOT EXISTS aggregated_download_stats (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	registry TEXT NOT NULL,
	time_bucket DATETIME NOT NULL,
	resolution TEXT NOT NULL,
	download_count INTEGER NOT NULL,
	UNIQUE(registry, time_bucket, resolution)
);

CREATE INDEX IF NOT EXISTS idx_aggregated_stats_registry ON aggregated_download_stats(registry);
CREATE INDEX IF NOT EXISTS idx_aggregated_stats_time_bucket ON aggregated_download_stats(time_bucket);
CREATE INDEX IF NOT EXISTS idx_aggregated_stats_resolution ON aggregated_download_stats(resolution);
`

// New creates a new SQLite metadata store
func New(cfg Config) (*SQLiteStore, error) {
	if cfg.Path == "" {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "SQLite database path is required")
	}

	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 10
	}

	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 5
	}

	// Open database with WAL mode for better concurrency
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_cache_size=2000", cfg.Path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to open SQLite database")
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Hour)

	// Create schema
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create SQLite schema")
	}

	// Run migrations for existing databases
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to run database migrations")
	}

	return &SQLiteStore{
		db: db,
	}, nil
}

// runMigrations runs database migrations for existing databases
func runMigrations(db *sql.DB) error {
	// Migration 1: Add requires_auth and auth_provider columns (if they don't exist)
	// SQLite doesn't have IF NOT EXISTS for ALTER TABLE, so we need to check first
	var columnExists int
	err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('packages') WHERE name='requires_auth'").Scan(&columnExists)
	if err != nil {
		return err
	}

	if columnExists == 0 {
		log.Info().Msg("Running migration: adding requires_auth and auth_provider columns")

		// Add requires_auth column
		if _, err := db.Exec("ALTER TABLE packages ADD COLUMN requires_auth BOOLEAN DEFAULT 0"); err != nil {
			return fmt.Errorf("failed to add requires_auth column: %w", err)
		}

		// Add auth_provider column
		if _, err := db.Exec("ALTER TABLE packages ADD COLUMN auth_provider TEXT"); err != nil {
			return fmt.Errorf("failed to add auth_provider column: %w", err)
		}

		// Create index
		if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_packages_requires_auth ON packages(requires_auth)"); err != nil {
			return fmt.Errorf("failed to create requires_auth index: %w", err)
		}

		log.Info().Msg("Migration completed successfully")
	}

	return nil
}

// SavePackage saves package metadata
func (s *SQLiteStore) SavePackage(ctx context.Context, pkg *metadata.Package) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Serialize metadata
	metadataJSON, err := goccy_json.Marshal(pkg.Metadata)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalServer, "failed to serialize package metadata")
	}

	var expiresAt interface{}
	if pkg.ExpiresAt != nil {
		expiresAt = pkg.ExpiresAt
	}

	query := `
		INSERT INTO packages (
			id, registry, name, version, storage_key, size,
			checksum_md5, checksum_sha256, upstream_url,
			cached_at, last_accessed, expires_at, download_count,
			metadata, security_scanned, requires_auth, auth_provider
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(registry, name, version) DO UPDATE SET
			storage_key = excluded.storage_key,
			size = excluded.size,
			checksum_md5 = excluded.checksum_md5,
			checksum_sha256 = excluded.checksum_sha256,
			upstream_url = excluded.upstream_url,
			last_accessed = excluded.last_accessed,
			expires_at = excluded.expires_at,
			metadata = excluded.metadata,
			security_scanned = excluded.security_scanned,
			requires_auth = excluded.requires_auth,
			auth_provider = excluded.auth_provider
	`

	_, err = s.db.ExecContext(ctx, query,
		pkg.ID, pkg.Registry, pkg.Name, pkg.Version, pkg.StorageKey, pkg.Size,
		pkg.ChecksumMD5, pkg.ChecksumSHA256, pkg.UpstreamURL,
		pkg.CachedAt, pkg.LastAccessed, expiresAt, pkg.DownloadCount,
		string(metadataJSON), pkg.SecurityScanned, pkg.RequiresAuth, pkg.AuthProvider,
	)

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save package metadata")
	}

	return nil
}

// GetPackage retrieves package metadata
func (s *SQLiteStore) GetPackage(ctx context.Context, registry, name, version string) (*metadata.Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, registry, name, version, storage_key, size,
			checksum_md5, checksum_sha256, upstream_url,
			cached_at, last_accessed, expires_at, download_count,
			metadata, security_scanned, requires_auth, auth_provider
		FROM packages
		WHERE registry = ? AND name = ? AND version = ?
	`

	var pkg metadata.Package
	var metadataJSON string
	var expiresAt sql.NullTime
	var authProvider sql.NullString

	err := s.db.QueryRowContext(ctx, query, registry, name, version).Scan(
		&pkg.ID, &pkg.Registry, &pkg.Name, &pkg.Version, &pkg.StorageKey, &pkg.Size,
		&pkg.ChecksumMD5, &pkg.ChecksumSHA256, &pkg.UpstreamURL,
		&pkg.CachedAt, &pkg.LastAccessed, &expiresAt, &pkg.DownloadCount,
		&metadataJSON, &pkg.SecurityScanned, &pkg.RequiresAuth, &authProvider,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound(fmt.Sprintf("package not found: %s/%s@%s", registry, name, version))
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get package metadata")
	}

	if expiresAt.Valid {
		pkg.ExpiresAt = &expiresAt.Time
	}

	if authProvider.Valid {
		pkg.AuthProvider = authProvider.String
	}

	// Deserialize metadata
	if metadataJSON != "" {
		if err := goccy_json.Unmarshal([]byte(metadataJSON), &pkg.Metadata); err != nil {
			log.Warn().Err(err).Msg("Failed to deserialize package metadata")
		}
	}

	return &pkg, nil
}

// DeletePackage deletes package metadata
func (s *SQLiteStore) DeletePackage(ctx context.Context, registry, name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := "DELETE FROM packages WHERE registry = ? AND name = ? AND version = ?"
	result, err := s.db.ExecContext(ctx, query, registry, name, version)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete package metadata")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("package not found: %s/%s@%s", registry, name, version))
	}

	return nil
}

// ListPackages lists packages with optional filtering
func (s *SQLiteStore) ListPackages(ctx context.Context, opts *metadata.ListOptions) ([]*metadata.Package, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, registry, name, version, storage_key, size, checksum_md5, checksum_sha256, upstream_url, cached_at, last_accessed, expires_at, download_count, metadata, security_scanned FROM packages WHERE 1=1"
	args := []interface{}{}

	if opts != nil {
		if opts.Registry != "" {
			query += " AND registry = ?"
			args = append(args, opts.Registry)
		}

		if opts.NamePrefix != "" {
			query += " AND name LIKE ?"
			args = append(args, opts.NamePrefix+"%")
		}

		if opts.MinSize > 0 {
			query += " AND size >= ?"
			args = append(args, opts.MinSize)
		}

		if opts.MaxSize > 0 {
			query += " AND size <= ?"
			args = append(args, opts.MaxSize)
		}

		if opts.ScannedOnly {
			query += " AND security_scanned = 1"
		}

		if !opts.SinceDate.IsZero() {
			query += " AND cached_at >= ?"
			args = append(args, opts.SinceDate)
		}

		// Sorting
		sortBy := "cached_at"
		if opts.SortBy != "" {
			sortBy = opts.SortBy
		}
		sortOrder := "ASC"
		if opts.SortDesc {
			sortOrder = "DESC"
		}
		query += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

		// Pagination
		if opts.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, opts.Limit)
		}

		if opts.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, opts.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list packages")
	}
	defer rows.Close()

	var packages []*metadata.Package
	for rows.Next() {
		var pkg metadata.Package
		var metadataJSON string
		var expiresAt sql.NullTime

		err := rows.Scan(
			&pkg.ID, &pkg.Registry, &pkg.Name, &pkg.Version, &pkg.StorageKey, &pkg.Size,
			&pkg.ChecksumMD5, &pkg.ChecksumSHA256, &pkg.UpstreamURL,
			&pkg.CachedAt, &pkg.LastAccessed, &expiresAt, &pkg.DownloadCount,
			&metadataJSON, &pkg.SecurityScanned,
		)

		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to scan package row")
		}

		if expiresAt.Valid {
			pkg.ExpiresAt = &expiresAt.Time
		}

		if metadataJSON != "" {
			goccy_json.Unmarshal([]byte(metadataJSON), &pkg.Metadata)
		}

		packages = append(packages, &pkg)
	}

	return packages, nil
}

// UpdateDownloadCount increments download counter and records download event
func (s *SQLiteStore) UpdateDownloadCount(ctx context.Context, registry, name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Start transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to start transaction")
	}
	defer tx.Rollback()

	// Update download count
	updateQuery := `
		UPDATE packages
		SET download_count = download_count + 1,
			last_accessed = ?
		WHERE registry = ? AND name = ? AND version = ?
	`
	_, err = tx.ExecContext(ctx, updateQuery, now, registry, name, version)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to update download count")
	}

	// Record download event for time-series statistics
	insertQuery := `
		INSERT INTO download_events (registry, package_name, package_version, downloaded_at)
		VALUES (?, ?, ?, ?)
	`
	_, err = tx.ExecContext(ctx, insertQuery, registry, name, version, now)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to record download event")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to commit transaction")
	}

	return nil
}

// GetStats returns statistics
func (s *SQLiteStore) GetStats(ctx context.Context, registry string) (*metadata.Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT
			COUNT(*) as total_packages,
			COALESCE(SUM(size), 0) as total_size,
			COALESCE(SUM(download_count), 0) as total_downloads,
			COALESCE(SUM(CASE WHEN security_scanned = 1 THEN 1 ELSE 0 END), 0) as scanned_packages
		FROM packages
		WHERE version NOT IN ('list', 'latest', 'metadata', 'page')
	`

	args := []interface{}{}
	if registry != "" {
		query += " AND registry = ?"
		args = append(args, registry)
	}

	var stats metadata.Stats
	stats.Registry = registry
	stats.LastUpdated = time.Now()

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&stats.TotalPackages,
		&stats.TotalSize,
		&stats.TotalDownloads,
		&stats.ScannedPackages,
	)

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get stats")
	}

	// Count vulnerable packages
	vulnQuery := `SELECT COUNT(*) FROM scan_results WHERE status = 'vulnerable'`
	vulnArgs := []interface{}{}
	if registry != "" {
		vulnQuery += " AND registry = ?"
		vulnArgs = append(vulnArgs, registry)
	}

	s.db.QueryRowContext(ctx, vulnQuery, vulnArgs...).Scan(&stats.VulnerablePackages)

	return &stats, nil
}

// GetTimeSeriesStats returns time-series download statistics
// Uses different data sources based on period for efficiency:
// - 1h: raw download_events (last hour only)
// - 1day: hourly aggregates
// - 7day, 30day: daily aggregates
func (s *SQLiteStore) GetTimeSeriesStats(ctx context.Context, period string, registry string) (*metadata.TimeSeriesStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		timeFormat    string
		startTime     time.Time
		bucketCount   int
		useRawEvents  bool
		useResolution string
	)

	now := time.Now()

	// Determine time range, bucket size, and data source based on period
	switch period {
	case "1h":
		startTime = now.Add(-1 * time.Hour)
		timeFormat = "%Y-%m-%d %H:%M:00" // 5-minute buckets
		bucketCount = 12 // 12 x 5min = 60min
		useRawEvents = true // Use raw events for last hour
	case "1day":
		startTime = now.Add(-24 * time.Hour)
		timeFormat = "%Y-%m-%d %H:00:00" // hourly buckets
		bucketCount = 24
		useResolution = "hourly" // Use hourly aggregates
	case "7day":
		startTime = now.Add(-7 * 24 * time.Hour)
		timeFormat = "%Y-%m-%d 00:00:00" // daily buckets
		bucketCount = 7
		useResolution = "daily" // Use daily aggregates
	case "30day":
		startTime = now.Add(-30 * 24 * time.Hour)
		timeFormat = "%Y-%m-%d 00:00:00" // daily buckets
		bucketCount = 30
		useResolution = "daily" // Use daily aggregates
	default:
		return nil, errors.New(errors.ErrCodeBadRequest, "invalid period, must be one of: 1h, 1day, 7day, 30day")
	}

	var query string
	var args []interface{}

	if useRawEvents {
		// Query raw download_events for 1h period
		query = `
			SELECT
				strftime(?, downloaded_at) as time_bucket,
				COUNT(*) as download_count
			FROM download_events
			WHERE downloaded_at >= ?
				AND downloaded_at IS NOT NULL
		`
		args = []interface{}{timeFormat, startTime}

		if registry != "" {
			query += " AND registry = ?"
			args = append(args, registry)
		}

		query += `
			GROUP BY time_bucket
			HAVING time_bucket IS NOT NULL
			ORDER BY time_bucket ASC
		`
	} else {
		// Query aggregated_download_stats for longer periods
		query = `
			SELECT
				time_bucket,
				SUM(download_count) as download_count
			FROM aggregated_download_stats
			WHERE resolution = ?
				AND time_bucket >= ?
				AND time_bucket IS NOT NULL
		`
		args = []interface{}{useResolution, startTime}

		if registry != "" {
			query += " AND registry = ?"
			args = append(args, registry)
		}

		query += `
			GROUP BY time_bucket
			ORDER BY time_bucket ASC
		`
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to query time-series stats")
	}
	defer rows.Close()

	// Collect data points
	dataMap := make(map[string]int64)
	for rows.Next() {
		var bucket sql.NullString
		var count int64
		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to scan time-series data")
		}
		// Skip NULL buckets (shouldn't happen with NOT NULL constraint, but defensive)
		if bucket.Valid && bucket.String != "" {
			dataMap[bucket.String] = count
		}
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "error iterating time-series data")
	}

	// Create complete data points array with zeros for missing buckets
	dataPoints := make([]*metadata.TimeSeriesDataPoint, 0, bucketCount)

	// Generate all expected buckets
	currentTime := startTime
	var increment time.Duration
	switch period {
	case "1h":
		increment = 5 * time.Minute
	case "1day":
		increment = time.Hour
	case "7day", "30day":
		increment = 24 * time.Hour
	}

	for i := 0; i < bucketCount; i++ {
		var bucket string
		if useRawEvents {
			bucket = currentTime.Format(convertGoTimeFormat(timeFormat))
		} else {
			// For aggregated data, time_bucket is already in the right format
			bucket = currentTime.Format("2006-01-02 15:04:05")
		}
		count := dataMap[bucket]

		dataPoints = append(dataPoints, &metadata.TimeSeriesDataPoint{
			Timestamp: currentTime,
			Value:     count,
		})

		currentTime = currentTime.Add(increment)
	}

	return &metadata.TimeSeriesStats{
		Period:     period,
		Registry:   registry,
		DataPoints: dataPoints,
	}, nil
}

// convertGoTimeFormat converts SQLite strftime format to Go time format
func convertGoTimeFormat(sqliteFormat string) string {
	// SQLite strftime to Go time.Format mapping
	format := sqliteFormat
	format = strings.ReplaceAll(format, "%Y", "2006")
	format = strings.ReplaceAll(format, "%m", "01")
	format = strings.ReplaceAll(format, "%d", "02")
	format = strings.ReplaceAll(format, "%H", "15")
	format = strings.ReplaceAll(format, "%M", "04")
	format = strings.ReplaceAll(format, "%S", "05")
	return format
}

// AggregateDownloadData aggregates raw download events into hourly/daily buckets and cleans up old data
// This should be called periodically (e.g., every hour) as a background job
func (s *SQLiteStore) AggregateDownloadData(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Info().Msg("Starting download data aggregation")

	// Start transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to start aggregation transaction")
	}
	defer tx.Rollback()

	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)
	oneDayAgo := now.Add(-24 * time.Hour)

	// Step 1: Aggregate raw events older than 1 hour into hourly buckets
	// Group by registry and hour, then insert into aggregated_download_stats
	hourlyAggQuery := `
		INSERT OR REPLACE INTO aggregated_download_stats (registry, time_bucket, resolution, download_count)
		SELECT
			registry,
			strftime('%Y-%m-%d %H:00:00', downloaded_at) as time_bucket,
			'hourly' as resolution,
			COUNT(*) as download_count
		FROM download_events
		WHERE downloaded_at < ?
			AND downloaded_at IS NOT NULL
		GROUP BY registry, time_bucket
		HAVING time_bucket IS NOT NULL
	`
	_, err = tx.ExecContext(ctx, hourlyAggQuery, oneHourAgo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to aggregate hourly data")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to aggregate hourly download data")
	}

	// Step 2: Delete raw events older than 1 hour (they're now aggregated)
	deleteRawQuery := `DELETE FROM download_events WHERE downloaded_at < ?`
	result, err := tx.ExecContext(ctx, deleteRawQuery, oneHourAgo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to delete old raw events")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete old download events")
	}
	rawDeleted, _ := result.RowsAffected()

	// Step 3: Aggregate hourly stats older than 24 hours into daily buckets
	dailyAggQuery := `
		INSERT OR REPLACE INTO aggregated_download_stats (registry, time_bucket, resolution, download_count)
		SELECT
			registry,
			strftime('%Y-%m-%d 00:00:00', time_bucket) as time_bucket,
			'daily' as resolution,
			SUM(download_count) as download_count
		FROM aggregated_download_stats
		WHERE resolution = 'hourly'
			AND time_bucket < ?
			AND time_bucket IS NOT NULL
		GROUP BY registry, strftime('%Y-%m-%d 00:00:00', time_bucket)
		HAVING time_bucket IS NOT NULL
	`
	_, err = tx.ExecContext(ctx, dailyAggQuery, oneDayAgo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to aggregate daily data")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to aggregate daily download data")
	}

	// Step 4: Delete hourly stats older than 24 hours (they're now aggregated into daily)
	deleteHourlyQuery := `DELETE FROM aggregated_download_stats WHERE resolution = 'hourly' AND time_bucket < ?`
	result, err = tx.ExecContext(ctx, deleteHourlyQuery, oneDayAgo)
	if err != nil {
		log.Error().Err(err).Msg("Failed to delete old hourly aggregates")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete old hourly aggregates")
	}
	hourlyDeleted, _ := result.RowsAffected()

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to commit aggregation transaction")
	}

	log.Info().
		Int64("raw_events_deleted", rawDeleted).
		Int64("hourly_aggregates_deleted", hourlyDeleted).
		Msg("Download data aggregation completed successfully")

	return nil
}

// SaveScanResult saves security scan result
func (s *SQLiteStore) SaveScanResult(ctx context.Context, result *metadata.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Serialize vulnerabilities and details
	vulnJSON, err := goccy_json.Marshal(result.Vulnerabilities)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalServer, "failed to serialize vulnerabilities")
	}

	detailsJSON, err := goccy_json.Marshal(result.Details)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalServer, "failed to serialize scan details")
	}

	query := `
		INSERT INTO scan_results (
			id, registry, package_name, package_version, scanner,
			scanned_at, status, vulnerability_count, vulnerabilities, details
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(registry, package_name, package_version, scanner) DO UPDATE SET
			scanned_at = excluded.scanned_at,
			status = excluded.status,
			vulnerability_count = excluded.vulnerability_count,
			vulnerabilities = excluded.vulnerabilities,
			details = excluded.details
	`

	_, err = s.db.ExecContext(ctx, query,
		result.ID, result.Registry, result.PackageName, result.PackageVersion, result.Scanner,
		result.ScannedAt, result.Status, result.VulnerabilityCount,
		string(vulnJSON), string(detailsJSON),
	)

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save scan result")
	}

	// Update package security_scanned flag
	updateQuery := `UPDATE packages SET security_scanned = 1 WHERE registry = ? AND name = ? AND version = ?`
	updateResult, err := s.db.ExecContext(ctx, updateQuery, result.Registry, result.PackageName, result.PackageVersion)
	if err != nil {
		log.Warn().
			Err(err).
			Str("registry", result.Registry).
			Str("package", result.PackageName).
			Str("version", result.PackageVersion).
			Msg("Failed to update security_scanned flag")
		// Don't return error - scan result is already saved
	} else {
		rowsAffected, _ := updateResult.RowsAffected()
		if rowsAffected == 0 {
			log.Warn().
				Str("registry", result.Registry).
				Str("package", result.PackageName).
				Str("version", result.PackageVersion).
				Msg("Package not found when updating security_scanned flag - possibly name mismatch")
		}
	}

	return nil
}

// GetScanResult retrieves security scan result
func (s *SQLiteStore) GetScanResult(ctx context.Context, registry, name, version string) (*metadata.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, registry, package_name, package_version, scanner,
			scanned_at, status, vulnerability_count, vulnerabilities, details
		FROM scan_results
		WHERE registry = ? AND package_name = ? AND package_version = ?
		ORDER BY scanned_at DESC
		LIMIT 1
	`

	var result metadata.ScanResult
	var vulnJSON, detailsJSON string

	err := s.db.QueryRowContext(ctx, query, registry, name, version).Scan(
		&result.ID, &result.Registry, &result.PackageName, &result.PackageVersion, &result.Scanner,
		&result.ScannedAt, &result.Status, &result.VulnerabilityCount,
		&vulnJSON, &detailsJSON,
	)

	if err == sql.ErrNoRows {
		return nil, errors.NotFound(fmt.Sprintf("scan result not found: %s/%s@%s", registry, name, version))
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get scan result")
	}

	// Deserialize
	if vulnJSON != "" {
		goccy_json.Unmarshal([]byte(vulnJSON), &result.Vulnerabilities)
	}

	if detailsJSON != "" {
		goccy_json.Unmarshal([]byte(detailsJSON), &result.Details)
	}

	return &result, nil
}

// Count returns total number of packages
func (s *SQLiteStore) Count(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	query := "SELECT COUNT(*) FROM packages"

	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to count packages")
	}

	return count, nil
}

// Health checks metadata store health
func (s *SQLiteStore) Health(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// SaveCVEBypass saves a CVE bypass (admin only)
func (s *SQLiteStore) SaveCVEBypass(ctx context.Context, bypass *metadata.CVEBypass) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		INSERT INTO cve_bypasses (
			id, type, target, reason, created_by, created_at,
			expires_at, applies_to, notify_on_expiry, active
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			type = excluded.type,
			target = excluded.target,
			reason = excluded.reason,
			expires_at = excluded.expires_at,
			applies_to = excluded.applies_to,
			notify_on_expiry = excluded.notify_on_expiry,
			active = excluded.active
	`

	_, err := s.db.ExecContext(ctx, query,
		bypass.ID, bypass.Type, bypass.Target, bypass.Reason, bypass.CreatedBy,
		bypass.CreatedAt, bypass.ExpiresAt, bypass.AppliesTo,
		bypass.NotifyOnExpiry, bypass.Active,
	)

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save CVE bypass")
	}

	return nil
}

// GetActiveCVEBypasses retrieves all active (non-expired) CVE bypasses
func (s *SQLiteStore) GetActiveCVEBypasses(ctx context.Context) ([]*metadata.CVEBypass, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, type, target, reason, created_by, created_at,
			expires_at, applies_to, notify_on_expiry, active
		FROM cve_bypasses
		WHERE active = 1 AND expires_at > ?
		ORDER BY created_at DESC
	`

	rows, err := s.db.QueryContext(ctx, query, time.Now())
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get active CVE bypasses")
	}
	defer rows.Close()

	var bypasses []*metadata.CVEBypass
	for rows.Next() {
		var bypass metadata.CVEBypass
		var appliesTo sql.NullString

		err := rows.Scan(
			&bypass.ID, &bypass.Type, &bypass.Target, &bypass.Reason, &bypass.CreatedBy,
			&bypass.CreatedAt, &bypass.ExpiresAt, &appliesTo,
			&bypass.NotifyOnExpiry, &bypass.Active,
		)

		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to scan CVE bypass row")
		}

		if appliesTo.Valid {
			bypass.AppliesTo = appliesTo.String
		}

		bypasses = append(bypasses, &bypass)
	}

	return bypasses, nil
}

// ListCVEBypasses lists all CVE bypasses (including expired)
func (s *SQLiteStore) ListCVEBypasses(ctx context.Context, opts *metadata.BypassListOptions) ([]*metadata.CVEBypass, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT id, type, target, reason, created_by, created_at,
			expires_at, applies_to, notify_on_expiry, active
		FROM cve_bypasses
		WHERE 1=1
	`
	args := []interface{}{}

	if opts != nil {
		if opts.Type != "" {
			query += " AND type = ?"
			args = append(args, opts.Type)
		}

		if !opts.IncludeExpired {
			query += " AND expires_at > ?"
			args = append(args, time.Now())
		}

		if opts.ActiveOnly {
			query += " AND active = 1"
		}

		query += " ORDER BY created_at DESC"

		if opts.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, opts.Limit)
		}

		if opts.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, opts.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list CVE bypasses")
	}
	defer rows.Close()

	var bypasses []*metadata.CVEBypass
	for rows.Next() {
		var bypass metadata.CVEBypass
		var appliesTo sql.NullString

		err := rows.Scan(
			&bypass.ID, &bypass.Type, &bypass.Target, &bypass.Reason, &bypass.CreatedBy,
			&bypass.CreatedAt, &bypass.ExpiresAt, &appliesTo,
			&bypass.NotifyOnExpiry, &bypass.Active,
		)

		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to scan CVE bypass row")
		}

		if appliesTo.Valid {
			bypass.AppliesTo = appliesTo.String
		}

		bypasses = append(bypasses, &bypass)
	}

	return bypasses, nil
}

// DeleteCVEBypass deletes a CVE bypass by ID
func (s *SQLiteStore) DeleteCVEBypass(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := "DELETE FROM cve_bypasses WHERE id = ?"
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete CVE bypass")
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.NotFound(fmt.Sprintf("CVE bypass not found: %s", id))
	}

	return nil
}

// CleanupExpiredBypasses removes expired bypasses
func (s *SQLiteStore) CleanupExpiredBypasses(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := "DELETE FROM cve_bypasses WHERE expires_at <= ?"
	result, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to cleanup expired CVE bypasses")
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// Close closes the metadata store
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
