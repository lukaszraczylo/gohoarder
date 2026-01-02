package sqlite

import (
	"context"
	"database/sql"
	"fmt"
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

	return &SQLiteStore{
		db: db,
	}, nil
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
			metadata, security_scanned
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(registry, name, version) DO UPDATE SET
			storage_key = excluded.storage_key,
			size = excluded.size,
			checksum_md5 = excluded.checksum_md5,
			checksum_sha256 = excluded.checksum_sha256,
			upstream_url = excluded.upstream_url,
			last_accessed = excluded.last_accessed,
			expires_at = excluded.expires_at,
			metadata = excluded.metadata,
			security_scanned = excluded.security_scanned
	`

	_, err = s.db.ExecContext(ctx, query,
		pkg.ID, pkg.Registry, pkg.Name, pkg.Version, pkg.StorageKey, pkg.Size,
		pkg.ChecksumMD5, pkg.ChecksumSHA256, pkg.UpstreamURL,
		pkg.CachedAt, pkg.LastAccessed, expiresAt, pkg.DownloadCount,
		string(metadataJSON), pkg.SecurityScanned,
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
			metadata, security_scanned
		FROM packages
		WHERE registry = ? AND name = ? AND version = ?
	`

	var pkg metadata.Package
	var metadataJSON string
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, registry, name, version).Scan(
		&pkg.ID, &pkg.Registry, &pkg.Name, &pkg.Version, &pkg.StorageKey, &pkg.Size,
		&pkg.ChecksumMD5, &pkg.ChecksumSHA256, &pkg.UpstreamURL,
		&pkg.CachedAt, &pkg.LastAccessed, &expiresAt, &pkg.DownloadCount,
		&metadataJSON, &pkg.SecurityScanned,
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

// UpdateDownloadCount increments download counter
func (s *SQLiteStore) UpdateDownloadCount(ctx context.Context, registry, name, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
		UPDATE packages
		SET download_count = download_count + 1,
			last_accessed = ?
		WHERE registry = ? AND name = ? AND version = ?
	`

	_, err := s.db.ExecContext(ctx, query, time.Now(), registry, name, version)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to update download count")
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
	`

	args := []interface{}{}
	if registry != "" {
		query += " WHERE registry = ?"
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
