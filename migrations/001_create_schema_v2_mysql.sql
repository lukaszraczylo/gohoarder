-- GoHoarder Database Schema V2 - MySQL/MariaDB
-- Optimized for multi-user production deployments
-- Created: 2026-01-03
-- Requires: MySQL 8.0+ or MariaDB 10.5+

-- Set charset and collation
SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- ============================================================================
-- TABLE: registries
-- Purpose: Normalized registry data (eliminates repeated strings)
-- ============================================================================

CREATE TABLE IF NOT EXISTS registries (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(50) UNIQUE NOT NULL,
    display_name    VARCHAR(100) NOT NULL,
    upstream_url    VARCHAR(512) NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    scan_by_default BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at      TIMESTAMP NULL,

    INDEX idx_registry_name (name),
    INDEX idx_registry_enabled (enabled, deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: packages
-- Purpose: Core package metadata with denormalized counts for performance
-- ============================================================================

CREATE TABLE IF NOT EXISTS packages (
    id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    registry_id         INT UNSIGNED NOT NULL,
    name                VARCHAR(255) NOT NULL,
    version             VARCHAR(100) NOT NULL,

    -- Storage information
    storage_key         VARCHAR(512) UNIQUE NOT NULL,
    size                BIGINT NOT NULL,
    checksum_md5        CHAR(32),
    checksum_sha256     CHAR(64),
    upstream_url        VARCHAR(1024),

    -- Cache management
    cached_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP NULL,
    access_count        BIGINT NOT NULL DEFAULT 0,

    -- Security (denormalized for performance)
    security_scanned    BOOLEAN NOT NULL DEFAULT FALSE,
    last_scanned_at     TIMESTAMP NULL,
    vulnerability_count INT NOT NULL DEFAULT 0,
    highest_severity    VARCHAR(20),

    -- Authentication
    requires_auth       BOOLEAN NOT NULL DEFAULT FALSE,
    auth_provider       VARCHAR(50),

    -- Audit trail
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMP NULL,

    FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE RESTRICT ON UPDATE CASCADE,

    UNIQUE INDEX idx_package_registry_name_version (registry_id, name, version, deleted_at),
    INDEX idx_package_storage_key (storage_key),
    INDEX idx_package_name (name(50)),
    INDEX idx_package_last_accessed (last_accessed DESC),
    INDEX idx_package_expires_at (expires_at),
    INDEX idx_package_access_count (access_count DESC),
    INDEX idx_package_size (size DESC),
    INDEX idx_package_vuln_count (vulnerability_count),
    INDEX idx_package_severity (highest_severity),
    INDEX idx_package_security_scanned (security_scanned, deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: package_metadata
-- Purpose: Structured metadata (1:1 with packages)
-- ============================================================================

CREATE TABLE IF NOT EXISTS package_metadata (
    package_id  BIGINT UNSIGNED PRIMARY KEY,
    author      VARCHAR(255),
    license     VARCHAR(100),
    homepage    VARCHAR(512),
    repository  VARCHAR(512),
    description TEXT,
    keywords    JSON,       -- JSON array for MySQL 8.0+
    raw_metadata JSON,      -- Full metadata as JSON
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMP NULL,

    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE ON UPDATE CASCADE,

    INDEX idx_metadata_author (author(100)),
    INDEX idx_metadata_license (license)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: vulnerabilities
-- Purpose: Normalized vulnerability data (each CVE stored once)
-- ============================================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    cve_id        VARCHAR(50) UNIQUE NOT NULL,
    title         VARCHAR(512) NOT NULL,
    description   TEXT,
    severity      VARCHAR(20) NOT NULL,
    cvss          FLOAT,
    published_at  TIMESTAMP NOT NULL,
    fixed_version VARCHAR(100),
    references    JSON,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at    TIMESTAMP NULL,

    UNIQUE INDEX idx_vuln_cve_id (cve_id),
    INDEX idx_vuln_severity (severity),
    INDEX idx_vuln_cvss (cvss DESC),
    INDEX idx_vuln_published (published_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: package_vulnerabilities
-- Purpose: Many-to-many relationship between packages and vulnerabilities
-- ============================================================================

CREATE TABLE IF NOT EXISTS package_vulnerabilities (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    package_id        BIGINT UNSIGNED NOT NULL,
    vulnerability_id  BIGINT UNSIGNED NOT NULL,
    scanner           VARCHAR(50) NOT NULL,
    detected_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    bypassed          BOOLEAN NOT NULL DEFAULT FALSE,
    bypass_id         BIGINT UNSIGNED,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at        TIMESTAMP NULL,

    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE ON UPDATE CASCADE,

    INDEX idx_pkg_vuln_package (package_id, deleted_at),
    INDEX idx_pkg_vuln_vuln (vulnerability_id, deleted_at),
    INDEX idx_pkg_vuln_composite (package_id, vulnerability_id, deleted_at),
    INDEX idx_pkg_vuln_scanner (scanner),
    INDEX idx_pkg_vuln_bypassed (bypassed)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: scan_results
-- Purpose: Security scan results with severity breakdown
-- ============================================================================

CREATE TABLE IF NOT EXISTS scan_results (
    id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    package_id     BIGINT UNSIGNED NOT NULL,
    scanner        VARCHAR(50) NOT NULL,
    scanned_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status         VARCHAR(20) NOT NULL,
    vuln_count     INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count     INT NOT NULL DEFAULT 0,
    medium_count   INT NOT NULL DEFAULT 0,
    low_count      INT NOT NULL DEFAULT 0,
    scan_duration  INT NOT NULL DEFAULT 0,
    details        JSON,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at     TIMESTAMP NULL,

    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE ON UPDATE CASCADE,

    INDEX idx_scan_package_scanner (package_id, scanner, deleted_at),
    INDEX idx_scan_scanned_at (scanned_at DESC),
    INDEX idx_scan_status (status),
    INDEX idx_scan_vuln_count (vuln_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: cve_bypasses
-- Purpose: CVE bypass rules with usage tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS cve_bypasses (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    type             VARCHAR(20) NOT NULL,
    target           VARCHAR(512) NOT NULL,
    reason           TEXT NOT NULL,
    created_by       VARCHAR(255) NOT NULL,
    expires_at       TIMESTAMP NOT NULL,
    notify_on_expiry BOOLEAN NOT NULL DEFAULT FALSE,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    usage_count      BIGINT NOT NULL DEFAULT 0,
    last_used_at     TIMESTAMP NULL,
    registry_id      INT UNSIGNED,
    package_id       BIGINT UNSIGNED,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at       TIMESTAMP NULL,

    FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE SET NULL ON UPDATE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE SET NULL ON UPDATE CASCADE,

    INDEX idx_bypass_type (type),
    INDEX idx_bypass_target (target(100)),
    INDEX idx_bypass_active (active, deleted_at),
    INDEX idx_bypass_expires_at (expires_at, active),
    INDEX idx_bypass_created_by (created_by(100))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: download_events
-- Purpose: High-volume time-series data
-- Note: MySQL doesn't support native partitioning as elegantly as PostgreSQL
-- Consider manual partitioning or TimescaleDB if needed
-- ============================================================================

CREATE TABLE IF NOT EXISTS download_events (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    package_id    BIGINT UNSIGNED NOT NULL,
    registry_id   INT UNSIGNED NOT NULL,
    downloaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent    VARCHAR(512),
    ip_address    VARCHAR(45),
    authenticated BOOLEAN NOT NULL DEFAULT FALSE,
    username      VARCHAR(255),

    INDEX idx_download_events_package (package_id, downloaded_at),
    INDEX idx_download_events_registry (registry_id),
    INDEX idx_download_events_time (downloaded_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: download_stats_hourly
-- Purpose: Pre-aggregated hourly statistics
-- ============================================================================

CREATE TABLE IF NOT EXISTS download_stats_hourly (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    registry_id     INT UNSIGNED NOT NULL,
    package_id      BIGINT UNSIGNED,
    time_bucket     TIMESTAMP NOT NULL,
    download_count  BIGINT NOT NULL DEFAULT 0,
    unique_ips      BIGINT NOT NULL DEFAULT 0,
    auth_downloads  BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE ON UPDATE CASCADE,

    UNIQUE INDEX idx_stats_hourly_composite (registry_id, IFNULL(package_id, 0), time_bucket),
    INDEX idx_stats_hourly_time (time_bucket DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: download_stats_daily
-- Purpose: Pre-aggregated daily statistics
-- ============================================================================

CREATE TABLE IF NOT EXISTS download_stats_daily (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    registry_id     INT UNSIGNED NOT NULL,
    package_id      BIGINT UNSIGNED,
    time_bucket     TIMESTAMP NOT NULL,
    download_count  BIGINT NOT NULL DEFAULT 0,
    unique_ips      BIGINT NOT NULL DEFAULT 0,
    auth_downloads  BIGINT NOT NULL DEFAULT 0,
    top_user_agents JSON,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (registry_id) REFERENCES registries(id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE CASCADE ON UPDATE CASCADE,

    UNIQUE INDEX idx_stats_daily_composite (registry_id, IFNULL(package_id, 0), time_bucket),
    INDEX idx_stats_daily_time (time_bucket DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABLE: audit_log
-- Purpose: Audit trail for compliance
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_id   BIGINT NOT NULL,
    action      VARCHAR(20) NOT NULL,
    username    VARCHAR(255) NOT NULL,
    timestamp   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    changes     JSON,
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(512),

    INDEX idx_audit_log_entity (entity_type, entity_id),
    INDEX idx_audit_log_username (username(100)),
    INDEX idx_audit_log_timestamp (timestamp DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SEED DATA: Default registries
-- ============================================================================

INSERT INTO registries (name, display_name, upstream_url, enabled, scan_by_default) VALUES
    ('npm', 'NPM Registry', 'https://registry.npmjs.org', TRUE, TRUE),
    ('pypi', 'PyPI', 'https://pypi.org', TRUE, TRUE),
    ('go', 'Go Modules', 'https://proxy.golang.org', TRUE, TRUE)
ON DUPLICATE KEY UPDATE
    display_name = VALUES(display_name),
    upstream_url = VALUES(upstream_url);

-- ============================================================================
-- VIEWS: Convenience views for common queries
-- ============================================================================

CREATE OR REPLACE VIEW v_vulnerable_packages AS
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
    p.vulnerability_count DESC;

-- ============================================================================
-- PERFORMANCE TUNING RECOMMENDATIONS
-- ============================================================================

-- Set InnoDB buffer pool size to 50-70% of RAM
-- SET GLOBAL innodb_buffer_pool_size = 4294967296; -- 4GB

-- Enable query cache (MySQL 5.7 and earlier)
-- SET GLOBAL query_cache_type = 1;
-- SET GLOBAL query_cache_size = 67108864; -- 64MB

-- Optimize for SSD
-- SET GLOBAL innodb_flush_log_at_trx_commit = 2;
-- SET GLOBAL innodb_io_capacity = 2000;

-- ============================================================================
-- COMPLETE
-- ============================================================================

SELECT 'Schema V2 created successfully for MySQL/MariaDB!' AS status;
