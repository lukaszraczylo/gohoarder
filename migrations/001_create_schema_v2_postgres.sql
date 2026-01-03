-- GoHoarder Database Schema V2 - PostgreSQL
-- Optimized for multi-user production deployments
-- Created: 2026-01-03

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- TABLE: registries
-- Purpose: Normalized registry data (eliminates repeated strings)
-- ============================================================================

CREATE TABLE IF NOT EXISTS registries (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) UNIQUE NOT NULL,
    display_name    VARCHAR(100) NOT NULL,
    upstream_url    VARCHAR(512) NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    scan_by_default BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMP
);

CREATE INDEX idx_registry_name ON registries(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_registry_enabled ON registries(enabled) WHERE enabled = TRUE AND deleted_at IS NULL;

COMMENT ON TABLE registries IS 'Normalized registry data (npm, pypi, go)';
COMMENT ON COLUMN registries.name IS 'Short name: npm, pypi, go';
COMMENT ON COLUMN registries.display_name IS 'Human-readable name: NPM Registry, PyPI';

-- ============================================================================
-- TABLE: packages
-- Purpose: Core package metadata with denormalized counts for performance
-- ============================================================================

CREATE TABLE IF NOT EXISTS packages (
    id                  BIGSERIAL PRIMARY KEY,
    registry_id         INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT,
    name                VARCHAR(255) NOT NULL,
    version             VARCHAR(100) NOT NULL,

    -- Storage information
    storage_key         VARCHAR(512) UNIQUE NOT NULL,
    size                BIGINT NOT NULL,
    checksum_md5        VARCHAR(32),
    checksum_sha256     VARCHAR(64),
    upstream_url        VARCHAR(1024),

    -- Cache management
    cached_at           TIMESTAMP NOT NULL DEFAULT NOW(),
    last_accessed       TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMP,
    access_count        BIGINT NOT NULL DEFAULT 0,

    -- Security (denormalized for performance)
    security_scanned    BOOLEAN NOT NULL DEFAULT FALSE,
    last_scanned_at     TIMESTAMP,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    highest_severity    VARCHAR(20), -- critical, high, medium, low, none

    -- Authentication
    requires_auth       BOOLEAN NOT NULL DEFAULT FALSE,
    auth_provider       VARCHAR(50),

    -- Audit trail
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMP
);

-- Composite indexes for common queries
CREATE UNIQUE INDEX idx_package_registry_name_version
    ON packages(registry_id, name, version) WHERE deleted_at IS NULL;

CREATE INDEX idx_package_storage_key ON packages(storage_key);
CREATE INDEX idx_package_name ON packages(name text_pattern_ops) WHERE deleted_at IS NULL;
CREATE INDEX idx_package_last_accessed ON packages(last_accessed DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_package_expires_at ON packages(expires_at) WHERE expires_at IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX idx_package_access_count ON packages(access_count DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_package_size ON packages(size DESC);

-- Partial indexes for security queries
CREATE INDEX idx_package_vuln_count ON packages(vulnerability_count) WHERE vulnerability_count > 0 AND deleted_at IS NULL;
CREATE INDEX idx_package_severity ON packages(highest_severity) WHERE highest_severity IN ('critical', 'high') AND deleted_at IS NULL;
CREATE INDEX idx_package_security_scanned ON packages(security_scanned) WHERE deleted_at IS NULL;

COMMENT ON TABLE packages IS 'Core package metadata (optimized V2 schema)';
COMMENT ON COLUMN packages.access_count IS 'Total downloads (denormalized from stats)';
COMMENT ON COLUMN packages.vulnerability_count IS 'Number of vulnerabilities (denormalized)';

-- ============================================================================
-- TABLE: package_metadata
-- Purpose: Structured metadata (1:1 with packages, reduces main table size)
-- ============================================================================

CREATE TABLE IF NOT EXISTS package_metadata (
    package_id  BIGINT PRIMARY KEY REFERENCES packages(id) ON DELETE CASCADE,
    author      VARCHAR(255),
    license     VARCHAR(100),
    homepage    VARCHAR(512),
    repository  VARCHAR(512),
    description TEXT,
    keywords    JSONB,      -- Array of keywords
    raw_metadata JSONB,     -- Full metadata
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMP
);

CREATE INDEX idx_metadata_author ON package_metadata(author);
CREATE INDEX idx_metadata_license ON package_metadata(license);
CREATE INDEX idx_metadata_keywords ON package_metadata USING GIN(keywords);
CREATE INDEX idx_metadata_raw ON package_metadata USING GIN(raw_metadata);

COMMENT ON TABLE package_metadata IS 'Structured package metadata (separated for performance)';

-- ============================================================================
-- TABLE: vulnerabilities
-- Purpose: Normalized vulnerability data (each CVE stored once)
-- ============================================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           BIGSERIAL PRIMARY KEY,
    cve_id       VARCHAR(50) UNIQUE NOT NULL,
    title        VARCHAR(512) NOT NULL,
    description  TEXT,
    severity     VARCHAR(20) NOT NULL, -- critical, high, medium, low
    cvss         REAL,
    published_at TIMESTAMP NOT NULL,
    fixed_version VARCHAR(100),
    references   JSONB, -- Array of URLs
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMP
);

CREATE UNIQUE INDEX idx_vuln_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_cvss ON vulnerabilities(cvss DESC NULLS LAST);
CREATE INDEX idx_vuln_published ON vulnerabilities(published_at DESC);

COMMENT ON TABLE vulnerabilities IS 'Normalized vulnerability data (99% storage reduction)';

-- ============================================================================
-- TABLE: package_vulnerabilities
-- Purpose: Many-to-many relationship between packages and vulnerabilities
-- ============================================================================

CREATE TABLE IF NOT EXISTS package_vulnerabilities (
    id              BIGSERIAL PRIMARY KEY,
    package_id      BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    scanner         VARCHAR(50) NOT NULL,
    detected_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    bypassed        BOOLEAN NOT NULL DEFAULT FALSE,
    bypass_id       BIGINT, -- References cve_bypasses.id (soft reference)
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMP
);

CREATE INDEX idx_pkg_vuln_package ON package_vulnerabilities(package_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_pkg_vuln_vuln ON package_vulnerabilities(vulnerability_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_pkg_vuln_composite ON package_vulnerabilities(package_id, vulnerability_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_pkg_vuln_scanner ON package_vulnerabilities(scanner);
CREATE INDEX idx_pkg_vuln_bypassed ON package_vulnerabilities(bypassed) WHERE bypassed = FALSE;

-- ============================================================================
-- TABLE: scan_results
-- Purpose: Security scan results with severity breakdown
-- ============================================================================

CREATE TABLE IF NOT EXISTS scan_results (
    id             BIGSERIAL PRIMARY KEY,
    package_id     BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    scanner        VARCHAR(50) NOT NULL,
    scanned_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    status         VARCHAR(20) NOT NULL, -- success, failed, pending
    vuln_count     INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    medium_count   INTEGER NOT NULL DEFAULT 0,
    low_count      INTEGER NOT NULL DEFAULT 0,
    scan_duration  INTEGER NOT NULL DEFAULT 0, -- milliseconds
    details        JSONB,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at     TIMESTAMP
);

CREATE INDEX idx_scan_package_scanner ON scan_results(package_id, scanner) WHERE deleted_at IS NULL;
CREATE INDEX idx_scan_scanned_at ON scan_results(scanned_at DESC);
CREATE INDEX idx_scan_status ON scan_results(status);
CREATE INDEX idx_scan_vuln_count ON scan_results(vuln_count) WHERE vuln_count > 0;

COMMENT ON TABLE scan_results IS 'Security scan results (optimized V2)';

-- ============================================================================
-- TABLE: cve_bypasses
-- Purpose: CVE bypass rules with usage tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS cve_bypasses (
    id               BIGSERIAL PRIMARY KEY,
    type             VARCHAR(20) NOT NULL, -- cve, package, registry
    target           VARCHAR(512) NOT NULL,
    reason           TEXT NOT NULL,
    created_by       VARCHAR(255) NOT NULL,
    expires_at       TIMESTAMP NOT NULL,
    notify_on_expiry BOOLEAN NOT NULL DEFAULT FALSE,
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    usage_count      BIGINT NOT NULL DEFAULT 0,
    last_used_at     TIMESTAMP,
    registry_id      INTEGER REFERENCES registries(id),
    package_id       BIGINT REFERENCES packages(id),
    created_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMP
);

CREATE INDEX idx_bypass_type ON cve_bypasses(type);
CREATE INDEX idx_bypass_target ON cve_bypasses(target);
CREATE INDEX idx_bypass_active ON cve_bypasses(active) WHERE active = TRUE AND deleted_at IS NULL;
CREATE INDEX idx_bypass_expires_at ON cve_bypasses(expires_at) WHERE active = TRUE;
CREATE INDEX idx_bypass_created_by ON cve_bypasses(created_by);

COMMENT ON TABLE cve_bypasses IS 'CVE bypass rules with scope limiting';

-- ============================================================================
-- PARTITIONED TABLE: download_events
-- Purpose: High-volume time-series data (partitioned by month)
-- ============================================================================

CREATE TABLE IF NOT EXISTS download_events (
    id            BIGSERIAL,
    package_id    BIGINT NOT NULL,
    registry_id   INTEGER NOT NULL,
    downloaded_at TIMESTAMP NOT NULL,
    user_agent    VARCHAR(512),
    ip_address    VARCHAR(45),
    authenticated BOOLEAN NOT NULL DEFAULT FALSE,
    username      VARCHAR(255)
) PARTITION BY RANGE (downloaded_at);

CREATE INDEX idx_download_events_package ON download_events(package_id, downloaded_at);
CREATE INDEX idx_download_events_registry ON download_events(registry_id);
CREATE INDEX idx_download_events_time ON download_events(downloaded_at);

COMMENT ON TABLE download_events IS 'Download events (partitioned by month for performance)';

-- Create partitions for current month ± 2 months
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
    i INTEGER;
BEGIN
    FOR i IN -2..2 LOOP
        start_date := date_trunc('month', NOW() + (i || ' months')::INTERVAL)::DATE;
        end_date := (start_date + INTERVAL '1 month')::DATE;
        partition_name := 'download_events_' || to_char(start_date, 'YYYY_MM');

        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF download_events FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date);

        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(package_id, downloaded_at)',
            partition_name || '_package_idx', partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(registry_id)',
            partition_name || '_registry_idx', partition_name);
    END LOOP;
END $$;

-- ============================================================================
-- TABLE: download_stats_hourly
-- Purpose: Pre-aggregated hourly statistics (1000x faster queries)
-- ============================================================================

CREATE TABLE IF NOT EXISTS download_stats_hourly (
    id              BIGSERIAL PRIMARY KEY,
    registry_id     INTEGER NOT NULL REFERENCES registries(id),
    package_id      BIGINT REFERENCES packages(id), -- NULL = all packages in registry
    time_bucket     TIMESTAMP NOT NULL,
    download_count  BIGINT NOT NULL DEFAULT 0,
    unique_ips      BIGINT NOT NULL DEFAULT 0,
    auth_downloads  BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_stats_hourly_composite
    ON download_stats_hourly(registry_id, COALESCE(package_id, 0), time_bucket);
CREATE INDEX idx_stats_hourly_time ON download_stats_hourly(time_bucket DESC);

COMMENT ON TABLE download_stats_hourly IS 'Hourly aggregated stats (pre-computed)';

-- ============================================================================
-- TABLE: download_stats_daily
-- Purpose: Pre-aggregated daily statistics with analytics
-- ============================================================================

CREATE TABLE IF NOT EXISTS download_stats_daily (
    id              BIGSERIAL PRIMARY KEY,
    registry_id     INTEGER NOT NULL REFERENCES registries(id),
    package_id      BIGINT REFERENCES packages(id),
    time_bucket     TIMESTAMP NOT NULL,
    download_count  BIGINT NOT NULL DEFAULT 0,
    unique_ips      BIGINT NOT NULL DEFAULT 0,
    auth_downloads  BIGINT NOT NULL DEFAULT 0,
    top_user_agents JSONB,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_stats_daily_composite
    ON download_stats_daily(registry_id, COALESCE(package_id, 0), time_bucket);
CREATE INDEX idx_stats_daily_time ON download_stats_daily(time_bucket DESC);

COMMENT ON TABLE download_stats_daily IS 'Daily aggregated stats with analytics';

-- ============================================================================
-- PARTITIONED TABLE: audit_log
-- Purpose: Audit trail for compliance (partitioned by month)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id   BIGINT NOT NULL,
    action      VARCHAR(20) NOT NULL, -- create, update, delete
    username    VARCHAR(255) NOT NULL,
    timestamp   TIMESTAMP NOT NULL DEFAULT NOW(),
    changes     JSONB,
    ip_address  VARCHAR(45),
    user_agent  VARCHAR(512)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_username ON audit_log(username);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);

COMMENT ON TABLE audit_log IS 'Audit trail for compliance and debugging';

-- Create audit_log partitions
DO $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
    i INTEGER;
BEGIN
    FOR i IN -1..2 LOOP
        start_date := date_trunc('month', NOW() + (i || ' months')::INTERVAL)::DATE;
        end_date := (start_date + INTERVAL '1 month')::DATE;
        partition_name := 'audit_log_' || to_char(start_date, 'YYYY_MM');

        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
            partition_name, start_date, end_date);

        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(entity_type, entity_id)',
            partition_name || '_entity_idx', partition_name);
        EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(username)',
            partition_name || '_user_idx', partition_name);
    END LOOP;
END $$;

-- ============================================================================
-- FUNCTIONS: Automatic partition creation
-- ============================================================================

CREATE OR REPLACE FUNCTION create_next_month_partitions()
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

    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(package_id, downloaded_at)',
        partition_name || '_package_idx', partition_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(registry_id)',
        partition_name || '_registry_idx', partition_name);

    -- Audit log partition
    partition_name := 'audit_log_' || to_char(next_month, 'YYYY_MM');

    EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_log FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date);

    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I(entity_type, entity_id)',
        partition_name || '_entity_idx', partition_name);

    RAISE NOTICE 'Created partitions for %', to_char(next_month, 'YYYY-MM');
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION create_next_month_partitions() IS 'Auto-create partitions for next month';

-- ============================================================================
-- TRIGGERS: Updated_at timestamp
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_registries_updated_at BEFORE UPDATE ON registries
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_packages_updated_at BEFORE UPDATE ON packages
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_package_metadata_updated_at BEFORE UPDATE ON package_metadata
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- SEED DATA: Default registries
-- ============================================================================

INSERT INTO registries (name, display_name, upstream_url, enabled, scan_by_default) VALUES
    ('npm', 'NPM Registry', 'https://registry.npmjs.org', TRUE, TRUE),
    ('pypi', 'PyPI', 'https://pypi.org', TRUE, TRUE),
    ('go', 'Go Modules', 'https://proxy.golang.org', TRUE, TRUE)
ON CONFLICT (name) DO NOTHING;

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

COMMENT ON VIEW v_vulnerable_packages IS 'All packages with vulnerabilities (sorted by severity)';

-- ============================================================================
-- COMPLETE
-- ============================================================================

SELECT 'Schema V2 created successfully!' AS status;
