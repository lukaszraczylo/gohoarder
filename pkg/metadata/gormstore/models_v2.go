package gormstore

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// BaseModel provides common fields for all models with audit trail
type BaseModel struct {
	CreatedAt time.Time      `gorm:"not null"`
	UpdatedAt time.Time      `gorm:"not null"`
	DeletedAt gorm.DeletedAt `gorm:"index"` // Soft delete support (auto-generated index name per table)
}

// RegistryModel represents package registries (normalized)
// This eliminates repetition of "npm", "pypi", "go" across millions of rows
type RegistryModel struct {
	ID            int32  `gorm:"primaryKey;autoIncrement"`
	Name          string `gorm:"uniqueIndex:idx_registry_name;not null;size:50"` // npm, pypi, go
	DisplayName   string `gorm:"not null;size:100"`                              // NPM Registry, PyPI, Go Modules
	UpstreamURL   string `gorm:"not null;size:512"`                              // https://registry.npmjs.org
	Enabled       bool   `gorm:"not null;default:true;index:idx_registry_enabled"`
	ScanByDefault bool   `gorm:"not null;default:true"`
	BaseModel
}

func (RegistryModel) TableName() string {
	return "registries"
}

// PackageModel represents the core package data (optimized)
type PackageModel struct {
	ID         int64  `gorm:"primaryKey;autoIncrement"`
	RegistryID int32  `gorm:"not null;index:idx_package_registry_name_version,priority:1"` // Foreign key to registries
	Name       string `gorm:"not null;size:255;index:idx_package_name;index:idx_package_registry_name_version,priority:2"`
	Version    string `gorm:"not null;size:100;index:idx_package_registry_name_version,priority:3"`

	// Storage information
	StorageKey     string `gorm:"not null;uniqueIndex:idx_package_storage_key;size:512"`
	Size           int64  `gorm:"not null;index:idx_package_size"` // For storage quota queries
	ChecksumMD5    string `gorm:"size:32;index:idx_package_md5"`
	ChecksumSHA256 string `gorm:"size:64;index:idx_package_sha256"`
	UpstreamURL    string `gorm:"size:1024"`

	// Cache management
	CachedAt     time.Time  `gorm:"not null;index:idx_package_cached_at"`
	LastAccessed time.Time  `gorm:"not null;index:idx_package_last_accessed"`          // For LRU eviction
	ExpiresAt    *time.Time `gorm:"index:idx_package_expires_at"`                      // For cache invalidation
	AccessCount  int64      `gorm:"not null;default:0;index:idx_package_access_count"` // Total access count (denormalized for performance)

	// Security
	SecurityScanned    bool       `gorm:"not null;default:false;index:idx_package_security_scanned"`
	LastScannedAt      *time.Time `gorm:"index:idx_package_last_scanned"`
	VulnerabilityCount int        `gorm:"not null;default:0;index:idx_package_vuln_count"` // Denormalized for fast filtering
	HighestSeverity    string     `gorm:"size:20;index:idx_package_severity"`              // critical, high, medium, low, none
	CriticalCount      int        `gorm:"not null;default:0"`                              // Count of critical vulnerabilities
	HighCount          int        `gorm:"not null;default:0"`                              // Count of high vulnerabilities
	ModerateCount      int        `gorm:"not null;default:0"`                              // Count of moderate vulnerabilities
	LowCount           int        `gorm:"not null;default:0"`                              // Count of low vulnerabilities

	// Authentication
	RequiresAuth bool   `gorm:"not null;default:false;index:idx_package_requires_auth"`
	AuthProvider string `gorm:"size:50;index:idx_package_auth_provider"` // github, gitlab, custom

	BaseModel

	// Relationships
	Registry        RegistryModel               `gorm:"foreignKey:RegistryID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT"`
	Metadata        *PackageMetadataModel       `gorm:"foreignKey:PackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	ScanResults     []ScanResultModel           `gorm:"foreignKey:PackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Vulnerabilities []PackageVulnerabilityModel `gorm:"foreignKey:PackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (PackageModel) TableName() string {
	return "packages"
}

// BeforeCreate hook to set access count
func (p *PackageModel) BeforeCreate(tx *gorm.DB) error {
	if p.AccessCount == 0 {
		p.AccessCount = 0
	}
	return nil
}

// PackageMetadataModel stores structured package metadata (1:1 with packages)
// Separated from main table to reduce row size and improve query performance
type PackageMetadataModel struct {
	PackageID   int64         `gorm:"primaryKey;not null"` // 1:1 relationship
	Author      string        `gorm:"size:255;index:idx_metadata_author"`
	License     string        `gorm:"size:100;index:idx_metadata_license"`
	Homepage    string        `gorm:"size:512"`
	Repository  string        `gorm:"size:512"`
	Description string        `gorm:"type:text"`
	Keywords    PostgresArray `gorm:"type:text"`  // JSONB array for PostgreSQL, JSON for MySQL/SQLite
	RawMetadata JSONBField    `gorm:"type:jsonb"` // Full metadata as JSONB (PostgreSQL) or JSON
	BaseModel
}

func (PackageMetadataModel) TableName() string {
	return "package_metadata"
}

// ScanResultModel represents security scan results (optimized)
type ScanResultModel struct {
	ID            int64      `gorm:"primaryKey;autoIncrement"`
	PackageID     int64      `gorm:"not null;index:idx_scan_package_scanner,priority:1"` // Foreign key
	Scanner       string     `gorm:"not null;size:50;index:idx_scan_scanner;index:idx_scan_package_scanner,priority:2"`
	ScannedAt     time.Time  `gorm:"not null;index:idx_scan_scanned_at"`
	Status        string     `gorm:"not null;size:20;index:idx_scan_status"` // success, failed, pending
	VulnCount     int        `gorm:"not null;default:0;index:idx_scan_vuln_count"`
	CriticalCount int        `gorm:"not null;default:0"`
	HighCount     int        `gorm:"not null;default:0"`
	MediumCount   int        `gorm:"not null;default:0"`
	LowCount      int        `gorm:"not null;default:0"`
	ScanDuration  int        `gorm:"not null;default:0"` // milliseconds
	Details       JSONBField `gorm:"type:jsonb"`         // Scanner-specific details
	BaseModel

	Package PackageModel `gorm:"foreignKey:PackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (ScanResultModel) TableName() string {
	return "scan_results"
}

// VulnerabilityModel represents unique vulnerabilities (normalized)
type VulnerabilityModel struct {
	ID           int64         `gorm:"primaryKey;autoIncrement"`
	CVEID        string        `gorm:"uniqueIndex:idx_vuln_cve_id;not null;size:50"` // CVE-2021-12345
	Title        string        `gorm:"not null;size:512"`
	Description  string        `gorm:"type:text"`
	Severity     string        `gorm:"not null;size:20;index:idx_vuln_severity"` // critical, high, medium, low
	CVSS         float32       `gorm:"index:idx_vuln_cvss"`                      // CVSS score for sorting
	PublishedAt  time.Time     `gorm:"not null;index:idx_vuln_published"`
	FixedVersion string        `gorm:"size:100"`  // First version where it's fixed
	References   PostgresArray `gorm:"type:text"` // URLs to advisories
	BaseModel
}

func (VulnerabilityModel) TableName() string {
	return "vulnerabilities"
}

// PackageVulnerabilityModel is a many-to-many relationship between packages and vulnerabilities
type PackageVulnerabilityModel struct {
	ID              int64     `gorm:"primaryKey;autoIncrement"`
	PackageID       int64     `gorm:"not null;index:idx_pkg_vuln_package,priority:1;index:idx_pkg_vuln_composite,priority:1"`
	VulnerabilityID int64     `gorm:"not null;index:idx_pkg_vuln_vuln,priority:1;index:idx_pkg_vuln_composite,priority:2"`
	Scanner         string    `gorm:"not null;size:50;index:idx_pkg_vuln_scanner"`
	DetectedAt      time.Time `gorm:"not null;index:idx_pkg_vuln_detected"`
	Bypassed        bool      `gorm:"not null;default:false;index:idx_pkg_vuln_bypassed"`
	BypassID        *int64    `gorm:"index:idx_pkg_vuln_bypass_id"` // Reference to bypass if applicable
	BaseModel

	Package       PackageModel       `gorm:"foreignKey:PackageID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
	Vulnerability VulnerabilityModel `gorm:"foreignKey:VulnerabilityID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (PackageVulnerabilityModel) TableName() string {
	return "package_vulnerabilities"
}

// CVEBypassModel represents CVE bypass rules (improved)
type CVEBypassModel struct {
	ID             int64      `gorm:"primaryKey;autoIncrement"`
	Type           string     `gorm:"not null;size:20;index:idx_bypass_type"`    // cve, package, registry
	Target         string     `gorm:"not null;size:512;index:idx_bypass_target"` // CVE-ID, package name, etc.
	Reason         string     `gorm:"not null;type:text"`
	CreatedBy      string     `gorm:"not null;size:255;index:idx_bypass_created_by"`
	ExpiresAt      time.Time  `gorm:"not null;index:idx_bypass_expires_at"`
	NotifyOnExpiry bool       `gorm:"not null;default:false"`
	Active         bool       `gorm:"not null;default:true;index:idx_bypass_active"`
	UsageCount     int64      `gorm:"not null;default:0"` // How many times this bypass has been used
	LastUsedAt     *time.Time `gorm:"index:idx_bypass_last_used"`

	// Scope limiting (optional)
	RegistryID *int32 `gorm:"index:idx_bypass_registry"` // NULL = all registries
	PackageID  *int64 `gorm:"index:idx_bypass_package"`  // NULL = all packages

	BaseModel
}

func (CVEBypassModel) TableName() string {
	return "cve_bypasses"
}

// DownloadEventModel represents raw download events (partitioned by month)
// This table should use PostgreSQL partitioning or time-series DB features
type DownloadEventModel struct {
	ID            int64     `gorm:"primaryKey;autoIncrement"`
	PackageID     int64     `gorm:"not null;index:idx_download_package,priority:1"`
	RegistryID    int32     `gorm:"not null;index:idx_download_registry"`
	DownloadedAt  time.Time `gorm:"not null;index:idx_download_time;index:idx_download_package,priority:2"` // Partition key
	UserAgent     string    `gorm:"size:512"`                                                               // For analytics
	IPAddress     string    `gorm:"size:45;index:idx_download_ip"`                                          // IPv6 support
	Authenticated bool      `gorm:"not null;default:false"`
	Username      string    `gorm:"size:255;index:idx_download_user"`

	// No BaseModel - this is append-only, no updates/deletes on individual rows
	// Partitioned tables handle cleanup via DROP PARTITION
}

func (DownloadEventModel) TableName() string {
	return "download_events"
}

// DownloadStatsHourlyModel represents pre-aggregated hourly statistics (partitioned)
type DownloadStatsHourlyModel struct {
	ID            int64     `gorm:"primaryKey;autoIncrement"`
	RegistryID    int32     `gorm:"not null;index:idx_stats_hourly_composite,priority:1"`
	PackageID     *int64    `gorm:"index:idx_stats_hourly_package"`                       // NULL = all packages in registry
	TimeBucket    time.Time `gorm:"not null;index:idx_stats_hourly_composite,priority:2"` // Truncated to hour
	DownloadCount int64     `gorm:"not null;default:0"`
	UniqueIPs     int64     `gorm:"not null;default:0"` // Unique downloaders
	AuthDownloads int64     `gorm:"not null;default:0"` // Authenticated downloads

	BaseModel
}

func (DownloadStatsHourlyModel) TableName() string {
	return "download_stats_hourly"
}

// DownloadStatsDailyModel represents pre-aggregated daily statistics
type DownloadStatsDailyModel struct {
	ID            int64      `gorm:"primaryKey;autoIncrement"`
	RegistryID    int32      `gorm:"not null;index:idx_stats_daily_composite,priority:1"`
	PackageID     *int64     `gorm:"index:idx_stats_daily_package"`                       // NULL = all packages in registry
	TimeBucket    time.Time  `gorm:"not null;index:idx_stats_daily_composite,priority:2"` // Truncated to day
	DownloadCount int64      `gorm:"not null;default:0"`
	UniqueIPs     int64      `gorm:"not null;default:0"`
	AuthDownloads int64      `gorm:"not null;default:0"`
	TopUserAgents JSONBField `gorm:"type:jsonb"` // Top 10 user agents

	BaseModel
}

func (DownloadStatsDailyModel) TableName() string {
	return "download_stats_daily"
}

// AuditLogModel tracks all important changes (optional, for compliance)
type AuditLogModel struct {
	ID         int64      `gorm:"primaryKey;autoIncrement"`
	EntityType string     `gorm:"not null;size:50;index:idx_audit_entity_type"` // package, bypass, registry
	EntityID   int64      `gorm:"not null;index:idx_audit_entity_id"`
	Action     string     `gorm:"not null;size:20;index:idx_audit_action"` // create, update, delete
	Username   string     `gorm:"not null;size:255;index:idx_audit_username"`
	Timestamp  time.Time  `gorm:"not null;index:idx_audit_timestamp"`
	Changes    JSONBField `gorm:"type:jsonb"` // Before/after values
	IPAddress  string     `gorm:"size:45"`
	UserAgent  string     `gorm:"size:512"`

	// No BaseModel - append-only audit log
}

func (AuditLogModel) TableName() string {
	return "audit_log"
}

// JSONBField is a custom type for JSONB (PostgreSQL) / JSON (MySQL/SQLite)
type JSONBField map[string]interface{}

func (j JSONBField) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

func (j *JSONBField) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, j)
}

// PostgresArray is a custom type for PostgreSQL arrays stored as JSON
type PostgresArray []string

func (a PostgresArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
}

func (a *PostgresArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, a)
}

// GetAllModels returns all models for GORM auto-migration
func GetAllModels() []interface{} {
	return []interface{}{
		&RegistryModel{},
		&PackageModel{},
		&PackageMetadataModel{},
		&ScanResultModel{},
		&VulnerabilityModel{},
		&PackageVulnerabilityModel{},
		&CVEBypassModel{},
		&DownloadEventModel{},
		&DownloadStatsHourlyModel{},
		&DownloadStatsDailyModel{},
		&AuditLogModel{},
	}
}
