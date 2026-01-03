package metadata

import (
	"context"
	"strings"
	"time"
)

// Store is an alias for MetadataStore for convenience
type Store = MetadataStore

// MetadataStore defines the interface for package metadata storage
type MetadataStore interface {
	// SavePackage saves package metadata
	SavePackage(ctx context.Context, pkg *Package) error

	// GetPackage retrieves package metadata
	GetPackage(ctx context.Context, registry, name, version string) (*Package, error)

	// DeletePackage deletes package metadata
	DeletePackage(ctx context.Context, registry, name, version string) error

	// ListPackages lists packages with optional filtering
	ListPackages(ctx context.Context, opts *ListOptions) ([]*Package, error)

	// UpdateDownloadCount increments download counter
	UpdateDownloadCount(ctx context.Context, registry, name, version string) error

	// GetStats returns statistics
	GetStats(ctx context.Context, registry string) (*Stats, error)

	// SaveScanResult saves security scan result
	SaveScanResult(ctx context.Context, result *ScanResult) error

	// GetScanResult retrieves security scan result
	GetScanResult(ctx context.Context, registry, name, version string) (*ScanResult, error)

	// SaveCVEBypass saves a CVE bypass (admin only)
	SaveCVEBypass(ctx context.Context, bypass *CVEBypass) error

	// GetActiveCVEBypasses retrieves all active (non-expired) CVE bypasses
	GetActiveCVEBypasses(ctx context.Context) ([]*CVEBypass, error)

	// ListCVEBypasses lists all CVE bypasses (including expired)
	ListCVEBypasses(ctx context.Context, opts *BypassListOptions) ([]*CVEBypass, error)

	// DeleteCVEBypass deletes a CVE bypass by ID
	DeleteCVEBypass(ctx context.Context, id string) error

	// CleanupExpiredBypasses removes expired bypasses
	CleanupExpiredBypasses(ctx context.Context) (int, error)

	// Count returns total number of packages
	Count(ctx context.Context) (int, error)

	// Health checks metadata store health
	Health(ctx context.Context) error

	// GetTimeSeriesStats returns time-series download statistics
	GetTimeSeriesStats(ctx context.Context, period string, registry string) (*TimeSeriesStats, error)

	// AggregateDownloadData aggregates raw download events and cleans up old data
	AggregateDownloadData(ctx context.Context) error

	// Close closes the metadata store
	Close() error
}

// Package represents package metadata
type Package struct {
	CachedAt        time.Time         `json:"cached_at"`
	LastAccessed    time.Time         `json:"last_accessed"`
	Metadata        map[string]string `json:"metadata"`
	ExpiresAt       *time.Time        `json:"expires_at"`
	UpstreamURL     string            `json:"upstream_url"`
	ChecksumMD5     string            `json:"checksum_md5"`
	ChecksumSHA256  string            `json:"checksum_sha256"`
	ID              string            `json:"id"`
	StorageKey      string            `json:"storage_key"`
	Version         string            `json:"version"`
	Name            string            `json:"name"`
	Registry        string            `json:"registry"`
	AuthProvider    string            `json:"auth_provider"`
	Size            int64             `json:"size"`
	DownloadCount   int64             `json:"download_count"`
	SecurityScanned bool              `json:"security_scanned"`
	RequiresAuth    bool              `json:"requires_auth"`
}

// ScanResult represents a security scan result
type ScanResult struct {
	ScannedAt          time.Time              `json:"scanned_at"`
	Details            map[string]interface{} `json:"details"`
	ID                 string                 `json:"id"`
	Registry           string                 `json:"registry"`
	PackageName        string                 `json:"package_name"`
	PackageVersion     string                 `json:"package_version"`
	Scanner            string                 `json:"scanner"`
	Status             ScanStatus             `json:"status"`
	Vulnerabilities    []Vulnerability        `json:"vulnerabilities"`
	VulnerabilityCount int                    `json:"vulnerability_count"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string   `json:"id"`       // CVE-xxx, GHSA-xxx, etc.
	Severity    string   `json:"severity"` // critical, high, moderate, low
	Title       string   `json:"title"`
	Description string   `json:"description"`
	References  []string `json:"references"`
	FixedIn     string   `json:"fixed_in"`              // Version where fixed
	DetectedBy  []string `json:"detected_by,omitempty"` // List of scanners that detected this vulnerability
}

// NormalizeSeverity normalizes severity names to standard values
// Ensures consistent naming: CRITICAL, HIGH, MODERATE, LOW
func NormalizeSeverity(severity string) string {
	normalized := strings.ToUpper(strings.TrimSpace(severity))

	// Map MEDIUM to MODERATE for consistency
	if normalized == "MEDIUM" {
		return "MODERATE"
	}

	// Ensure we only return valid severity levels
	switch normalized {
	case "CRITICAL", "HIGH", "MODERATE", "LOW":
		return normalized
	default:
		return "LOW" // Default unknown severities to LOW
	}
}

// ScanStatus represents scan result status
type ScanStatus string

const (
	ScanStatusClean      ScanStatus = "clean"
	ScanStatusVulnerable ScanStatus = "vulnerable"
	ScanStatusError      ScanStatus = "error"
	ScanStatusPending    ScanStatus = "pending"
)

// Stats represents metadata statistics
type Stats struct {
	LastUpdated        time.Time `json:"last_updated"`
	Registry           string    `json:"registry"`
	TotalPackages      int64     `json:"total_packages"`
	TotalSize          int64     `json:"total_size"`
	TotalDownloads     int64     `json:"total_downloads"`
	ScannedPackages    int64     `json:"scanned_packages"`
	VulnerablePackages int64     `json:"vulnerable_packages"`
}

// TimeSeriesDataPoint represents a single data point in time-series
type TimeSeriesDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     int64     `json:"value"`
}

// TimeSeriesStats represents time-series download statistics
type TimeSeriesStats struct {
	Period     string                 `json:"period"`   // 1h, 1day, 7day, 30day
	Registry   string                 `json:"registry"` // empty string for all registries
	DataPoints []*TimeSeriesDataPoint `json:"data_points"`
}

// CVEBypass represents a temporary bypass for a CVE or package
type CVEBypass struct {
	ID             string     `json:"id"`                   // Unique bypass ID
	Type           BypassType `json:"type"`                 // cve, package
	Target         string     `json:"target"`               // CVE ID (e.g., "CVE-2021-23337") or package (e.g., "npm/lodash@4.17.20")
	Reason         string     `json:"reason"`               // Why this bypass was created
	CreatedBy      string     `json:"created_by"`           // Admin user who created it
	CreatedAt      time.Time  `json:"created_at"`           // When created
	ExpiresAt      time.Time  `json:"expires_at"`           // When it expires
	AppliesTo      string     `json:"applies_to,omitempty"` // Optional: limit to specific package (for CVE bypasses)
	NotifyOnExpiry bool       `json:"notify_on_expiry"`     // Send notification when expired
	Active         bool       `json:"active"`               // Can be deactivated without deletion
}

// BypassType represents the type of bypass
type BypassType string

const (
	BypassTypeCVE     BypassType = "cve"     // Bypass specific CVE
	BypassTypePackage BypassType = "package" // Bypass entire package
)

// BypassListOptions contains options for listing CVE bypasses
type BypassListOptions struct {
	Type           BypassType // Filter by type
	IncludeExpired bool       // Include expired bypasses
	ActiveOnly     bool       // Only active bypasses
	Limit          int        // Max results
	Offset         int        // Pagination offset
}

// ListOptions contains options for listing packages
type ListOptions struct {
	SinceDate   time.Time
	Registry    string
	NamePrefix  string
	SortBy      string
	MinSize     int64
	MaxSize     int64
	Limit       int
	Offset      int
	ScannedOnly bool
	SortDesc    bool
}
