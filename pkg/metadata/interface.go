// Package metadata defines the Store interface and shared model types for
// package metadata persistence backends.
package metadata

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrNotImplemented signals that an optional MetadataStore method is not
// supported by the current backend (e.g. a backend may not persist API keys).
// Callers should treat it as a non-fatal capability check.
var ErrNotImplemented = errors.New("metadata: operation not implemented by this backend")

// DefaultBatchSize bounds the rows a list query returns when the caller passes no limit.
const DefaultBatchSize = 500

// MetadataVersions are the cache-key versions of metadata pages (index, list, latest).
var MetadataVersions = []string{"list", "page", "latest", "metadata"}

// MetadataNameSuffixes mark Go module metadata files (.mod, .info).
var MetadataNameSuffixes = []string{".mod", ".info"}

// GoRegistry is the registry whose cache keys carry the name suffixes above.
const GoRegistry = "go"

// IsMetadataEntry reports whether a cache entry is a metadata page that must
// refresh, as opposed to an immutable artifact. The name suffixes apply to Go
// only: an npm or PyPI package may legitimately end in .mod or .info.
func IsMetadataEntry(registry, name, version string) bool {
	for _, v := range MetadataVersions {
		if version == v {
			return true
		}
	}
	if registry != GoRegistry {
		return false
	}
	for _, suffix := range MetadataNameSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

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

	// ListPackageGroups returns one page of (registry, name) groups with every
	// version row of each group. It costs a constant number of statements.
	ListPackageGroups(ctx context.Context, opts GroupListOptions) (*GroupPage, error)

	// GetScanSummaries returns the latest scan of each scanned package in one
	// round trip. A nil packageIDs means every scanned package. Vulnerability
	// lists are loaded only when withDetails is set.
	GetScanSummaries(ctx context.Context, packageIDs []string, withDetails bool) ([]*ScanSummary, error)

	// GetRegistryStats returns per-registry totals over cache artifacts.
	GetRegistryStats(ctx context.Context) ([]RegistryStat, error)

	// UpdateDownloadCount increments download counter and stamps last_accessed
	UpdateDownloadCount(ctx context.Context, registry, name, version string) error

	// ListIdlePackages returns up to limit packages last accessed before
	// idleBefore, oldest first. A limit <= 0 means DefaultBatchSize.
	ListIdlePackages(ctx context.Context, idleBefore time.Time, limit int) ([]*Package, error)

	// ListExpiredPackages returns up to limit packages whose ExpiresAt is before
	// the given time, oldest first. A limit <= 0 means DefaultBatchSize.
	ListExpiredPackages(ctx context.Context, expiredBefore time.Time, limit int) ([]*Package, error)

	// PurgeDeletedPackages hard-deletes up to limit soft-deleted packages whose
	// deletion is older than deletedBefore, with their scan and vulnerability
	// rows, and returns the number removed. A limit <= 0 means DefaultBatchSize.
	PurgeDeletedPackages(ctx context.Context, deletedBefore time.Time, limit int) (int64, error)

	// GetStatsTrend returns the daily stats snapshots from the UTC day of since
	// on, oldest first. Backends without history return none.
	GetStatsTrend(ctx context.Context, since time.Time) ([]*StatsSnapshot, error)

	// ClearArtifactExpiry removes ExpiresAt from every non-metadata entry and
	// returns the number of rows changed. It is idempotent.
	ClearArtifactExpiry(ctx context.Context) (int64, error)

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

	// SaveAPIKey persists (insert or update) an API key record. Backends that
	// do not implement persistent API keys MUST return ErrNotImplemented.
	SaveAPIKey(ctx context.Context, key *APIKey) error

	// GetAPIKey retrieves a single API key by ID. Returns ErrNotImplemented if
	// the backend does not persist API keys. Returns a not-found error wrapped
	// from the backend if the key does not exist.
	GetAPIKey(ctx context.Context, id string) (*APIKey, error)

	// ListAPIKeys returns all API keys (including revoked) so callers can
	// decide whether to filter. Returns ErrNotImplemented for backends that
	// do not persist API keys.
	ListAPIKeys(ctx context.Context) ([]*APIKey, error)

	// DeleteAPIKey removes an API key by ID. Returns ErrNotImplemented for
	// backends that do not persist API keys.
	DeleteAPIKey(ctx context.Context, id string) error

	// UpdateAPIKeyLastUsed updates the last-used timestamp without rewriting
	// the rest of the row. Implementations should make this cheap; auth.Manager
	// may invoke it asynchronously on every successful validation.
	UpdateAPIKeyLastUsed(ctx context.Context, id string, t time.Time) error

	// Close closes the metadata store
	Close() error
}

// APIKey is the storage-layer representation of an authentication API key.
// It is intentionally separate from auth.APIKey to avoid an import cycle:
// the auth package depends on metadata, never the other way around.
type APIKey struct {
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ID          string     `json:"id"`
	KeyHash     string     `json:"key_hash"`
	Project     string     `json:"project"`
	Role        string     `json:"role"`
	Permissions string     `json:"permissions,omitempty"` // JSON-encoded list (optional)
	Revoked     bool       `json:"revoked"`
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
	ReleaseVersion  string            `json:"release_version,omitempty"`
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
	Aliases     []string `json:"aliases,omitempty"`     // Other ids of the same advisory; a CVE bypass matches any of them
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
	LastUpdated             time.Time `json:"last_updated"`
	Registry                string    `json:"registry"`
	TotalPackages           int64     `json:"total_packages"`
	TotalSize               int64     `json:"total_size"`
	TotalDownloads          int64     `json:"total_downloads"`
	ScannedPackages         int64     `json:"scanned_packages"`
	VulnerablePackages      int64     `json:"vulnerable_packages"`
	BlockedPackages         int64     `json:"blocked_packages"`
	CriticalVulnerabilities int64     `json:"critical_vulnerabilities"`
	HighVulnerabilities     int64     `json:"high_vulnerabilities"`
	ModerateVulnerabilities int64     `json:"moderate_vulnerabilities"`
	LowVulnerabilities      int64     `json:"low_vulnerabilities"`
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

// Group sort keys for GroupListOptions.SortBy.
const (
	GroupSortName      = "name"
	GroupSortCachedAt  = "cached_at"
	GroupSortDownloads = "downloads"
	GroupSortSize      = "size"
)

// GroupListOptions selects one page of package groups. A group is one
// (registry, cleaned name) pair; metadata pages never form a group.
type GroupListOptions struct {
	Registry string // empty = every registry
	Query    string // case-insensitive substring of name, version or release version
	SortBy   string // one of the GroupSort* keys; empty = name
	// Severities keeps rows whose latest scan holds a vulnerability of any listed
	// severity (SeverityCritical and the like); empty = no severity filter.
	Severities []string
	Page       int // 1-based
	PageSize   int // 0 = every group, unpaginated
	SortDesc   bool
}

// Severity filter values of GroupListOptions.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityModerate = "moderate"
	SeverityLow      = "low"
)

// Severities lists the severity filter values, most severe first.
var Severities = []string{SeverityCritical, SeverityHigh, SeverityModerate, SeverityLow}

// StatsSnapshot is the cache state at the end of one UTC day. The pointer
// fields are nil for days whose value cannot be reconstructed.
type StatsSnapshot struct {
	VulnerablePackages *int64 `json:"vulnerable_packages"`
	Critical           *int64 `json:"critical"`
	High               *int64 `json:"high"`
	Moderate           *int64 `json:"moderate"`
	Low                *int64 `json:"low"`
	Blocked            *int64 `json:"blocked"`
	Date               string `json:"date"` // YYYY-MM-DD, UTC
	TotalPackages      int64  `json:"total_packages"`
	TotalSize          int64  `json:"total_size"`
}

// StatsSnapshotDateLayout is the layout of StatsSnapshot.Date.
const StatsSnapshotDateLayout = "2006-01-02"

// GroupPage is one page of groups, flattened to rows.
type GroupPage struct {
	// Packages holds every version row of each group on the page, in group
	// order and newest first within a group. Name is the cleaned group name.
	Packages []*Package
	// TotalGroups counts the groups matching the filters, across all pages.
	TotalGroups int64
}

// ScanSummary is the latest scan of one package, without the heavy details.
type ScanSummary struct {
	ScannedAt       time.Time
	Details         map[string]interface{} // set only for failed scans
	Registry        string
	PackageID       string
	Name            string // the cache row name, including any Go /@v/ suffix
	Version         string
	ReleaseVersion  string
	Status          ScanStatus
	Vulnerabilities []Vulnerability // set only when requested
	Total           int
	Critical        int
	High            int
	Moderate        int
	Low             int
	HasScan         bool // false when the package is flagged scanned but has no scan row
}

// RegistryStat holds the totals of one registry.
type RegistryStat struct {
	Registry  string
	Count     int64
	Size      int64
	Downloads int64
}

// CleanName strips the Go "/@v/<file>" suffix so every file of a module version shares one name.
func CleanName(name string) string {
	if idx := strings.Index(name, "/@v/"); idx != -1 {
		return name[:idx]
	}
	return name
}

// DedupeVersions keeps one row per (cleaned name, version), preferring the largest
// (the Go .zip over its .mod and .info), and renames the rows to the cleaned name.
// Output order follows the first appearance of each key.
func DedupeVersions(rows []*Package) []*Package {
	index := make(map[string]int, len(rows))
	out := make([]*Package, 0, len(rows))
	for _, row := range rows {
		clean := *row
		clean.Name = CleanName(row.Name)
		key := clean.Registry + "\x00" + clean.Name + "\x00" + clean.Version
		if i, ok := index[key]; ok {
			if clean.Size > out[i].Size {
				out[i] = &clean
			}
			continue
		}
		index[key] = len(out)
		out = append(out, &clean)
	}
	return out
}

// TrendingPackage is a package's download count over the last 7 days and the 7 days before.
type TrendingPackage struct {
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Recent   int64  `json:"recent"`
	Previous int64  `json:"previous"`
}

// TrendingSource ranks packages from persisted download history. Backends without
// persisted downloads do not implement it.
type TrendingSource interface {
	GetTrendingPackages(ctx context.Context, limit int) ([]*TrendingPackage, error)
}
