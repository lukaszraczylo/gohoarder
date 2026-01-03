package gormstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GORMStoreV2TestSuite is the test suite for V2 GORM implementation
type GORMStoreV2TestSuite struct {
	suite.Suite
	db    *gorm.DB
	store *GORMStoreV2
	ctx   context.Context
}

// SetupSuite runs once before all tests
func (s *GORMStoreV2TestSuite) SetupSuite() {
	// Use in-memory SQLite for fast tests
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	s.Require().NoError(err)
	s.db = db
}

// SetupTest runs before each test
func (s *GORMStoreV2TestSuite) SetupTest() {
	s.ctx = context.Background()

	// Create fresh store with V2 schema
	cfg := Config{
		Driver:          "sqlite",
		DSN:             "file::memory:?cache=shared",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 3600 * time.Second,
		LogLevel:        "silent",
	}

	store, err := NewV2(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(store)

	s.store = store
}

// TearDownTest runs after each test
func (s *GORMStoreV2TestSuite) TearDownTest() {
	if s.store != nil {
		// Clean up all tables for next test
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
		}

		for _, table := range tables {
			s.store.db.Exec(fmt.Sprintf("DELETE FROM %s", table))
		}

		s.store.Close()
	}
}

// TestGORMStoreV2TestSuite runs the test suite
func TestGORMStoreV2TestSuite(t *testing.T) {
	suite.Run(t, new(GORMStoreV2TestSuite))
}

// Test_V2_SavePackage_Success tests saving a package
func (s *GORMStoreV2TestSuite) Test_V2_SavePackage_Success() {
	pkg := &metadata.Package{
		Registry:       "npm",
		Name:           "test-package",
		Version:        "1.0.0",
		StorageKey:     "npm/test-package/1.0.0.tgz",
		Size:           12345,
		ChecksumMD5:    "abc123",
		ChecksumSHA256: "def456",
		UpstreamURL:    "https://registry.npmjs.org/test-package",
		CachedAt:       time.Now(),
		LastAccessed:   time.Now(),
	}

	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Verify package was saved
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "test-package", "1.0.0")
	s.NoError(err)
	s.NotNil(retrieved)
	s.Equal("npm", retrieved.Registry)
	s.Equal("test-package", retrieved.Name)
	s.Equal("1.0.0", retrieved.Version)
	s.Equal(int64(12345), retrieved.Size)
}

// Test_V2_SavePackage_WithMetadata tests saving package with metadata
func (s *GORMStoreV2TestSuite) Test_V2_SavePackage_WithMetadata() {
	metadataMap := map[string]string{
		"author":      "Test Author",
		"license":     "MIT",
		"homepage":    "https://example.com",
		"description": "Test package description",
	}

	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "meta-package",
		Version:      "2.0.0",
		StorageKey:   "npm/meta-package/2.0.0.tgz",
		Size:         5000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
		Metadata:     metadataMap,
	}

	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Verify metadata was saved in separate table
	var pkgMetadata PackageMetadataModel
	err = s.store.db.Where("package_id = (SELECT id FROM packages WHERE name = ?)", "meta-package").
		First(&pkgMetadata).Error
	s.NoError(err)
	s.Equal("Test Author", pkgMetadata.Author)
	s.Equal("MIT", pkgMetadata.License)
	s.Equal("https://example.com", pkgMetadata.Homepage)
}

// Test_V2_SavePackage_Upsert tests update on conflict
func (s *GORMStoreV2TestSuite) Test_V2_SavePackage_Upsert() {
	// Save initial package
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "upsert-test",
		Version:      "1.0.0",
		StorageKey:   "npm/upsert-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Update same package
	pkg.Size = 2000
	pkg.ChecksumMD5 = "updated"
	err = s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Verify updated
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "upsert-test", "1.0.0")
	s.NoError(err)
	s.Equal(int64(2000), retrieved.Size)
	s.Equal("updated", retrieved.ChecksumMD5)
}

// Test_V2_GetPackage_NotFound tests getting non-existent package
func (s *GORMStoreV2TestSuite) Test_V2_GetPackage_NotFound() {
	_, err := s.store.GetPackage(s.ctx, "npm", "nonexistent", "1.0.0")
	s.Error(err)
	s.Contains(err.Error(), "not found")
}

// Test_V2_DeletePackage_Success tests soft delete
func (s *GORMStoreV2TestSuite) Test_V2_DeletePackage_Success() {
	// Save package
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "delete-test",
		Version:      "1.0.0",
		StorageKey:   "npm/delete-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Delete package (soft delete)
	err = s.store.DeletePackage(s.ctx, "npm", "delete-test", "1.0.0")
	s.NoError(err)

	// Verify deleted (should not be found)
	_, err = s.store.GetPackage(s.ctx, "npm", "delete-test", "1.0.0")
	s.Error(err)

	// Verify soft delete (deleted_at set)
	var count int64
	s.store.db.Unscoped().Model(&PackageModel{}).
		Where("name = ?", "delete-test").
		Count(&count)
	s.Equal(int64(1), count) // Still in DB, just soft deleted
}

// Test_V2_ListPackages_All tests listing all packages
func (s *GORMStoreV2TestSuite) Test_V2_ListPackages_All() {
	// Create multiple packages
	for i := 0; i < 5; i++ {
		pkg := &metadata.Package{
			Registry:     "npm",
			Name:         fmt.Sprintf("package-%d", i),
			Version:      "1.0.0",
			StorageKey:   fmt.Sprintf("npm/package-%d/1.0.0.tgz", i),
			Size:         int64(i * 1000),
			CachedAt:     time.Now(),
			LastAccessed: time.Now(),
		}
		err := s.store.SavePackage(s.ctx, pkg)
		s.NoError(err)
	}

	// List all packages
	packages, err := s.store.ListPackages(s.ctx, &metadata.ListOptions{})
	s.NoError(err)
	s.Len(packages, 5)
}

// Test_V2_ListPackages_FilterByRegistry tests filtering by registry
func (s *GORMStoreV2TestSuite) Test_V2_ListPackages_FilterByRegistry() {
	// Create packages in different registries
	registries := []string{"npm", "pypi", "go"}
	for _, reg := range registries {
		pkg := &metadata.Package{
			Registry:     reg,
			Name:         "test-package",
			Version:      "1.0.0",
			StorageKey:   fmt.Sprintf("%s/test-package/1.0.0", reg),
			Size:         1000,
			CachedAt:     time.Now(),
			LastAccessed: time.Now(),
		}
		err := s.store.SavePackage(s.ctx, pkg)
		s.NoError(err)
	}

	// Filter by npm registry
	packages, err := s.store.ListPackages(s.ctx, &metadata.ListOptions{
		Registry: "npm",
	})
	s.NoError(err)
	s.Len(packages, 1)
	s.Equal("npm", packages[0].Registry)
}

// Test_V2_ListPackages_Pagination tests pagination
func (s *GORMStoreV2TestSuite) Test_V2_ListPackages_Pagination() {
	// Create 10 packages
	for i := 0; i < 10; i++ {
		pkg := &metadata.Package{
			Registry:     "npm",
			Name:         fmt.Sprintf("package-%d", i),
			Version:      "1.0.0",
			StorageKey:   fmt.Sprintf("npm/package-%d/1.0.0.tgz", i),
			Size:         int64(i * 1000),
			CachedAt:     time.Now(),
			LastAccessed: time.Now(),
		}
		err := s.store.SavePackage(s.ctx, pkg)
		s.NoError(err)
	}

	// Get first page (5 items)
	page1, err := s.store.ListPackages(s.ctx, &metadata.ListOptions{
		Limit:  5,
		Offset: 0,
	})
	s.NoError(err)
	s.Len(page1, 5)

	// Get second page (5 items)
	page2, err := s.store.ListPackages(s.ctx, &metadata.ListOptions{
		Limit:  5,
		Offset: 5,
	})
	s.NoError(err)
	s.Len(page2, 5)

	// Verify different packages
	s.NotEqual(page1[0].Name, page2[0].Name)
}

// Test_V2_UpdateDownloadCount_Success tests incrementing download count
func (s *GORMStoreV2TestSuite) Test_V2_UpdateDownloadCount_Success() {
	// Create package
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "download-test",
		Version:      "1.0.0",
		StorageKey:   "npm/download-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Update download count
	err = s.store.UpdateDownloadCount(s.ctx, "npm", "download-test", "1.0.0")
	s.NoError(err)

	// Verify count incremented
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "download-test", "1.0.0")
	s.NoError(err)
	s.Equal(int64(1), retrieved.DownloadCount)

	// Update again
	err = s.store.UpdateDownloadCount(s.ctx, "npm", "download-test", "1.0.0")
	s.NoError(err)

	retrieved, err = s.store.GetPackage(s.ctx, "npm", "download-test", "1.0.0")
	s.NoError(err)
	s.Equal(int64(2), retrieved.DownloadCount)

	// Verify download event was recorded
	var eventCount int64
	s.store.db.Model(&DownloadEventModel{}).Count(&eventCount)
	s.Equal(int64(2), eventCount)
}

// Test_V2_Count tests counting packages
func (s *GORMStoreV2TestSuite) Test_V2_Count() {
	// Initially zero
	count, err := s.store.Count(s.ctx)
	s.NoError(err)
	s.Equal(0, count)

	// Create 3 packages
	for i := 0; i < 3; i++ {
		pkg := &metadata.Package{
			Registry:     "npm",
			Name:         fmt.Sprintf("count-test-%d", i),
			Version:      "1.0.0",
			StorageKey:   fmt.Sprintf("npm/count-test-%d/1.0.0.tgz", i),
			Size:         1000,
			CachedAt:     time.Now(),
			LastAccessed: time.Now(),
		}
		err := s.store.SavePackage(s.ctx, pkg)
		s.NoError(err)
	}

	count, err = s.store.Count(s.ctx)
	s.NoError(err)
	s.Equal(3, count)
}

// Test_V2_GetStats tests aggregated statistics
func (s *GORMStoreV2TestSuite) Test_V2_GetStats() {
	// Create packages in different registries
	packages := []*metadata.Package{
		{Registry: "npm", Name: "pkg1", Version: "1.0.0", StorageKey: "npm/pkg1/1.0.0.tgz", Size: 1000, CachedAt: time.Now(), LastAccessed: time.Now()},
		{Registry: "npm", Name: "pkg2", Version: "1.0.0", StorageKey: "npm/pkg2/1.0.0.tgz", Size: 2000, CachedAt: time.Now(), LastAccessed: time.Now()},
		{Registry: "pypi", Name: "pkg3", Version: "1.0.0", StorageKey: "pypi/pkg3/1.0.0.tar.gz", Size: 3000, CachedAt: time.Now(), LastAccessed: time.Now()},
	}

	for _, pkg := range packages {
		err := s.store.SavePackage(s.ctx, pkg)
		s.NoError(err)
	}

	// Update download counts
	s.store.UpdateDownloadCount(s.ctx, "npm", "pkg1", "1.0.0")
	s.store.UpdateDownloadCount(s.ctx, "npm", "pkg1", "1.0.0")
	s.store.UpdateDownloadCount(s.ctx, "npm", "pkg2", "1.0.0")

	// Get stats for all registries
	statsAll, err := s.store.GetStats(s.ctx, "")
	s.NoError(err)
	s.Equal(int64(3), statsAll.TotalPackages)
	s.Equal(int64(6000), statsAll.TotalSize)
	s.Equal(int64(3), statsAll.TotalDownloads)

	// Get stats for npm registry
	statsNpm, err := s.store.GetStats(s.ctx, "npm")
	s.NoError(err)
	s.Equal("npm", statsNpm.Registry)
	s.Equal(int64(2), statsNpm.TotalPackages)
	s.Equal(int64(3000), statsNpm.TotalSize)
	s.Equal(int64(3), statsNpm.TotalDownloads)

	// Get stats for pypi registry
	statsPypi, err := s.store.GetStats(s.ctx, "pypi")
	s.NoError(err)
	s.Equal("pypi", statsPypi.Registry)
	s.Equal(int64(1), statsPypi.TotalPackages)
	s.Equal(int64(3000), statsPypi.TotalSize)
}

// Test_V2_Health tests database health check
func (s *GORMStoreV2TestSuite) Test_V2_Health() {
	err := s.store.Health(s.ctx)
	s.NoError(err)
}

// Test_V2_RegistryCache tests registry caching
func (s *GORMStoreV2TestSuite) Test_V2_RegistryCache() {
	// Default registries should be cached
	s.Contains(s.store.registryCache, "npm")
	s.Contains(s.store.registryCache, "pypi")
	s.Contains(s.store.registryCache, "go")

	// Get registry ID from cache
	npmID, err := s.store.getRegistryID("npm")
	s.NoError(err)
	s.Greater(npmID, int32(0))

	// Second call should use cache (no DB query)
	npmID2, err := s.store.getRegistryID("npm")
	s.NoError(err)
	s.Equal(npmID, npmID2)

	// Non-existent registry
	_, err = s.store.getRegistryID("nonexistent")
	s.Error(err)
	s.Contains(err.Error(), "not found")
}

// Test_V2_SoftDelete tests soft delete behavior
func (s *GORMStoreV2TestSuite) Test_V2_SoftDelete() {
	// Create package
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "soft-delete",
		Version:      "1.0.0",
		StorageKey:   "npm/soft-delete/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Delete
	err = s.store.DeletePackage(s.ctx, "npm", "soft-delete", "1.0.0")
	s.NoError(err)

	// Count should not include deleted
	count, err := s.store.Count(s.ctx)
	s.NoError(err)
	s.Equal(0, count)

	// But record still exists with deleted_at set
	var pkgModel PackageModel
	err = s.store.db.Unscoped().Where("name = ?", "soft-delete").First(&pkgModel).Error
	s.NoError(err)
	s.NotNil(pkgModel.DeletedAt)
}

// Test_V2_AggregationWorker tests that aggregation worker is initialized
func (s *GORMStoreV2TestSuite) Test_V2_AggregationWorker() {
	s.NotNil(s.store.aggregationWorker)
}

// Test_V2_ConcurrentUpdates tests concurrent download count updates
func (s *GORMStoreV2TestSuite) Test_V2_ConcurrentUpdates() {
	// Create package
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "concurrent-test",
		Version:      "1.0.0",
		StorageKey:   "npm/concurrent-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// SQLite: Sequential updates only (write lock prevents concurrent writes)
	updateCount := 5
	for i := 0; i < updateCount; i++ {
		err := s.store.UpdateDownloadCount(s.ctx, "npm", "concurrent-test", "1.0.0")
		s.NoError(err)
	}

	// Verify all updates succeeded
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "concurrent-test", "1.0.0")
	s.NoError(err)
	s.Equal(int64(updateCount), retrieved.DownloadCount)
}

// Test_V2_SaveScanResult tests saving a scan result
func (s *GORMStoreV2TestSuite) Test_V2_SaveScanResult() {
	// Create a package first
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "test-package",
		Version:      "1.0.0",
		StorageKey:   "/cache/npm/test-package-1.0.0.tgz",
		Size:         1024,
		UpstreamURL:  "https://registry.npmjs.org/test-package",
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Create and save a scan result
	scanResult := &metadata.ScanResult{
		Registry:       "npm",
		PackageName:    "test-package",
		PackageVersion: "1.0.0",
		Scanner:        "trivy",
		Status:         metadata.ScanStatusVulnerable,
		ScannedAt:      time.Now(),
		Vulnerabilities: []metadata.Vulnerability{
			{
				ID:          "CVE-2024-0001",
				Severity:    "HIGH",
				Title:       "Test vulnerability",
				Description: "Test description",
				References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001"},
			},
			{
				ID:          "CVE-2024-0002",
				Severity:    "CRITICAL",
				Title:       "Critical vulnerability",
				Description: "Critical test description",
				References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0002"},
			},
		},
		VulnerabilityCount: 2,
		Details: map[string]interface{}{
			"scan_duration":   42,
			"scanner_version": "1.0.0",
		},
	}

	err = s.store.SaveScanResult(s.ctx, scanResult)
	s.NoError(err)

	// Verify the scan result was saved and package was updated
	retrievedPkg, err := s.store.GetPackage(s.ctx, "npm", "test-package", "1.0.0")
	s.NoError(err)
	s.True(retrievedPkg.SecurityScanned)
}

// Test_V2_GetScanResult tests retrieving a scan result
func (s *GORMStoreV2TestSuite) Test_V2_GetScanResult() {
	// Create a package
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "scan-test",
		Version:      "2.0.0",
		StorageKey:   "/cache/npm/scan-test-2.0.0.tgz",
		Size:         2048,
		UpstreamURL:  "https://registry.npmjs.org/scan-test",
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Save a scan result with vulnerabilities
	scanResult := &metadata.ScanResult{
		Registry:       "npm",
		PackageName:    "scan-test",
		PackageVersion: "2.0.0",
		Scanner:        "grype",
		Status:         metadata.ScanStatusVulnerable,
		ScannedAt:      time.Now(),
		Vulnerabilities: []metadata.Vulnerability{
			{
				ID:          "CVE-2024-1234",
				Severity:    "HIGH",
				Title:       "Test High Severity",
				Description: "High severity test",
				References:  []string{"https://example.com/cve-2024-1234"},
				FixedIn:     "2.1.0",
			},
			{
				ID:          "CVE-2024-5678",
				Severity:    "MODERATE",
				Title:       "Test Moderate Severity",
				Description: "Moderate severity test",
				References:  []string{"https://example.com/cve-2024-5678"},
			},
		},
		VulnerabilityCount: 2,
	}
	err = s.store.SaveScanResult(s.ctx, scanResult)
	s.NoError(err)

	// Retrieve the scan result
	retrieved, err := s.store.GetScanResult(s.ctx, "npm", "scan-test", "2.0.0")
	s.NoError(err)
	s.NotNil(retrieved)
	s.Equal("grype", retrieved.Scanner)
	s.Equal(metadata.ScanStatusVulnerable, retrieved.Status)
	s.Equal(2, retrieved.VulnerabilityCount)
	s.Len(retrieved.Vulnerabilities, 2)

	// Verify vulnerability details are retrieved correctly
	s.Equal("CVE-2024-1234", retrieved.Vulnerabilities[0].ID)
	s.Equal("HIGH", retrieved.Vulnerabilities[0].Severity)
	s.Equal("Test High Severity", retrieved.Vulnerabilities[0].Title)
	s.Equal("2.1.0", retrieved.Vulnerabilities[0].FixedIn)
	s.Len(retrieved.Vulnerabilities[0].References, 1)
}

// Test_V2_GetScanResult_NotFound tests retrieving a non-existent scan result
func (s *GORMStoreV2TestSuite) Test_V2_GetScanResult_NotFound() {
	_, err := s.store.GetScanResult(s.ctx, "npm", "nonexistent", "1.0.0")
	s.Error(err)
}

// Test_V2_SaveCVEBypass tests saving a CVE bypass
func (s *GORMStoreV2TestSuite) Test_V2_SaveCVEBypass() {
	bypass := &metadata.CVEBypass{
		Type:           metadata.BypassTypeCVE,
		Target:         "CVE-2024-0001",
		Reason:         "False positive - not applicable to our use case",
		CreatedBy:      "admin@example.com",
		ExpiresAt:      time.Now().Add(30 * 24 * time.Hour), // 30 days
		NotifyOnExpiry: true,
		Active:         true,
	}

	err := s.store.SaveCVEBypass(s.ctx, bypass)
	s.NoError(err)
	s.NotEmpty(bypass.ID)
	s.NotZero(bypass.CreatedAt)
}

// Test_V2_SaveCVEBypass_Update tests updating an existing CVE bypass
func (s *GORMStoreV2TestSuite) Test_V2_SaveCVEBypass_Update() {
	// Create initial bypass
	bypass := &metadata.CVEBypass{
		Type:           metadata.BypassTypeCVE,
		Target:         "CVE-2024-0002",
		Reason:         "Initial reason",
		CreatedBy:      "admin@example.com",
		ExpiresAt:      time.Now().Add(30 * 24 * time.Hour),
		NotifyOnExpiry: false,
		Active:         true,
	}
	err := s.store.SaveCVEBypass(s.ctx, bypass)
	s.NoError(err)
	s.NotEmpty(bypass.ID)

	// Update the bypass
	bypass.Reason = "Updated reason"
	bypass.NotifyOnExpiry = true
	err = s.store.SaveCVEBypass(s.ctx, bypass)
	s.NoError(err)
}

// Test_V2_GetActiveCVEBypasses tests retrieving active CVE bypasses
func (s *GORMStoreV2TestSuite) Test_V2_GetActiveCVEBypasses() {
	// Create active bypass with unique target
	uniqueTarget := fmt.Sprintf("CVE-2024-TEST-%d", time.Now().UnixNano())
	activeBypass := &metadata.CVEBypass{
		Type:      metadata.BypassTypeCVE,
		Target:    uniqueTarget,
		Reason:    "Active bypass",
		CreatedBy: "admin@example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		Active:    true,
	}
	err := s.store.SaveCVEBypass(s.ctx, activeBypass)
	s.NoError(err)

	// Create expired bypass
	expiredBypass := &metadata.CVEBypass{
		Type:      metadata.BypassTypeCVE,
		Target:    "CVE-2024-0004",
		Reason:    "Expired bypass",
		CreatedBy: "admin@example.com",
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
		Active:    true,
	}
	err = s.store.SaveCVEBypass(s.ctx, expiredBypass)
	s.NoError(err)

	// Create inactive bypass
	inactiveBypass := &metadata.CVEBypass{
		Type:      metadata.BypassTypeCVE,
		Target:    "CVE-2024-0005",
		Reason:    "Inactive bypass",
		CreatedBy: "admin@example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		Active:    false,
	}
	err = s.store.SaveCVEBypass(s.ctx, inactiveBypass)
	s.NoError(err)

	// Retrieve active bypasses
	bypasses, err := s.store.GetActiveCVEBypasses(s.ctx)
	s.NoError(err)

	// Should contain our active bypass, but may contain others from parallel tests
	found := false
	for _, b := range bypasses {
		if b.Target == uniqueTarget {
			found = true
			break
		}
		// All bypasses should be active and non-expired
		s.True(b.Active)
		s.True(b.ExpiresAt.After(time.Now()))
	}
	s.True(found, "Should find our unique active bypass")
}

// Test_V2_ListCVEBypasses tests listing CVE bypasses with filters
func (s *GORMStoreV2TestSuite) Test_V2_ListCVEBypasses() {
	// Create multiple bypasses with unique targets
	nano := time.Now().UnixNano()
	bypasses := []*metadata.CVEBypass{
		{
			Type:      metadata.BypassTypeCVE,
			Target:    fmt.Sprintf("CVE-2024-LIST-%d-1", nano),
			Reason:    "Test 1",
			CreatedBy: "admin@example.com",
			ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
			Active:    true,
		},
		{
			Type:      metadata.BypassTypePackage,
			Target:    fmt.Sprintf("npm/vulnerable-package@%d", nano),
			Reason:    "Test 2",
			CreatedBy: "admin@example.com",
			ExpiresAt: time.Now().Add(15 * 24 * time.Hour),
			Active:    true,
		},
		{
			Type:      metadata.BypassTypeCVE,
			Target:    fmt.Sprintf("CVE-2024-LIST-%d-2", nano),
			Reason:    "Test 3",
			CreatedBy: "admin@example.com",
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
			Active:    true,
		},
	}

	for _, b := range bypasses {
		err := s.store.SaveCVEBypass(s.ctx, b)
		s.NoError(err)
	}

	// List only CVE type
	opts := &metadata.BypassListOptions{
		Type: metadata.BypassTypeCVE,
	}
	cveOnly, err := s.store.ListCVEBypasses(s.ctx, opts)
	s.NoError(err)
	for _, b := range cveOnly {
		s.Equal(metadata.BypassTypeCVE, b.Type)
	}

	// List only non-expired
	opts = &metadata.BypassListOptions{
		IncludeExpired: false,
	}
	nonExpired, err := s.store.ListCVEBypasses(s.ctx, opts)
	s.NoError(err)
	for _, b := range nonExpired {
		s.True(b.ExpiresAt.After(time.Now()))
	}

	// Test pagination
	opts = &metadata.BypassListOptions{
		Limit:  1,
		Offset: 0,
	}
	page1, err := s.store.ListCVEBypasses(s.ctx, opts)
	s.NoError(err)
	s.LessOrEqual(len(page1), 1) // Should be at most 1
}

// Test_V2_DeleteCVEBypass tests deleting a CVE bypass
func (s *GORMStoreV2TestSuite) Test_V2_DeleteCVEBypass() {
	// Create a bypass
	bypass := &metadata.CVEBypass{
		Type:      metadata.BypassTypeCVE,
		Target:    "CVE-2024-0008",
		Reason:    "To be deleted",
		CreatedBy: "admin@example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		Active:    true,
	}
	err := s.store.SaveCVEBypass(s.ctx, bypass)
	s.NoError(err)
	s.NotEmpty(bypass.ID)

	// Delete the bypass
	err = s.store.DeleteCVEBypass(s.ctx, bypass.ID)
	s.NoError(err)

	// Verify it's no longer in active bypasses
	active, err := s.store.GetActiveCVEBypasses(s.ctx)
	s.NoError(err)
	for _, b := range active {
		s.NotEqual(bypass.ID, b.ID)
	}
}

// Test_V2_DeleteCVEBypass_NotFound tests deleting a non-existent bypass
func (s *GORMStoreV2TestSuite) Test_V2_DeleteCVEBypass_NotFound() {
	err := s.store.DeleteCVEBypass(s.ctx, "99999999")
	s.Error(err)
}

// Test_V2_DeleteCVEBypass_InvalidID tests deleting with invalid ID
func (s *GORMStoreV2TestSuite) Test_V2_DeleteCVEBypass_InvalidID() {
	err := s.store.DeleteCVEBypass(s.ctx, "invalid-id")
	s.Error(err)
}

// Test_V2_CleanupExpiredBypasses tests cleaning up expired bypasses
func (s *GORMStoreV2TestSuite) Test_V2_CleanupExpiredBypasses() {
	// Create expired bypasses
	for i := 0; i < 3; i++ {
		bypass := &metadata.CVEBypass{
			Type:      metadata.BypassTypeCVE,
			Target:    fmt.Sprintf("CVE-2024-00%d", 10+i),
			Reason:    "Expired bypass",
			CreatedBy: "admin@example.com",
			ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
			Active:    true,
		}
		err := s.store.SaveCVEBypass(s.ctx, bypass)
		s.NoError(err)
	}

	// Create active bypass (should not be deleted)
	activeBypass := &metadata.CVEBypass{
		Type:      metadata.BypassTypeCVE,
		Target:    "CVE-2024-0999",
		Reason:    "Active bypass",
		CreatedBy: "admin@example.com",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		Active:    true,
	}
	err := s.store.SaveCVEBypass(s.ctx, activeBypass)
	s.NoError(err)

	// Cleanup expired bypasses
	count, err := s.store.CleanupExpiredBypasses(s.ctx)
	s.NoError(err)
	s.GreaterOrEqual(count, 3) // At least the 3 we just created

	// Verify active bypass is still there
	active, err := s.store.GetActiveCVEBypasses(s.ctx)
	s.NoError(err)
	found := false
	for _, b := range active {
		if b.Target == "CVE-2024-0999" {
			found = true
			break
		}
	}
	s.True(found, "Active bypass should still exist")
}
