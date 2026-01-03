//go:build integration
// +build integration

package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/wait"
)

// MySQLV2IntegrationTestSuite embeds the V2 test suite with MySQL container
type MySQLV2IntegrationTestSuite struct {
	GORMStoreV2TestSuite
	container *mysql.MySQLContainer
}

// SetupSuite runs once before all tests
func (s *MySQLV2IntegrationTestSuite) SetupSuite() {
	ctx := context.Background()

	// Start MySQL container
	container, err := mysql.RunContainer(ctx,
		testcontainers.WithImage("mysql:8.0"),
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("testuser"),
		mysql.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server").
				WithOccurrence(1).
				WithStartupTimeout(60*time.Second),
		),
	)
	s.Require().NoError(err)
	s.container = container
}

// TearDownSuite runs once after all tests
func (s *MySQLV2IntegrationTestSuite) TearDownSuite() {
	if s.container != nil {
		ctx := context.Background()
		err := s.container.Terminate(ctx)
		s.NoError(err)
	}
}

// SetupTest runs before each test
func (s *MySQLV2IntegrationTestSuite) SetupTest() {
	s.ctx = context.Background()

	// Get connection string from container
	connStr, err := s.container.ConnectionString(s.ctx)
	s.Require().NoError(err)

	// Create GORM store with MySQL
	cfg := Config{
		Driver:          "mysql",
		DSN:             connStr,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 3600 * time.Second,
		LogLevel:        "silent",
	}

	s.store, err = NewV2(cfg)
	s.Require().NoError(err)
	s.Require().NotNil(s.store)
}

// TearDownTest runs after each test
func (s *MySQLV2IntegrationTestSuite) TearDownTest() {
	if s.store != nil {
		// Clean up all tables for next test
		tables := []string{
			"download_events",
			"download_stats_hourly",
			"download_stats_daily",
			"audit_log",
			"cve_bypasses",
			"scan_results",
			"package_vulnerabilities",
			"vulnerabilities",
			"package_metadata",
			"packages",
			"registries",
		}

		for _, table := range tables {
			s.store.db.Exec("TRUNCATE TABLE " + table)
		}

		// Re-seed default registries after truncate
		defaultRegistries := []RegistryModel{
			{Name: "npm", DisplayName: "NPM Registry", UpstreamURL: "https://registry.npmjs.org", Enabled: true, ScanByDefault: true},
			{Name: "pypi", DisplayName: "PyPI", UpstreamURL: "https://pypi.org", Enabled: true, ScanByDefault: true},
			{Name: "go", DisplayName: "Go Modules", UpstreamURL: "https://proxy.golang.org", Enabled: true, ScanByDefault: true},
		}
		for _, reg := range defaultRegistries {
			s.store.db.Create(&reg)
		}

		// Rebuild registry cache
		s.store.rebuildRegistryCache()

		s.store.Close()
	}
}

// TestMySQLV2IntegrationTestSuite runs the integration test suite with MySQL
func TestMySQLV2IntegrationTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	suite.Run(t, new(MySQLV2IntegrationTestSuite))
}

// Test_MySQLV2_SpecificFeatures tests MySQL-specific features
func (s *MySQLV2IntegrationTestSuite) Test_MySQLV2_SpecificFeatures() {
	// Test that we're actually using MySQL
	var version string
	err := s.store.db.Raw("SELECT VERSION()").Scan(&version).Error
	s.NoError(err)
	s.Contains(version, "MySQL")
}

// Test_MySQLV2_NoPartitioning tests that partition manager is nil for MySQL
func (s *MySQLV2IntegrationTestSuite) Test_MySQLV2_NoPartitioning() {
	// MySQL doesn't use our partition manager (uses native partitioning differently)
	s.Nil(s.store.partitionManager)
}

// Test_MySQLV2_HighConcurrency tests MySQL's concurrent write support
func (s *MySQLV2IntegrationTestSuite) Test_MySQLV2_HighConcurrency() {
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

	// MySQL can handle concurrent writes (with InnoDB row-level locking)
	concurrency := 15
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			err := s.store.UpdateDownloadCount(s.ctx, "npm", "concurrent-test", "1.0.0")
			s.NoError(err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Verify all updates succeeded
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "concurrent-test", "1.0.0")
	s.NoError(err)
	s.Equal(int64(concurrency), retrieved.DownloadCount)
}

// Test_MySQLV2_JSON tests MySQL JSON functionality
func (s *MySQLV2IntegrationTestSuite) Test_MySQLV2_JSON() {
	metadata := map[string]interface{}{
		"author":      "Test Author",
		"license":     "MIT",
		"description": "Test package",
		"keywords":    []interface{}{"test", "mysql", "json"},
	}

	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "json-test",
		Version:      "1.0.0",
		StorageKey:   "npm/json-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
		Metadata:     metadata,
	}

	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Retrieve and verify JSON data
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "json-test", "1.0.0")
	s.NoError(err)
	s.NotNil(retrieved.Metadata)
	s.Equal("MIT", retrieved.Metadata["license"])
	s.Equal("Test Author", retrieved.Metadata["author"])
}

// Test_MySQLV2_TransactionRollback tests MySQL transaction rollback
func (s *MySQLV2IntegrationTestSuite) Test_MySQLV2_TransactionRollback() {
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "tx-test",
		Version:      "1.0.0",
		StorageKey:   "npm/tx-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
	}
	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Try to update with invalid data that should trigger rollback
	err = s.store.db.Transaction(func(tx *gorm.DB) error {
		// First update succeeds
		result := tx.Model(&PackageModel{}).
			Where("registry_id = ? AND name = ? AND version = ?",
				s.store.registryCache["npm"], "tx-test", "1.0.0").
			Update("access_count", gorm.Expr("access_count + ?", 1))
		if result.Error != nil {
			return result.Error
		}

		// Second operation fails (invalid foreign key)
		invalidModel := &PackageModel{
			RegistryID:   9999, // Non-existent registry
			Name:         "invalid",
			Version:      "1.0.0",
			StorageKey:   "invalid",
			Size:         100,
			CachedAt:     time.Now(),
			LastAccessed: time.Now(),
		}
		return tx.Create(invalidModel).Error
	})

	// Transaction should fail
	s.Error(err)

	// Verify first update was rolled back
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "tx-test", "1.0.0")
	s.NoError(err)
	s.Equal(int64(0), retrieved.DownloadCount) // Should still be 0, not 1
}

// Test_MySQLV2_CharacterSet tests MySQL UTF-8 support
func (s *MySQLV2IntegrationTestSuite) Test_MySQLV2_CharacterSet() {
	// Test package with Unicode characters
	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "unicode-test-世界-🚀",
		Version:      "1.0.0",
		StorageKey:   "npm/unicode-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
		Metadata: map[string]interface{}{
			"description": "Test with emoji 🎉 and Chinese 中文",
		},
	}

	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Retrieve and verify Unicode data preserved
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "unicode-test-世界-🚀", "1.0.0")
	s.NoError(err)
	s.Equal("unicode-test-世界-🚀", retrieved.Name)
	s.Contains(retrieved.Metadata["description"], "🎉")
	s.Contains(retrieved.Metadata["description"], "中文")
}
