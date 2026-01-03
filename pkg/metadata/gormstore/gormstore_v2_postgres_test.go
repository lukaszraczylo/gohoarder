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
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PostgresV2IntegrationTestSuite embeds the V2 test suite with PostgreSQL container
type PostgresV2IntegrationTestSuite struct {
	GORMStoreV2TestSuite
	container *postgres.PostgresContainer
}

// SetupSuite runs once before all tests
func (s *PostgresV2IntegrationTestSuite) SetupSuite() {
	ctx := context.Background()

	// Start PostgreSQL container
	container, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:16-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	s.Require().NoError(err)
	s.container = container
}

// TearDownSuite runs once after all tests
func (s *PostgresV2IntegrationTestSuite) TearDownSuite() {
	if s.container != nil {
		ctx := context.Background()
		err := s.container.Terminate(ctx)
		s.NoError(err)
	}
}

// SetupTest runs before each test
func (s *PostgresV2IntegrationTestSuite) SetupTest() {
	s.ctx = context.Background()

	// Get connection string from container
	connStr, err := s.container.ConnectionString(s.ctx)
	s.Require().NoError(err)

	// Create GORM store with PostgreSQL
	cfg := Config{
		Driver:          "postgres",
		DSN:             connStr + "sslmode=disable",
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
func (s *PostgresV2IntegrationTestSuite) TearDownTest() {
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
		}

		for _, table := range tables {
			s.store.db.Exec("TRUNCATE TABLE " + table + " CASCADE")
		}

		s.store.Close()
	}
}

// TestPostgresV2IntegrationTestSuite runs the integration test suite with PostgreSQL
func TestPostgresV2IntegrationTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	suite.Run(t, new(PostgresV2IntegrationTestSuite))
}

// Test_PostgresV2_SpecificFeatures tests PostgreSQL-specific features
func (s *PostgresV2IntegrationTestSuite) Test_PostgresV2_SpecificFeatures() {
	// Test that we're actually using PostgreSQL
	var version string
	err := s.store.db.Raw("SELECT version()").Scan(&version).Error
	s.NoError(err)
	s.Contains(version, "PostgreSQL")
}

// Test_PostgresV2_Partitioning tests partition manager
func (s *PostgresV2IntegrationTestSuite) Test_PostgresV2_Partitioning() {
	s.NotNil(s.store.partitionManager)

	// Get partition info
	info, err := s.store.partitionManager.GetPartitionInfo()
	s.NoError(err)
	s.NotNil(info)

	// Should have created partitions
	downloadPartitions := info["download_events_partitions"].(int64)
	s.Greater(downloadPartitions, int64(0))

	auditPartitions := info["audit_log_partitions"].(int64)
	s.Greater(auditPartitions, int64(0))
}

// Test_PostgresV2_HighConcurrency tests PostgreSQL's excellent concurrent write support
func (s *PostgresV2IntegrationTestSuite) Test_PostgresV2_HighConcurrency() {
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

	// PostgreSQL can handle many concurrent writes
	concurrency := 20
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

// Test_PostgresV2_JSONB tests PostgreSQL JSONB functionality
func (s *PostgresV2IntegrationTestSuite) Test_PostgresV2_JSONB() {
	metadata := map[string]interface{}{
		"author":      "Test Author",
		"license":     "MIT",
		"description": "Test package",
		"keywords":    []interface{}{"test", "postgres", "jsonb"},
	}

	pkg := &metadata.Package{
		Registry:     "npm",
		Name:         "jsonb-test",
		Version:      "1.0.0",
		StorageKey:   "npm/jsonb-test/1.0.0.tgz",
		Size:         1000,
		CachedAt:     time.Now(),
		LastAccessed: time.Now(),
		Metadata:     metadata,
	}

	err := s.store.SavePackage(s.ctx, pkg)
	s.NoError(err)

	// Retrieve and verify JSONB data
	retrieved, err := s.store.GetPackage(s.ctx, "npm", "jsonb-test", "1.0.0")
	s.NoError(err)
	s.NotNil(retrieved.Metadata)
	s.Equal("MIT", retrieved.Metadata["license"])
	s.Equal("Test Author", retrieved.Metadata["author"])
}
