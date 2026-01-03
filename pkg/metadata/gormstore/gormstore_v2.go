package gormstore

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GORMStoreV2 implements metadata.Store interface with optimized V2 schema
type GORMStoreV2 struct {
	db                *gorm.DB
	registryCache     map[string]int32 // Cache registry name -> ID mapping
	aggregationWorker *AggregationWorker
	partitionManager  *PartitionManager
}

// NewV2 creates a new GORM-based metadata store with V2 schema
func NewV2(cfg Config) (*GORMStoreV2, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Configure GORM logger
	var gormLogger logger.Interface
	switch cfg.LogLevel {
	case "silent":
		gormLogger = logger.Default.LogMode(logger.Silent)
	case "error":
		gormLogger = logger.Default.LogMode(logger.Error)
	case "warn":
		gormLogger = logger.Default.LogMode(logger.Warn)
	case "info":
		gormLogger = logger.Default.LogMode(logger.Info)
	default:
		gormLogger = logger.Default.LogMode(logger.Warn)
	}

	// Initialize database connection
	var dialector gorm.Dialector
	switch cfg.Driver {
	case "sqlite":
		dialector = sqlite.Open(cfg.DSN)
	case "postgres", "postgresql":
		dialector = postgres.Open(cfg.DSN)
	case "mysql":
		dialector = mysql.Open(cfg.DSN)
	default:
		return nil, errors.New(errors.ErrCodeInvalidConfig, "unsupported driver: "+cfg.Driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: true, // Better performance
		PrepareStmt:            true, // Cached prepared statements
	})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to connect to database")
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get sql.DB")
	}

	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Auto-migrate schema
	if err := db.AutoMigrate(GetAllModels()...); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to migrate database")
	}

	store := &GORMStoreV2{
		db:            db,
		registryCache: make(map[string]int32),
	}

	// Initialize partition manager (PostgreSQL only)
	if cfg.Driver == "postgres" || cfg.Driver == "postgresql" {
		store.partitionManager = NewPartitionManager(db)
		if err := store.partitionManager.EnsurePartitions(); err != nil {
			log.Warn().Err(err).Msg("Failed to create partitions, continuing anyway")
		}
	}

	// Load registry cache
	if err := store.loadRegistryCache(); err != nil {
		return nil, err
	}

	// Seed default registries if empty
	if len(store.registryCache) == 0 {
		if err := store.seedDefaultRegistries(); err != nil {
			return nil, err
		}
	}

	// Start aggregation worker (skip for in-memory databases used in tests)
	if !strings.Contains(cfg.DSN, ":memory:") {
		store.aggregationWorker = NewAggregationWorker(db)
		go store.aggregationWorker.Start()
	} else {
		// For tests: create worker but don't start it
		store.aggregationWorker = NewAggregationWorker(db)
	}

	log.Info().
		Str("driver", cfg.Driver).
		Int("max_open_conns", cfg.MaxOpenConns).
		Int("max_idle_conns", cfg.MaxIdleConns).
		Msg("GORM V2 metadata store initialized")

	return store, nil
}

// loadRegistryCache loads registry name -> ID mapping into memory
func (s *GORMStoreV2) loadRegistryCache() error {
	var registries []RegistryModel
	if err := s.db.Select("id", "name").Find(&registries).Error; err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to load registries")
	}

	for _, r := range registries {
		s.registryCache[r.Name] = r.ID
	}
	return nil
}

// seedDefaultRegistries creates default registry entries
func (s *GORMStoreV2) seedDefaultRegistries() error {
	defaultRegistries := []RegistryModel{
		{Name: "npm", DisplayName: "NPM Registry", UpstreamURL: "https://registry.npmjs.org", Enabled: true, ScanByDefault: true},
		{Name: "pypi", DisplayName: "PyPI", UpstreamURL: "https://pypi.org", Enabled: true, ScanByDefault: true},
		{Name: "go", DisplayName: "Go Modules", UpstreamURL: "https://proxy.golang.org", Enabled: true, ScanByDefault: true},
	}

	for _, reg := range defaultRegistries {
		if err := s.db.Create(&reg).Error; err != nil {
			return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to seed registry: "+reg.Name)
		}
		s.registryCache[reg.Name] = reg.ID
	}

	log.Info().Msg("Seeded default registries: npm, pypi, go")
	return nil
}

// getRegistryID returns the registry ID from cache or database
func (s *GORMStoreV2) getRegistryID(name string) (int32, error) {
	if id, ok := s.registryCache[name]; ok {
		return id, nil
	}

	// Not in cache, try to load from database
	var reg RegistryModel
	if err := s.db.Select("id").Where("name = ?", name).First(&reg).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return 0, errors.New(errors.ErrCodeNotFound, "registry not found: "+name)
		}
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to query registry")
	}

	s.registryCache[name] = reg.ID
	return reg.ID, nil
}

// getStringFromMap safely extracts a string value from a map[string]interface{}
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// SavePackage saves or updates a package
func (s *GORMStoreV2) SavePackage(ctx context.Context, pkg *metadata.Package) error {
	registryID, err := s.getRegistryID(pkg.Registry)
	if err != nil {
		return err
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Convert to model
		model := &PackageModel{
			RegistryID:     registryID,
			Name:           pkg.Name,
			Version:        pkg.Version,
			StorageKey:     pkg.StorageKey,
			Size:           pkg.Size,
			ChecksumMD5:    pkg.ChecksumMD5,
			ChecksumSHA256: pkg.ChecksumSHA256,
			UpstreamURL:    pkg.UpstreamURL,
			CachedAt:       pkg.CachedAt,
			LastAccessed:   pkg.LastAccessed,
			ExpiresAt:      pkg.ExpiresAt,
			RequiresAuth:   pkg.RequiresAuth,
			AuthProvider:   pkg.AuthProvider,
		}

		// Upsert package: first try to update, if no rows affected then create
		result := tx.Model(&PackageModel{}).
			Where("registry_id = ? AND name = ? AND version = ?", registryID, pkg.Name, pkg.Version).
			Updates(model)

		if result.Error != nil {
			return errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to update package")
		}

		// If no rows were updated, create new record
		if result.RowsAffected == 0 {
			if err := tx.Create(model).Error; err != nil {
				return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create package")
			}
		}

		// Save metadata if present
		if len(pkg.Metadata) > 0 {
			// Convert map[string]string to map[string]interface{} for JSONB
			metadataMap := make(map[string]interface{}, len(pkg.Metadata))
			for k, v := range pkg.Metadata {
				metadataMap[k] = v
			}

			metadata := &PackageMetadataModel{
				PackageID:   model.ID,
				RawMetadata: JSONBField(metadataMap),
			}

			// Extract common fields from map[string]string
			if author, ok := pkg.Metadata["author"]; ok {
				metadata.Author = author
			}
			if license, ok := pkg.Metadata["license"]; ok {
				metadata.License = license
			}
			if homepage, ok := pkg.Metadata["homepage"]; ok {
				metadata.Homepage = homepage
			}
			if repo, ok := pkg.Metadata["repository"]; ok {
				metadata.Repository = repo
			}
			if desc, ok := pkg.Metadata["description"]; ok {
				metadata.Description = desc
			}

			if err := tx.Save(metadata).Error; err != nil {
				return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save metadata")
			}
		}

		return nil
	})
}

// GetPackage retrieves a package by registry, name, and version
func (s *GORMStoreV2) GetPackage(ctx context.Context, registry, name, version string) (*metadata.Package, error) {
	registryID, err := s.getRegistryID(registry)
	if err != nil {
		return nil, err
	}

	var model PackageModel
	result := s.db.WithContext(ctx).
		Preload("Metadata").
		Where("registry_id = ? AND name = ? AND version = ?", registryID, name, version).
		First(&model)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeNotFound, fmt.Sprintf("package not found: %s/%s@%s", registry, name, version))
		}
		return nil, errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to get package")
	}

	return s.modelToPackage(&model, registry), nil
}

// modelToPackage converts PackageModel to metadata.Package
func (s *GORMStoreV2) modelToPackage(model *PackageModel, registryName string) *metadata.Package {
	pkg := &metadata.Package{
		ID:              fmt.Sprintf("%d", model.ID),
		Registry:        registryName,
		Name:            model.Name,
		Version:         model.Version,
		StorageKey:      model.StorageKey,
		Size:            model.Size,
		ChecksumMD5:     model.ChecksumMD5,
		ChecksumSHA256:  model.ChecksumSHA256,
		UpstreamURL:     model.UpstreamURL,
		CachedAt:        model.CachedAt,
		LastAccessed:    model.LastAccessed,
		ExpiresAt:       model.ExpiresAt,
		DownloadCount:   model.AccessCount,
		SecurityScanned: model.SecurityScanned,
		RequiresAuth:    model.RequiresAuth,
		AuthProvider:    model.AuthProvider,
	}

	// Add metadata if present
	if model.Metadata != nil {
		pkg.Metadata = make(map[string]string)
		for k, v := range model.Metadata.RawMetadata {
			// Convert interface{} values to strings
			if str, ok := v.(string); ok {
				pkg.Metadata[k] = str
			} else {
				// For non-string values, convert to string representation
				pkg.Metadata[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	return pkg
}

// DeletePackage deletes a package (soft delete)
func (s *GORMStoreV2) DeletePackage(ctx context.Context, registry, name, version string) error {
	registryID, err := s.getRegistryID(registry)
	if err != nil {
		return err
	}

	result := s.db.WithContext(ctx).
		Where("registry_id = ? AND name = ? AND version = ?", registryID, name, version).
		Delete(&PackageModel{})

	if result.Error != nil {
		return errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to delete package")
	}

	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, fmt.Sprintf("package not found: %s/%s@%s", registry, name, version))
	}

	return nil
}

// ListPackages returns packages matching the filter
func (s *GORMStoreV2) ListPackages(ctx context.Context, opts *metadata.ListOptions) ([]*metadata.Package, error) {
	if opts == nil {
		opts = &metadata.ListOptions{}
	}

	query := s.db.WithContext(ctx).Model(&PackageModel{})

	// Apply filters
	if opts.Registry != "" {
		registryID, err := s.getRegistryID(opts.Registry)
		if err != nil {
			return nil, err
		}
		query = query.Where("registry_id = ?", registryID)
	}

	if opts.NamePrefix != "" {
		query = query.Where("name LIKE ?", opts.NamePrefix+"%")
	}

	if opts.ScannedOnly {
		query = query.Where("security_scanned = ?", true)
	}

	if !opts.SinceDate.IsZero() {
		query = query.Where("cached_at >= ?", opts.SinceDate)
	}

	if opts.MinSize > 0 {
		query = query.Where("size >= ?", opts.MinSize)
	}

	if opts.MaxSize > 0 {
		query = query.Where("size <= ?", opts.MaxSize)
	}

	// Apply pagination
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}

	// Order by
	if opts.SortBy != "" {
		order := opts.SortBy
		if opts.SortDesc {
			order += " DESC"
		} else {
			order += " ASC"
		}
		query = query.Order(order)
	} else {
		query = query.Order("access_count DESC")
	}

	var models []PackageModel
	if err := query.Find(&models).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list packages")
	}

	// Convert to metadata.Package
	packages := make([]*metadata.Package, len(models))
	for i, model := range models {
		// Get registry name from cache
		var regName string
		for name, id := range s.registryCache {
			if id == model.RegistryID {
				regName = name
				break
			}
		}
		packages[i] = s.modelToPackage(&model, regName)
	}

	return packages, nil
}

// UpdateDownloadCount increments download count and records event
func (s *GORMStoreV2) UpdateDownloadCount(ctx context.Context, registry, name, version string) error {
	registryID, err := s.getRegistryID(registry)
	if err != nil {
		return err
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Find package
		var pkg PackageModel
		if err := tx.Where("registry_id = ? AND name = ? AND version = ?", registryID, name, version).
			First(&pkg).Error; err != nil {
			return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to find package")
		}

		// Update access count and last accessed
		if err := tx.Model(&pkg).Updates(map[string]interface{}{
			"access_count":  gorm.Expr("access_count + 1"),
			"last_accessed": time.Now(),
		}).Error; err != nil {
			return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to update download count")
		}

		// Record download event
		event := &DownloadEventModel{
			PackageID:    pkg.ID,
			RegistryID:   registryID,
			DownloadedAt: time.Now(),
		}

		if err := tx.Create(event).Error; err != nil {
			return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to record download event")
		}

		return nil
	})
}

// Count returns total number of packages
func (s *GORMStoreV2) Count(ctx context.Context) (int, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&PackageModel{}).Count(&count).Error; err != nil {
		return 0, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to count packages")
	}
	return int(count), nil
}

// GetStats returns aggregated statistics for a registry (or all if registry is empty)
func (s *GORMStoreV2) GetStats(ctx context.Context, registry string) (*metadata.Stats, error) {
	stats := &metadata.Stats{
		Registry:    registry,
		LastUpdated: time.Now(),
	}

	query := s.db.WithContext(ctx).Model(&PackageModel{})

	// Filter out metadata entries (npm metadata pages, pypi pages, etc.)
	query = query.Where("version NOT IN (?)", []string{"list", "latest", "metadata", "page"})

	// Filter by registry if specified
	if registry != "" {
		registryID, err := s.getRegistryID(registry)
		if err != nil {
			return nil, err
		}
		query = query.Where("registry_id = ?", registryID)
	}

	// Total packages
	if err := query.Count(&stats.TotalPackages).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to count packages")
	}

	// Total size, downloads, scanned, vulnerable, and severity breakdown
	var result struct {
		TotalSize               int64
		TotalDownloads          int64
		ScannedPackages         int64
		VulnerablePackages      int64
		CriticalVulnerabilities int64
		HighVulnerabilities     int64
		ModerateVulnerabilities int64
		LowVulnerabilities      int64
	}

	err := query.
		Select(`
			COALESCE(SUM(size), 0) as total_size,
			COALESCE(SUM(access_count), 0) as total_downloads,
			COALESCE(SUM(CASE WHEN security_scanned THEN 1 ELSE 0 END), 0) as scanned_packages,
			COALESCE(SUM(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END), 0) as vulnerable_packages,
			COALESCE(SUM(CASE WHEN highest_severity = 'critical' THEN 1 ELSE 0 END), 0) as critical_vulnerabilities,
			COALESCE(SUM(CASE WHEN highest_severity = 'high' THEN 1 ELSE 0 END), 0) as high_vulnerabilities,
			COALESCE(SUM(CASE WHEN highest_severity = 'medium' THEN 1 ELSE 0 END), 0) as moderate_vulnerabilities,
			COALESCE(SUM(CASE WHEN highest_severity = 'low' THEN 1 ELSE 0 END), 0) as low_vulnerabilities
		`).
		Scan(&result).Error

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to aggregate stats")
	}

	stats.TotalSize = result.TotalSize
	stats.TotalDownloads = result.TotalDownloads
	stats.ScannedPackages = result.ScannedPackages
	stats.VulnerablePackages = result.VulnerablePackages
	stats.CriticalVulnerabilities = result.CriticalVulnerabilities
	stats.HighVulnerabilities = result.HighVulnerabilities
	stats.ModerateVulnerabilities = result.ModerateVulnerabilities
	stats.LowVulnerabilities = result.LowVulnerabilities

	return stats, nil
}

// Health checks database connectivity
func (s *GORMStoreV2) Health(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get sql.DB")
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "database ping failed")
	}

	return nil
}

// Close closes the database connection
func (s *GORMStoreV2) Close() error {
	// Stop aggregation worker
	if s.aggregationWorker != nil {
		s.aggregationWorker.Stop()
	}

	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetTimeSeriesStats returns time-series download statistics
func (s *GORMStoreV2) GetTimeSeriesStats(ctx context.Context, period string, registry string) (*metadata.TimeSeriesStats, error) {
	stats := &metadata.TimeSeriesStats{
		Period:     period,
		Registry:   registry,
		DataPoints: make([]*metadata.TimeSeriesDataPoint, 0),
	}

	// Determine which table to query based on period
	var tableName string
	var since time.Time

	switch period {
	case "1h":
		tableName = "download_stats_hourly"
		since = time.Now().Add(-1 * time.Hour)
	case "1day":
		tableName = "download_stats_hourly"
		since = time.Now().Add(-24 * time.Hour)
	case "7day":
		tableName = "download_stats_daily"
		since = time.Now().Add(-7 * 24 * time.Hour)
	case "30day":
		tableName = "download_stats_daily"
		since = time.Now().Add(-30 * 24 * time.Hour)
	default:
		tableName = "download_stats_hourly"
		since = time.Now().Add(-24 * time.Hour)
	}

	query := s.db.WithContext(ctx).
		Table(tableName).
		Select("time_bucket as timestamp, download_count as value").
		Where("time_bucket >= ?", since)

	// Filter by registry if specified
	if registry != "" {
		registryID, err := s.getRegistryID(registry)
		if err != nil {
			return nil, err
		}
		query = query.Where("registry_id = ? AND package_id IS NULL", registryID)
	} else {
		query = query.Where("package_id IS NULL")
	}

	query = query.Order("time_bucket ASC")

	type Result struct {
		Timestamp time.Time
		Value     int64
	}

	var results []Result
	if err := query.Scan(&results).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get time series stats")
	}

	for _, r := range results {
		stats.DataPoints = append(stats.DataPoints, &metadata.TimeSeriesDataPoint{
			Timestamp: r.Timestamp,
			Value:     r.Value,
		})
	}

	return stats, nil
}

// AggregateDownloadData aggregates raw download events into hourly/daily stats
func (s *GORMStoreV2) AggregateDownloadData(ctx context.Context) error {
	if s.aggregationWorker == nil {
		return errors.New(errors.ErrCodeStorageFailure, "aggregation worker not initialized")
	}

	// Run hourly aggregation
	if err := s.aggregationWorker.AggregateHourly(); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to aggregate hourly data")
	}

	// Run daily aggregation
	if err := s.aggregationWorker.AggregateDaily(); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to aggregate daily data")
	}

	return nil
}

// SaveScanResult saves a security scan result
func (s *GORMStoreV2) SaveScanResult(ctx context.Context, result *metadata.ScanResult) error {
	// Get package by registry, name, version
	registryID, err := s.getRegistryID(result.Registry)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "registry not found")
	}

	var pkg PackageModel
	if err := s.db.WithContext(ctx).
		Where("registry_id = ? AND name = ? AND version = ?", registryID, result.PackageName, result.PackageVersion).
		First(&pkg).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.New(errors.ErrCodeNotFound, "package not found")
		}
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to find package")
	}

	// Count vulnerabilities by severity
	var criticalCount, highCount, mediumCount, lowCount int
	for _, vuln := range result.Vulnerabilities {
		severity := metadata.NormalizeSeverity(vuln.Severity)
		switch severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MODERATE":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	// Prepare Details field - merge scanner details with vulnerabilities
	details := make(map[string]interface{})
	if result.Details != nil {
		for k, v := range result.Details {
			details[k] = v
		}
	}
	// Store vulnerabilities array for later retrieval
	details["vulnerabilities"] = result.Vulnerabilities

	// Create scan result model
	scanModel := &ScanResultModel{
		PackageID:     pkg.ID,
		Scanner:       result.Scanner,
		ScannedAt:     result.ScannedAt,
		Status:        string(result.Status),
		VulnCount:     result.VulnerabilityCount,
		CriticalCount: criticalCount,
		HighCount:     highCount,
		MediumCount:   mediumCount,
		LowCount:      lowCount,
		Details:       JSONBField(details),
	}

	if err := s.db.WithContext(ctx).Create(scanModel).Error; err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to save scan result")
	}

	// Update package security fields
	highestSeverity := "none"
	if criticalCount > 0 {
		highestSeverity = "critical"
	} else if highCount > 0 {
		highestSeverity = "high"
	} else if mediumCount > 0 {
		highestSeverity = "medium"
	} else if lowCount > 0 {
		highestSeverity = "low"
	}

	now := time.Now()
	updates := map[string]interface{}{
		"security_scanned":    true,
		"last_scanned_at":     now,
		"vulnerability_count": result.VulnerabilityCount,
		"highest_severity":    highestSeverity,
		"critical_count":      criticalCount,
		"high_count":          highCount,
		"moderate_count":      mediumCount,
		"low_count":           lowCount,
	}

	if err := s.db.WithContext(ctx).Model(&PackageModel{}).
		Where("id = ?", pkg.ID).
		Updates(updates).Error; err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to update package security fields")
	}

	return nil
}

// GetScanResult retrieves the latest security scan result for a package
func (s *GORMStoreV2) GetScanResult(ctx context.Context, registry, name, version string) (*metadata.ScanResult, error) {
	// Get package by registry, name, version
	registryID, err := s.getRegistryID(registry)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "registry not found")
	}

	var pkg PackageModel
	if err := s.db.WithContext(ctx).
		Where("registry_id = ? AND name = ? AND version = ?", registryID, name, version).
		First(&pkg).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeNotFound, "package not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to find package")
	}

	// Get latest scan result for this package
	var scanModel ScanResultModel
	if err := s.db.WithContext(ctx).
		Where("package_id = ?", pkg.ID).
		Order("scanned_at DESC").
		First(&scanModel).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New(errors.ErrCodeNotFound, "scan result not found")
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to retrieve scan result")
	}

	// Extract vulnerabilities from Details
	var vulnerabilities []metadata.Vulnerability
	if vulnData, ok := scanModel.Details["vulnerabilities"]; ok {
		// The vulnerabilities are stored as []interface{} after JSON unmarshaling
		if vulnArray, ok := vulnData.([]interface{}); ok {
			for _, v := range vulnArray {
				if vulnMap, ok := v.(map[string]interface{}); ok {
					vuln := metadata.Vulnerability{
						ID:          getStringFromMap(vulnMap, "id"),
						Severity:    getStringFromMap(vulnMap, "severity"),
						Title:       getStringFromMap(vulnMap, "title"),
						Description: getStringFromMap(vulnMap, "description"),
						FixedIn:     getStringFromMap(vulnMap, "fixed_in"),
					}
					// Extract references array
					if refs, ok := vulnMap["references"].([]interface{}); ok {
						for _, ref := range refs {
							if refStr, ok := ref.(string); ok {
								vuln.References = append(vuln.References, refStr)
							}
						}
					}
					// Extract detected_by array
					if detectedBy, ok := vulnMap["detected_by"].([]interface{}); ok {
						for _, db := range detectedBy {
							if dbStr, ok := db.(string); ok {
								vuln.DetectedBy = append(vuln.DetectedBy, dbStr)
							}
						}
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}

	// Convert to metadata.ScanResult
	result := &metadata.ScanResult{
		ID:                 fmt.Sprintf("%d", scanModel.ID),
		Registry:           registry,
		PackageName:        name,
		PackageVersion:     version,
		Scanner:            scanModel.Scanner,
		Status:             metadata.ScanStatus(scanModel.Status),
		ScannedAt:          scanModel.ScannedAt,
		VulnerabilityCount: scanModel.VulnCount,
		Details:            map[string]interface{}(scanModel.Details),
		Vulnerabilities:    vulnerabilities,
	}

	return result, nil
}

// SaveCVEBypass saves a CVE bypass
func (s *GORMStoreV2) SaveCVEBypass(ctx context.Context, bypass *metadata.CVEBypass) error {
	// Convert metadata.CVEBypass to CVEBypassModel
	model := &CVEBypassModel{
		Type:           string(bypass.Type),
		Target:         bypass.Target,
		Reason:         bypass.Reason,
		CreatedBy:      bypass.CreatedBy,
		ExpiresAt:      bypass.ExpiresAt,
		NotifyOnExpiry: bypass.NotifyOnExpiry,
		Active:         bypass.Active,
	}

	// If ID is provided, try to update existing bypass
	if bypass.ID != "" {
		id, err := strconv.ParseInt(bypass.ID, 10, 64)
		if err == nil {
			model.ID = id
			if err := s.db.WithContext(ctx).Save(model).Error; err != nil {
				return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to update CVE bypass")
			}
			return nil
		}
	}

	// Create new bypass
	if err := s.db.WithContext(ctx).Create(model).Error; err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create CVE bypass")
	}

	// Update the ID in the passed bypass
	bypass.ID = fmt.Sprintf("%d", model.ID)
	bypass.CreatedAt = model.CreatedAt

	return nil
}

// GetActiveCVEBypasses retrieves all active (non-expired) CVE bypasses
func (s *GORMStoreV2) GetActiveCVEBypasses(ctx context.Context) ([]*metadata.CVEBypass, error) {
	var models []CVEBypassModel

	now := time.Now()
	if err := s.db.WithContext(ctx).
		Where("active = ? AND expires_at > ?", true, now).
		Find(&models).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to retrieve active CVE bypasses")
	}

	// Convert models to metadata.CVEBypass
	bypasses := make([]*metadata.CVEBypass, len(models))
	for i, model := range models {
		bypasses[i] = &metadata.CVEBypass{
			ID:             fmt.Sprintf("%d", model.ID),
			Type:           metadata.BypassType(model.Type),
			Target:         model.Target,
			Reason:         model.Reason,
			CreatedBy:      model.CreatedBy,
			CreatedAt:      model.CreatedAt,
			ExpiresAt:      model.ExpiresAt,
			NotifyOnExpiry: model.NotifyOnExpiry,
			Active:         model.Active,
		}
	}

	return bypasses, nil
}

// ListCVEBypasses lists CVE bypasses with filtering options
func (s *GORMStoreV2) ListCVEBypasses(ctx context.Context, opts *metadata.BypassListOptions) ([]*metadata.CVEBypass, error) {
	query := s.db.WithContext(ctx).Model(&CVEBypassModel{})

	// Apply filters if options provided
	if opts != nil {
		// Filter by type
		if opts.Type != "" {
			query = query.Where("type = ?", string(opts.Type))
		}

		// Filter by active status
		if opts.ActiveOnly {
			query = query.Where("active = ?", true)
		}

		// Filter expired/non-expired
		if !opts.IncludeExpired {
			query = query.Where("expires_at > ?", time.Now())
		}

		// Pagination
		if opts.Limit > 0 {
			query = query.Limit(opts.Limit)
		}
		if opts.Offset > 0 {
			query = query.Offset(opts.Offset)
		}
	}

	// Order by created_at descending (newest first)
	query = query.Order("created_at DESC")

	var models []CVEBypassModel
	if err := query.Find(&models).Error; err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list CVE bypasses")
	}

	// Convert models to metadata.CVEBypass
	bypasses := make([]*metadata.CVEBypass, len(models))
	for i, model := range models {
		bypasses[i] = &metadata.CVEBypass{
			ID:             fmt.Sprintf("%d", model.ID),
			Type:           metadata.BypassType(model.Type),
			Target:         model.Target,
			Reason:         model.Reason,
			CreatedBy:      model.CreatedBy,
			CreatedAt:      model.CreatedAt,
			ExpiresAt:      model.ExpiresAt,
			NotifyOnExpiry: model.NotifyOnExpiry,
			Active:         model.Active,
		}
	}

	return bypasses, nil
}

// DeleteCVEBypass deletes a CVE bypass by ID (soft delete)
func (s *GORMStoreV2) DeleteCVEBypass(ctx context.Context, id string) error {
	// Parse ID
	bypassID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return errors.New(errors.ErrCodeBadRequest, "invalid bypass ID")
	}

	// Soft delete the bypass
	result := s.db.WithContext(ctx).Delete(&CVEBypassModel{}, bypassID)
	if result.Error != nil {
		return errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to delete CVE bypass")
	}

	if result.RowsAffected == 0 {
		return errors.New(errors.ErrCodeNotFound, "CVE bypass not found")
	}

	return nil
}

// CleanupExpiredBypasses removes expired CVE bypasses
func (s *GORMStoreV2) CleanupExpiredBypasses(ctx context.Context) (int, error) {
	now := time.Now()

	// Hard delete expired bypasses (bypass soft delete with Unscoped)
	result := s.db.WithContext(ctx).
		Unscoped().
		Where("expires_at <= ?", now).
		Delete(&CVEBypassModel{})

	if result.Error != nil {
		return 0, errors.Wrap(result.Error, errors.ErrCodeStorageFailure, "failed to cleanup expired CVE bypasses")
	}

	return int(result.RowsAffected), nil
}
