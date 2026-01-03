package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockStorageBackend is a mock for storage.StorageBackend
type MockStorageBackend struct {
	mock.Mock
}

func (m *MockStorageBackend) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockStorageBackend) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	args := m.Called(ctx, key, data, opts)
	return args.Error(0)
}

func (m *MockStorageBackend) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockStorageBackend) Exists(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorageBackend) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	args := m.Called(ctx, prefix, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]storage.StorageObject), args.Error(1)
}

func (m *MockStorageBackend) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.StorageInfo), args.Error(1)
}

func (m *MockStorageBackend) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.QuotaInfo), args.Error(1)
}

func (m *MockStorageBackend) Health(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockStorageBackend) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockMetadataStore is a mock for metadata.MetadataStore
type MockMetadataStore struct {
	mock.Mock
}

func (m *MockMetadataStore) SavePackage(ctx context.Context, pkg *metadata.Package) error {
	args := m.Called(ctx, pkg)
	return args.Error(0)
}

func (m *MockMetadataStore) GetPackage(ctx context.Context, registry, name, version string) (*metadata.Package, error) {
	args := m.Called(ctx, registry, name, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*metadata.Package), args.Error(1)
}

func (m *MockMetadataStore) DeletePackage(ctx context.Context, registry, name, version string) error {
	args := m.Called(ctx, registry, name, version)
	return args.Error(0)
}

func (m *MockMetadataStore) ListPackages(ctx context.Context, opts *metadata.ListOptions) ([]*metadata.Package, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*metadata.Package), args.Error(1)
}

func (m *MockMetadataStore) UpdateDownloadCount(ctx context.Context, registry, name, version string) error {
	args := m.Called(ctx, registry, name, version)
	return args.Error(0)
}

func (m *MockMetadataStore) GetStats(ctx context.Context, registry string) (*metadata.Stats, error) {
	args := m.Called(ctx, registry)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*metadata.Stats), args.Error(1)
}

func (m *MockMetadataStore) SaveScanResult(ctx context.Context, result *metadata.ScanResult) error {
	args := m.Called(ctx, result)
	return args.Error(0)
}

func (m *MockMetadataStore) GetScanResult(ctx context.Context, registry, name, version string) (*metadata.ScanResult, error) {
	args := m.Called(ctx, registry, name, version)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*metadata.ScanResult), args.Error(1)
}

func (m *MockMetadataStore) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockMetadataStore) Health(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockMetadataStore) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockMetadataStore) SaveCVEBypass(ctx context.Context, bypass *metadata.CVEBypass) error {
	args := m.Called(ctx, bypass)
	return args.Error(0)
}

func (m *MockMetadataStore) GetActiveCVEBypasses(ctx context.Context) ([]*metadata.CVEBypass, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*metadata.CVEBypass), args.Error(1)
}

func (m *MockMetadataStore) ListCVEBypasses(ctx context.Context, opts *metadata.BypassListOptions) ([]*metadata.CVEBypass, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*metadata.CVEBypass), args.Error(1)
}

func (m *MockMetadataStore) DeleteCVEBypass(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockMetadataStore) CleanupExpiredBypasses(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockMetadataStore) GetTimeSeriesStats(ctx context.Context, period string, registry string) (*metadata.TimeSeriesStats, error) {
	args := m.Called(ctx, period, registry)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*metadata.TimeSeriesStats), args.Error(1)
}

func (m *MockMetadataStore) AggregateDownloadData(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// TestNew tests cache manager creation
func TestNew(t *testing.T) {
	tests := []struct {
		storage     storage.StorageBackend
		metadata    metadata.MetadataStore
		name        string
		errContains string
		config      Config
		wantErr     bool
	}{
		// GOOD: Valid configuration
		{
			name:     "valid config with defaults",
			storage:  &MockStorageBackend{},
			metadata: &MockMetadataStore{},
			config:   Config{},
			wantErr:  false,
		},
		{
			name:     "valid config with custom settings",
			storage:  &MockStorageBackend{},
			metadata: &MockMetadataStore{},
			config: Config{
				DefaultTTL:        24 * time.Hour,
				CleanupInterval:   30 * time.Minute,
				EvictionThreshold: 0.8,
				MaxConcurrent:     50,
			},
			wantErr: false,
		},
		// WRONG: Missing required components
		{
			name:        "nil storage",
			storage:     nil,
			metadata:    &MockMetadataStore{},
			config:      Config{},
			wantErr:     true,
			errContains: "storage backend is required",
		},
		{
			name:        "nil metadata",
			storage:     &MockStorageBackend{},
			metadata:    nil,
			config:      Config{},
			wantErr:     true,
			errContains: "metadata store is required",
		},
		// EDGE: Both nil
		{
			name:        "both nil",
			storage:     nil,
			metadata:    nil,
			config:      Config{},
			wantErr:     true,
			errContains: "storage backend is required",
		},
		// EDGE: Zero values get defaults
		{
			name:     "zero config gets defaults",
			storage:  &MockStorageBackend{},
			metadata: &MockMetadataStore{},
			config:   Config{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := New(tt.storage, tt.metadata, nil, nil, tt.config)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, manager)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manager)

				// Verify defaults were set
				if tt.config.DefaultTTL == 0 {
					assert.Equal(t, 7*24*time.Hour, manager.config.DefaultTTL)
				}
				if tt.config.CleanupInterval == 0 {
					assert.Equal(t, 1*time.Hour, manager.config.CleanupInterval)
				}
				if tt.config.EvictionThreshold == 0 {
					assert.Equal(t, 0.9, manager.config.EvictionThreshold)
				}
				if tt.config.MaxConcurrent == 0 {
					assert.Equal(t, 100, manager.config.MaxConcurrent)
				}
			}
		})
	}
}

// TestGet tests cache retrieval with various scenarios
func TestGet(t *testing.T) {
	tests := []struct {
		setupMock     func(*MockStorageBackend, *MockMetadataStore)
		fetchFunc     func(context.Context) (io.ReadCloser, string, error)
		name          string
		registry      string
		packageName   string
		version       string
		errContains   string
		wantFromCache bool
		wantErr       bool
	}{
		// GOOD: Cache hit
		{
			name:        "cache hit - package exists and valid",
			registry:    "npm",
			packageName: "react",
			version:     "18.2.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				now := time.Now()
				expiresAt := now.Add(24 * time.Hour)
				pkg := &metadata.Package{
					ID:           "test-id",
					Registry:     "npm",
					Name:         "react",
					Version:      "18.2.0",
					StorageKey:   "npm/react/18.2.0",
					CachedAt:     now,
					LastAccessed: now,
					ExpiresAt:    &expiresAt,
				}
				m.On("GetPackage", mock.Anything, "npm", "react", "18.2.0").Return(pkg, nil)
				s.On("Get", mock.Anything, "npm/react/18.2.0").Return(io.NopCloser(strings.NewReader("cached data")), nil)
				m.On("UpdateDownloadCount", mock.Anything, "npm", "react", "18.2.0").Return(nil)
			},
			wantFromCache: true,
			wantErr:       false,
		},
		// GOOD: Cache miss - fetch from upstream
		{
			name:        "cache miss - fetch from upstream",
			registry:    "npm",
			packageName: "lodash",
			version:     "4.17.21",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("GetPackage", mock.Anything, "npm", "lodash", "4.17.21").Return(nil, errors.New("not found"))
				s.On("GetQuota", mock.Anything).Return(&storage.QuotaInfo{Used: 100, Available: 900, Limit: 1000}, nil)
				s.On("Put", mock.Anything, "npm/lodash/4.17.21", mock.Anything, mock.Anything).Return(nil)
				m.On("SavePackage", mock.Anything, mock.Anything).Return(nil)
				s.On("Get", mock.Anything, "npm/lodash/4.17.21").Return(io.NopCloser(strings.NewReader("upstream data")), nil)
			},
			fetchFunc: func(ctx context.Context) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader("upstream data")), "https://registry.npmjs.org/lodash", nil
			},
			wantFromCache: false,
			wantErr:       false,
		},
		// WRONG: Expired package
		{
			name:        "expired package - re-fetch",
			registry:    "npm",
			packageName: "expired-pkg",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				now := time.Now()
				expiresAt := now.Add(-1 * time.Hour) // Expired 1 hour ago
				pkg := &metadata.Package{
					ID:         "test-id",
					Registry:   "npm",
					Name:       "expired-pkg",
					Version:    "1.0.0",
					StorageKey: "npm/expired-pkg/1.0.0",
					ExpiresAt:  &expiresAt,
				}
				m.On("GetPackage", mock.Anything, "npm", "expired-pkg", "1.0.0").Return(pkg, nil)
				m.On("DeletePackage", mock.Anything, "npm", "expired-pkg", "1.0.0").Return(nil)
				s.On("Delete", mock.Anything, "npm/expired-pkg/1.0.0").Return(nil)
				s.On("GetQuota", mock.Anything).Return(&storage.QuotaInfo{Used: 100, Available: 900, Limit: 1000}, nil)
				s.On("Put", mock.Anything, "npm/expired-pkg/1.0.0", mock.Anything, mock.Anything).Return(nil)
				m.On("SavePackage", mock.Anything, mock.Anything).Return(nil)
				s.On("Get", mock.Anything, "npm/expired-pkg/1.0.0").Return(io.NopCloser(strings.NewReader("refreshed data")), nil)
			},
			fetchFunc: func(ctx context.Context) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader("refreshed data")), "https://registry.npmjs.org/expired-pkg", nil
			},
			wantFromCache: false,
			wantErr:       false,
		},
		// BAD: Fetch function is nil and package not cached
		{
			name:        "nil fetch function and not cached",
			registry:    "npm",
			packageName: "missing",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("GetPackage", mock.Anything, "npm", "missing", "1.0.0").Return(nil, errors.New("not found"))
			},
			fetchFunc:   nil,
			wantErr:     true,
			errContains: "package not found and no fetch function provided",
		},
		// BAD: Upstream fetch fails
		{
			name:        "upstream fetch error",
			registry:    "npm",
			packageName: "fail-pkg",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("GetPackage", mock.Anything, "npm", "fail-pkg", "1.0.0").Return(nil, errors.New("not found"))
			},
			fetchFunc: func(ctx context.Context) (io.ReadCloser, string, error) {
				return nil, "", errors.New("upstream error")
			},
			wantErr:     true,
			errContains: "failed to fetch from upstream",
		},
		// EDGE: Metadata exists but storage missing
		{
			name:        "metadata exists but storage missing - inconsistency",
			registry:    "npm",
			packageName: "inconsistent",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				now := time.Now()
				expiresAt := now.Add(24 * time.Hour)
				pkg := &metadata.Package{
					ID:         "test-id",
					Registry:   "npm",
					Name:       "inconsistent",
					Version:    "1.0.0",
					StorageKey: "npm/inconsistent/1.0.0",
					ExpiresAt:  &expiresAt,
				}
				m.On("GetPackage", mock.Anything, "npm", "inconsistent", "1.0.0").Return(pkg, nil)
				// First Get fails (storage missing)
				s.On("Get", mock.Anything, "npm/inconsistent/1.0.0").Return(nil, errors.New("not found")).Once()
				m.On("DeletePackage", mock.Anything, "npm", "inconsistent", "1.0.0").Return(nil)
				s.On("GetQuota", mock.Anything).Return(&storage.QuotaInfo{Used: 100, Available: 900, Limit: 1000}, nil)
				s.On("Put", mock.Anything, "npm/inconsistent/1.0.0", mock.Anything, mock.Anything).Return(nil)
				m.On("SavePackage", mock.Anything, mock.Anything).Return(nil)
				// Second Get succeeds (after re-storing)
				s.On("Get", mock.Anything, "npm/inconsistent/1.0.0").Return(io.NopCloser(strings.NewReader("recovered data")), nil).Once()
			},
			fetchFunc: func(ctx context.Context) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader("recovered data")), "https://registry.npmjs.org/inconsistent", nil
			},
			wantFromCache: false,
			wantErr:       false,
		},
		// EDGE: Storage save fails
		{
			name:        "storage save fails",
			registry:    "npm",
			packageName: "save-fail",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("GetPackage", mock.Anything, "npm", "save-fail", "1.0.0").Return(nil, errors.New("not found"))
				s.On("GetQuota", mock.Anything).Return(&storage.QuotaInfo{Used: 100, Available: 900, Limit: 1000}, nil)
				s.On("Put", mock.Anything, "npm/save-fail/1.0.0", mock.Anything, mock.Anything).Return(errors.New("storage error"))
			},
			fetchFunc: func(ctx context.Context) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader("data")), "https://registry.npmjs.org/save-fail", nil
			},
			wantErr:     true,
			errContains: "storage error",
		},
		// EDGE: Metadata save fails (should cleanup storage)
		{
			name:        "metadata save fails - storage cleanup",
			registry:    "npm",
			packageName: "meta-fail",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("GetPackage", mock.Anything, "npm", "meta-fail", "1.0.0").Return(nil, errors.New("not found"))
				s.On("GetQuota", mock.Anything).Return(&storage.QuotaInfo{Used: 100, Available: 900, Limit: 1000}, nil)
				s.On("Put", mock.Anything, "npm/meta-fail/1.0.0", mock.Anything, mock.Anything).Return(nil)
				m.On("SavePackage", mock.Anything, mock.Anything).Return(errors.New("metadata error"))
				s.On("Delete", mock.Anything, "npm/meta-fail/1.0.0").Return(nil)
			},
			fetchFunc: func(ctx context.Context) (io.ReadCloser, string, error) {
				return io.NopCloser(strings.NewReader("data")), "https://registry.npmjs.org/meta-fail", nil
			},
			wantErr:     true,
			errContains: "metadata error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorageBackend{}
			mockMetadata := &MockMetadataStore{}

			if tt.setupMock != nil {
				tt.setupMock(mockStorage, mockMetadata)
			}

			manager, err := New(mockStorage, mockMetadata, nil, nil, Config{
				DefaultTTL:      24 * time.Hour,
				CleanupInterval: 1 * time.Hour,
			})
			require.NoError(t, err)

			ctx := context.Background()
			entry, err := manager.Get(ctx, tt.registry, tt.packageName, tt.version, tt.fetchFunc)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, entry)
			} else {
				require.NoError(t, err)
				require.NotNil(t, entry)
				assert.Equal(t, tt.wantFromCache, entry.FromCache)
				assert.NotNil(t, entry.Data)
				// Read and verify data exists
				data, _ := io.ReadAll(entry.Data)
				assert.NotEmpty(t, data)
			}

			mockStorage.AssertExpectations(t)
			mockMetadata.AssertExpectations(t)
		})
	}
}

// TestDelete tests package deletion
func TestDelete(t *testing.T) {
	tests := []struct {
		setupMock   func(*MockStorageBackend, *MockMetadataStore)
		name        string
		registry    string
		packageName string
		version     string
		errContains string
		wantErr     bool
	}{
		// GOOD: Successful deletion
		{
			name:        "successful deletion",
			registry:    "npm",
			packageName: "react",
			version:     "18.2.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				pkg := &metadata.Package{
					ID:         "test-id",
					Registry:   "npm",
					Name:       "react",
					Version:    "18.2.0",
					StorageKey: "npm/react/18.2.0",
				}
				m.On("GetPackage", mock.Anything, "npm", "react", "18.2.0").Return(pkg, nil)
				s.On("Delete", mock.Anything, "npm/react/18.2.0").Return(nil)
				m.On("DeletePackage", mock.Anything, "npm", "react", "18.2.0").Return(nil)
			},
			wantErr: false,
		},
		// WRONG: Package not found
		{
			name:        "package not found",
			registry:    "npm",
			packageName: "missing",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("GetPackage", mock.Anything, "npm", "missing", "1.0.0").Return(nil, errors.New("not found"))
			},
			wantErr:     true,
			errContains: "not found",
		},
		// EDGE: Storage delete fails but metadata succeeds
		{
			name:        "storage delete fails",
			registry:    "npm",
			packageName: "storage-fail",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				pkg := &metadata.Package{
					ID:         "test-id",
					Registry:   "npm",
					Name:       "storage-fail",
					Version:    "1.0.0",
					StorageKey: "npm/storage-fail/1.0.0",
				}
				m.On("GetPackage", mock.Anything, "npm", "storage-fail", "1.0.0").Return(pkg, nil)
				s.On("Delete", mock.Anything, "npm/storage-fail/1.0.0").Return(errors.New("storage error"))
				m.On("DeletePackage", mock.Anything, "npm", "storage-fail", "1.0.0").Return(nil)
			},
			wantErr: false, // Metadata delete still succeeds
		},
		// EDGE: Metadata delete fails
		{
			name:        "metadata delete fails",
			registry:    "npm",
			packageName: "meta-fail",
			version:     "1.0.0",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				pkg := &metadata.Package{
					ID:         "test-id",
					Registry:   "npm",
					Name:       "meta-fail",
					Version:    "1.0.0",
					StorageKey: "npm/meta-fail/1.0.0",
				}
				m.On("GetPackage", mock.Anything, "npm", "meta-fail", "1.0.0").Return(pkg, nil)
				s.On("Delete", mock.Anything, "npm/meta-fail/1.0.0").Return(nil)
				m.On("DeletePackage", mock.Anything, "npm", "meta-fail", "1.0.0").Return(errors.New("metadata error"))
			},
			wantErr:     true,
			errContains: "metadata error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorageBackend{}
			mockMetadata := &MockMetadataStore{}

			if tt.setupMock != nil {
				tt.setupMock(mockStorage, mockMetadata)
			}

			manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
			require.NoError(t, err)

			ctx := context.Background()
			err = manager.Delete(ctx, tt.registry, tt.packageName, tt.version)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			mockStorage.AssertExpectations(t)
			mockMetadata.AssertExpectations(t)
		})
	}
}

// TestHealth tests health check functionality
func TestHealth(t *testing.T) {
	tests := []struct {
		setupMock   func(*MockStorageBackend, *MockMetadataStore)
		name        string
		errContains string
		wantErr     bool
	}{
		// GOOD: Both healthy
		{
			name: "both storage and metadata healthy",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Health", mock.Anything).Return(nil)
				m.On("Health", mock.Anything).Return(nil)
			},
			wantErr: false,
		},
		// WRONG: Storage unhealthy
		{
			name: "storage unhealthy",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Health", mock.Anything).Return(errors.New("storage error"))
			},
			wantErr:     true,
			errContains: "storage health check failed",
		},
		// WRONG: Metadata unhealthy
		{
			name: "metadata unhealthy",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Health", mock.Anything).Return(nil)
				m.On("Health", mock.Anything).Return(errors.New("metadata error"))
			},
			wantErr:     true,
			errContains: "metadata health check failed",
		},
		// BAD: Both unhealthy
		{
			name: "both unhealthy",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Health", mock.Anything).Return(errors.New("storage error"))
			},
			wantErr:     true,
			errContains: "storage health check failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorageBackend{}
			mockMetadata := &MockMetadataStore{}

			if tt.setupMock != nil {
				tt.setupMock(mockStorage, mockMetadata)
			}

			manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
			require.NoError(t, err)

			ctx := context.Background()
			err = manager.Health(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			mockStorage.AssertExpectations(t)
			mockMetadata.AssertExpectations(t)
		})
	}
}

// TestGetStats tests statistics retrieval
func TestGetStats(t *testing.T) {
	mockStorage := &MockStorageBackend{}
	mockMetadata := &MockMetadataStore{}

	expectedStats := &metadata.Stats{
		Registry:       "npm",
		TotalPackages:  100,
		TotalSize:      1024 * 1024 * 100,
		TotalDownloads: 5000,
	}

	mockMetadata.On("GetStats", mock.Anything, "npm").Return(expectedStats, nil)

	manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
	require.NoError(t, err)

	ctx := context.Background()
	stats, err := manager.GetStats(ctx, "npm")

	require.NoError(t, err)
	assert.Equal(t, expectedStats, stats)
	mockMetadata.AssertExpectations(t)
}

// TestClose tests manager cleanup
func TestClose(t *testing.T) {
	tests := []struct {
		setupMock func(*MockStorageBackend, *MockMetadataStore)
		name      string
		wantErr   bool
	}{
		// GOOD: Clean close
		{
			name: "both close successfully",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Close").Return(nil)
				m.On("Close").Return(nil)
			},
			wantErr: false,
		},
		// WRONG: Storage close fails
		{
			name: "storage close fails",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Close").Return(errors.New("storage error"))
				m.On("Close").Return(nil)
			},
			wantErr: true,
		},
		// WRONG: Metadata close fails
		{
			name: "metadata close fails",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Close").Return(nil)
				m.On("Close").Return(errors.New("metadata error"))
			},
			wantErr: true,
		},
		// BAD: Both close fail
		{
			name: "both close fail",
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				s.On("Close").Return(errors.New("storage error"))
				m.On("Close").Return(errors.New("metadata error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorageBackend{}
			mockMetadata := &MockMetadataStore{}

			if tt.setupMock != nil {
				tt.setupMock(mockStorage, mockMetadata)
			}

			manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
			require.NoError(t, err)

			err = manager.Close() // #nosec G104 -- Cleanup, error not critical

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockStorage.AssertExpectations(t)
			mockMetadata.AssertExpectations(t)
		})
	}
}

// TestEvict tests LRU eviction
func TestEvict(t *testing.T) {
	tests := []struct {
		setupMock   func(*MockStorageBackend, *MockMetadataStore)
		name        string
		errContains string
		needed      int64
		wantErr     bool
	}{
		// GOOD: Successful eviction
		{
			name:   "evict enough to free space",
			needed: 200,
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				packages := []*metadata.Package{
					{
						ID:         "1",
						Name:       "old-pkg-1",
						Version:    "1.0.0",
						Registry:   "npm",
						StorageKey: "npm/old-pkg-1/1.0.0",
						Size:       100,
					},
					{
						ID:         "2",
						Name:       "old-pkg-2",
						Version:    "1.0.0",
						Registry:   "npm",
						StorageKey: "npm/old-pkg-2/1.0.0",
						Size:       150,
					},
				}
				m.On("ListPackages", mock.Anything, mock.MatchedBy(func(opts *metadata.ListOptions) bool {
					return opts.SortBy == "last_accessed" && !opts.SortDesc
				})).Return(packages, nil).Once()

				s.On("Delete", mock.Anything, "npm/old-pkg-1/1.0.0").Return(nil)
				m.On("DeletePackage", mock.Anything, "npm", "old-pkg-1", "1.0.0").Return(nil)
				s.On("Delete", mock.Anything, "npm/old-pkg-2/1.0.0").Return(nil)
				m.On("DeletePackage", mock.Anything, "npm", "old-pkg-2", "1.0.0").Return(nil)
			},
			wantErr: false,
		},
		// EDGE: No packages to evict
		{
			name:   "no packages available to evict",
			needed: 100,
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("ListPackages", mock.Anything, mock.Anything).Return([]*metadata.Package{}, nil)
			},
			wantErr: false, // Doesn't error, just can't free enough
		},
		// EDGE: Eviction list error
		{
			name:   "list packages fails",
			needed: 100,
			setupMock: func(s *MockStorageBackend, m *MockMetadataStore) {
				m.On("ListPackages", mock.Anything, mock.Anything).Return(nil, errors.New("list error"))
			},
			wantErr: false, // Doesn't error, just can't complete
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockStorageBackend{}
			mockMetadata := &MockMetadataStore{}

			if tt.setupMock != nil {
				tt.setupMock(mockStorage, mockMetadata)
			}

			manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
			require.NoError(t, err)

			ctx := context.Background()
			err = manager.evict(ctx, tt.needed)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}

			mockStorage.AssertExpectations(t)
			mockMetadata.AssertExpectations(t)
		})
	}
}

// TestGenerateStorageKey tests storage key generation
func TestGenerateStorageKey(t *testing.T) {
	mockStorage := &MockStorageBackend{}
	mockMetadata := &MockMetadataStore{}

	manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
	require.NoError(t, err)

	tests := []struct {
		registry string
		name     string
		version  string
		expected string
	}{
		{"npm", "react", "18.2.0", "npm/react/18.2.0"},
		{"pypi", "requests", "2.28.0", "pypi/requests/2.28.0"},
		{"go", "github.com/gin-gonic/gin", "v1.9.0", "go/github.com/gin-gonic/gin/v1.9.0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			key := manager.generateStorageKey(tt.registry, tt.name, tt.version)
			assert.Equal(t, tt.expected, key)
		})
	}
}

// TestConcurrentGet tests concurrent access doesn't cause data races
func TestConcurrentGet(t *testing.T) {
	mockStorage := &MockStorageBackend{}
	mockMetadata := &MockMetadataStore{}

	// Setup mocks for concurrent access
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	pkg := &metadata.Package{
		ID:           "test-id",
		Registry:     "npm",
		Name:         "concurrent",
		Version:      "1.0.0",
		StorageKey:   "npm/concurrent/1.0.0",
		CachedAt:     now,
		LastAccessed: now,
		ExpiresAt:    &expiresAt,
	}

	// Use Maybe() to allow variable number of calls due to singleflight deduplication
	mockMetadata.On("GetPackage", mock.Anything, "npm", "concurrent", "1.0.0").Return(pkg, nil).Maybe()
	mockStorage.On("Get", mock.Anything, "npm/concurrent/1.0.0").Return(
		io.NopCloser(bytes.NewReader([]byte("test data"))), nil).Maybe()
	mockMetadata.On("UpdateDownloadCount", mock.Anything, "npm", "concurrent", "1.0.0").Return(nil).Maybe()

	manager, err := New(mockStorage, mockMetadata, nil, nil, Config{})
	require.NoError(t, err)

	ctx := context.Background()
	const numGoroutines = 10

	// Run concurrent gets
	errs := make(chan error, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := manager.Get(ctx, "npm", "concurrent", "1.0.0", nil)
			errs <- err
		}()
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errs
		assert.NoError(t, err)
	}

	// Verify at least one call was made (singleflight may deduplicate others)
	mockMetadata.AssertCalled(t, "GetPackage", mock.Anything, "npm", "concurrent", "1.0.0")
}
