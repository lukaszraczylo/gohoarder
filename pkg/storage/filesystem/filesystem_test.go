package filesystem

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/stretchr/testify/suite"
)

type FilesystemStorageTestSuite struct {
	suite.Suite
	fs      *FilesystemStorage
	tempDir string
}

func (s *FilesystemStorageTestSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "gohoarder-test-*")
	s.Require().NoError(err)

	s.fs, err = New(s.tempDir, 1024*1024) // 1MB quota
	s.Require().NoError(err)
}

func (s *FilesystemStorageTestSuite) TearDownTest() {
	if s.fs != nil {
		s.fs.Close() // #nosec G104 -- Cleanup, error not critical
	}
	if s.tempDir != "" {
		_ = os.RemoveAll(s.tempDir) // #nosec G104 -- Cleanup
	}
}

func TestFilesystemStorageTestSuite(t *testing.T) {
	suite.Run(t, new(FilesystemStorageTestSuite))
}

// Test Put operation
func (s *FilesystemStorageTestSuite) TestPut() {
	tests := []struct {
		opts        *storage.PutOptions
		errorCheck  func(error) bool
		name        string
		key         string
		data        string
		expectError bool
	}{
		{
			name:        "successful put",
			key:         "test/file.txt",
			data:        "hello world",
			opts:        nil,
			expectError: false,
		},
		{
			name:        "put with valid MD5 checksum",
			key:         "test/checksummed.txt",
			data:        "test data",
			opts:        &storage.PutOptions{ChecksumMD5: "eb733a00c0c9d336e65691a37ab54293"},
			expectError: false,
		},
		{
			name:        "put with invalid MD5 checksum",
			key:         "test/bad-checksum.txt",
			data:        "test data",
			opts:        &storage.PutOptions{ChecksumMD5: "invalid"},
			expectError: true,
		},
		{
			name:        "put with nested path",
			key:         "deep/nested/path/file.txt",
			data:        "nested content",
			opts:        nil,
			expectError: false,
		},
		{
			name:        "put with path traversal attempt",
			key:         "../../../etc/passwd",
			data:        "malicious",
			opts:        nil,
			expectError: false, // Should be sanitized, not error
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			ctx := context.Background()
			reader := strings.NewReader(tt.data)

			err := s.fs.Put(ctx, tt.key, reader, tt.opts)

			if tt.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
				// Verify file exists
				exists, err := s.fs.Exists(ctx, tt.key)
				s.NoError(err)
				s.True(exists)
			}
		})
	}
}

// Test Get operation
func (s *FilesystemStorageTestSuite) TestGet() {
	ctx := context.Background()

	// Setup: Put a test file
	testData := "test content for retrieval"
	err := s.fs.Put(ctx, "test/get.txt", strings.NewReader(testData), nil)
	s.Require().NoError(err)

	tests := []struct {
		name        string
		key         string
		expectData  string
		expectError bool
	}{
		{
			name:        "get existing file",
			key:         "test/get.txt",
			expectError: false,
			expectData:  testData,
		},
		{
			name:        "get non-existent file",
			key:         "does/not/exist.txt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			reader, err := s.fs.Get(ctx, tt.key)

			if tt.expectError {
				s.Error(err)
				s.Nil(reader)
			} else {
				s.NoError(err)
				s.NotNil(reader)
				defer reader.Close() // #nosec G104 -- Cleanup, error not critical

				data, err := io.ReadAll(reader)
				s.NoError(err)
				s.Equal(tt.expectData, string(data))
			}
		})
	}
}

// Test Delete operation
func (s *FilesystemStorageTestSuite) TestDelete() {
	ctx := context.Background()

	tests := []struct {
		name        string
		setupKey    string
		deleteKey   string
		expectError bool
	}{
		{
			name:        "delete existing file",
			setupKey:    "test/delete-me.txt",
			deleteKey:   "test/delete-me.txt",
			expectError: false,
		},
		{
			name:        "delete non-existent file",
			setupKey:    "",
			deleteKey:   "does/not/exist.txt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			// Setup
			if tt.setupKey != "" {
				err := s.fs.Put(ctx, tt.setupKey, strings.NewReader("to be deleted"), nil)
				s.Require().NoError(err)
			}

			// Test delete
			err := s.fs.Delete(ctx, tt.deleteKey)

			if tt.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
				// Verify file no longer exists
				exists, err := s.fs.Exists(ctx, tt.deleteKey)
				s.NoError(err)
				s.False(exists)
			}
		})
	}
}

// Test Exists operation
func (s *FilesystemStorageTestSuite) TestExists() {
	ctx := context.Background()

	// Setup: Put a test file
	err := s.fs.Put(ctx, "test/exists.txt", strings.NewReader("content"), nil)
	s.Require().NoError(err)

	tests := []struct {
		name   string
		key    string
		exists bool
	}{
		{
			name:   "existing file",
			key:    "test/exists.txt",
			exists: true,
		},
		{
			name:   "non-existent file",
			key:    "test/does-not-exist.txt",
			exists: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			exists, err := s.fs.Exists(ctx, tt.key)
			s.NoError(err)
			s.Equal(tt.exists, exists)
		})
	}
}

// Test List operation
func (s *FilesystemStorageTestSuite) TestList() {
	ctx := context.Background()

	// Setup: Create multiple files
	files := []string{
		"packages/npm/react/17.0.1/package.json",
		"packages/npm/react/17.0.2/package.json",
		"packages/npm/vue/3.0.0/package.json",
		"packages/pypi/django/3.2.0/wheel.whl",
	}

	for _, file := range files {
		err := s.fs.Put(ctx, file, strings.NewReader("content"), nil)
		s.Require().NoError(err)
	}

	tests := []struct {
		opts          *storage.ListOptions
		name          string
		prefix        string
		expectedKeys  []string
		expectedCount int
	}{
		{
			name:          "list all npm packages",
			prefix:        "packages/npm",
			opts:          nil,
			expectedCount: 3,
		},
		{
			name:          "list react packages",
			prefix:        "packages/npm/react",
			opts:          nil,
			expectedCount: 2,
		},
		{
			name:          "list with pagination",
			prefix:        "packages/npm",
			opts:          &storage.ListOptions{MaxResults: 2, Offset: 0},
			expectedCount: 2,
		},
		{
			name:          "list with offset",
			prefix:        "packages/npm",
			opts:          &storage.ListOptions{MaxResults: 2, Offset: 1},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			objects, err := s.fs.List(ctx, tt.prefix, tt.opts)
			s.NoError(err)
			s.Equal(tt.expectedCount, len(objects))

			// Verify objects have required fields
			for _, obj := range objects {
				s.NotEmpty(obj.Key)
				s.Greater(obj.Size, int64(0))
				s.False(obj.Modified.IsZero())
			}
		})
	}
}

// Test Stat operation
func (s *FilesystemStorageTestSuite) TestStat() {
	ctx := context.Background()

	// Setup: Put a test file
	testData := "stat test content"
	testKey := "test/stat.txt"
	err := s.fs.Put(ctx, testKey, strings.NewReader(testData), nil)
	s.Require().NoError(err)

	tests := []struct {
		name        string
		key         string
		expectError bool
	}{
		{
			name:        "stat existing file",
			key:         testKey,
			expectError: false,
		},
		{
			name:        "stat non-existent file",
			key:         "does/not/exist.txt",
			expectError: true,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			info, err := s.fs.Stat(ctx, tt.key)

			if tt.expectError {
				s.Error(err)
				s.Nil(info)
			} else {
				s.NoError(err)
				s.NotNil(info)
				s.Equal(tt.key, info.Key)
				s.Equal(int64(len(testData)), info.Size)
				s.False(info.Modified.IsZero())
			}
		})
	}
}

// Test Quota enforcement
func (s *FilesystemStorageTestSuite) TestQuotaEnforcement() {
	ctx := context.Background()

	// Create a new filesystem with small quota (100 bytes)
	smallQuotaDir, err := os.MkdirTemp("", "gohoarder-quota-*")
	s.Require().NoError(err)
	defer os.RemoveAll(smallQuotaDir)

	smallFs, err := New(smallQuotaDir, 100)
	s.Require().NoError(err)
	defer smallFs.Close() // #nosec G104 -- Cleanup, error not critical

	// First write should succeed
	err = smallFs.Put(ctx, "file1.txt", strings.NewReader("small content"), nil)
	s.NoError(err)

	// Large write should fail due to quota
	largeData := strings.Repeat("x", 200)
	err = smallFs.Put(ctx, "large.txt", strings.NewReader(largeData), nil)
	s.Error(err)

	// Verify quota info
	quotaInfo, err := smallFs.GetQuota(ctx)
	s.NoError(err)
	s.Equal(int64(100), quotaInfo.Limit)
	s.Greater(quotaInfo.Used, int64(0))
	s.LessOrEqual(quotaInfo.Used, quotaInfo.Limit)
}

// Test GetQuota operation
func (s *FilesystemStorageTestSuite) TestGetQuota() {
	ctx := context.Background()

	// Put some files
	err := s.fs.Put(ctx, "file1.txt", strings.NewReader("content1"), nil)
	s.Require().NoError(err)
	err = s.fs.Put(ctx, "file2.txt", strings.NewReader("content2"), nil)
	s.Require().NoError(err)

	quotaInfo, err := s.fs.GetQuota(ctx)
	s.NoError(err)
	s.NotNil(quotaInfo)
	s.Equal(int64(1024*1024), quotaInfo.Limit)
	s.Greater(quotaInfo.Used, int64(0))
	s.Greater(quotaInfo.Available, int64(0))
	s.Equal(quotaInfo.Limit, quotaInfo.Used+quotaInfo.Available)
}

// Test Health check
func (s *FilesystemStorageTestSuite) TestHealth() {
	ctx := context.Background()

	// Healthy filesystem
	err := s.fs.Health(ctx)
	s.NoError(err)

	// Unhealthy filesystem (removed directory)
	badDir := filepath.Join(s.tempDir, "nonexistent")
	badFs := &FilesystemStorage{basePath: badDir}
	err = badFs.Health(ctx)
	s.Error(err)
}

// Test Context cancellation
func (s *FilesystemStorageTestSuite) TestContextCancellation() {
	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		fn   func() error
		name string
	}{
		{
			name: "Get with cancelled context",
			fn: func() error {
				_, err := s.fs.Get(ctx, "test.txt")
				return err
			},
		},
		{
			name: "Put with cancelled context",
			fn: func() error {
				return s.fs.Put(ctx, "test.txt", strings.NewReader("data"), nil)
			},
		},
		{
			name: "Delete with cancelled context",
			fn: func() error {
				return s.fs.Delete(ctx, "test.txt")
			},
		},
		{
			name: "Exists with cancelled context",
			fn: func() error {
				_, err := s.fs.Exists(ctx, "test.txt")
				return err
			},
		},
		{
			name: "List with cancelled context",
			fn: func() error {
				_, err := s.fs.List(ctx, "test", nil)
				return err
			},
		},
		{
			name: "Stat with cancelled context",
			fn: func() error {
				_, err := s.fs.Stat(ctx, "test.txt")
				return err
			},
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			err := tt.fn()
			s.Error(err)
			s.Equal(context.Canceled, err)
		})
	}
}

// Test concurrent access (race condition testing)
func (s *FilesystemStorageTestSuite) TestConcurrentAccess() {
	ctx := context.Background()
	numGoroutines := 10
	numOperations := 100

	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("concurrent/%d/%d.txt", id, j)
				data := fmt.Sprintf("data-%d-%d", id, j)
				err := s.fs.Put(ctx, key, strings.NewReader(data), nil)
				s.NoError(err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all files exist
	objects, err := s.fs.List(ctx, "concurrent", nil)
	s.NoError(err)
	s.Equal(numGoroutines*numOperations, len(objects))
}

// Test concurrent reads and writes
func (s *FilesystemStorageTestSuite) TestConcurrentReadsAndWrites() {
	ctx := context.Background()

	// Setup: Create some initial files
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("shared/file-%d.txt", i)
		err := s.fs.Put(ctx, key, strings.NewReader(fmt.Sprintf("initial-%d", i)), nil)
		s.Require().NoError(err)
	}

	var wg sync.WaitGroup
	numReaders := 5
	numWriters := 5
	numOps := 50

	// Concurrent readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				key := fmt.Sprintf("shared/file-%d.txt", j%10)
				reader, err := s.fs.Get(ctx, key)
				if err == nil {
					io.ReadAll(reader)
					reader.Close() // #nosec G104 -- Cleanup, error not critical
				}
			}
		}(i)
	}

	// Concurrent writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				key := fmt.Sprintf("shared/writer-%d-%d.txt", id, j)
				data := fmt.Sprintf("writer-%d-%d", id, j)
				s.fs.Put(ctx, key, strings.NewReader(data), nil)
			}
		}(i)
	}

	wg.Wait()

	// Verify quota tracking is consistent
	quotaInfo, err := s.fs.GetQuota(ctx)
	s.NoError(err)
	s.Greater(quotaInfo.Used, int64(0))
}

// Test Delete updates quota correctly
func (s *FilesystemStorageTestSuite) TestDeleteUpdatesQuota() {
	ctx := context.Background()

	// Put a file
	testData := "test data for quota tracking"
	err := s.fs.Put(ctx, "quota/test.txt", strings.NewReader(testData), nil)
	s.Require().NoError(err)

	// Get quota before delete
	quotaBefore, err := s.fs.GetQuota(ctx)
	s.Require().NoError(err)

	// Delete the file
	err = s.fs.Delete(ctx, "quota/test.txt")
	s.NoError(err)

	// Get quota after delete
	quotaAfter, err := s.fs.GetQuota(ctx)
	s.NoError(err)

	// Quota should have decreased
	s.Less(quotaAfter.Used, quotaBefore.Used)
}

// Test atomic write behavior
func (s *FilesystemStorageTestSuite) TestAtomicWrite() {
	ctx := context.Background()
	key := "atomic/test.txt"

	// Initial write
	err := s.fs.Put(ctx, key, strings.NewReader("initial"), nil)
	s.Require().NoError(err)

	// Concurrent readers should never see partial writes
	var wg sync.WaitGroup
	stopReading := make(chan struct{})
	readErrors := make(chan error, 100)

	// Start readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReading:
					return
				default:
					reader, err := s.fs.Get(ctx, key)
					if err != nil {
						readErrors <- err
						continue
					}
					data, err := io.ReadAll(reader)
					reader.Close() // #nosec G104 -- Cleanup, error not critical
					if err != nil {
						readErrors <- err
						continue
					}
					// Data should be either "initial" or "updated", never partial
					content := string(data)
					if content != "initial" && content != "updated" {
						readErrors <- fmt.Errorf("read partial data: %s", content)
					}
				}
			}
		}()
	}

	// Perform update
	time.Sleep(10 * time.Millisecond)
	err = s.fs.Put(ctx, key, strings.NewReader("updated"), nil)
	s.NoError(err)

	// Stop readers
	time.Sleep(10 * time.Millisecond)
	close(stopReading)
	wg.Wait()
	close(readErrors)

	// Check for read errors
	for err := range readErrors {
		s.NoError(err)
	}
}

// Test path sanitization
func (s *FilesystemStorageTestSuite) TestPathSanitization() {
	ctx := context.Background()

	maliciousPaths := []string{
		"../../../etc/passwd",
		"/../secret.txt",
		"./../../outside.txt",
		"//etc/passwd",
	}

	for _, path := range maliciousPaths {
		s.Run(fmt.Sprintf("sanitize_%s", path), func() {
			err := s.fs.Put(ctx, path, strings.NewReader("malicious"), nil)
			s.NoError(err) // Should succeed but sanitize path

			// Verify file is inside base directory
			sanitized := s.fs.keyToPath(path)
			s.True(strings.HasPrefix(sanitized, s.tempDir),
				"Sanitized path %s should be inside %s", sanitized, s.tempDir)
		})
	}
}

// Test checksum validation
func (s *FilesystemStorageTestSuite) TestChecksumValidation() {
	ctx := context.Background()

	testData := "checksum test data"
	// Correct checksums calculated for "checksum test data"
	correctMD5 := "7dd7323e8ce3e087972f93d3711ef62b"

	tests := []struct {
		opts        *storage.PutOptions
		name        string
		expectError bool
	}{
		{
			name:        "valid MD5",
			opts:        &storage.PutOptions{ChecksumMD5: correctMD5},
			expectError: false,
		},
		{
			name:        "invalid MD5",
			opts:        &storage.PutOptions{ChecksumMD5: "invalid"},
			expectError: true,
		},
		{
			name:        "empty checksum (no validation)",
			opts:        &storage.PutOptions{ChecksumMD5: ""},
			expectError: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			key := fmt.Sprintf("checksum/%s.txt", tt.name)
			err := s.fs.Put(ctx, key, strings.NewReader(testData), tt.opts)

			if tt.expectError {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		})
	}
}

// Benchmark Put operation
func BenchmarkFilesystemPut(b *testing.B) {
	tempDir, _ := os.MkdirTemp("", "gohoarder-bench-*")
	defer os.RemoveAll(tempDir)

	fs, _ := New(tempDir, 1024*1024*1024) // 1GB quota
	defer fs.Close()                      // #nosec G104 -- Cleanup, error not critical

	ctx := context.Background()
	data := strings.Repeat("x", 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench/file-%d.txt", i)
		fs.Put(ctx, key, strings.NewReader(data), nil)
	}
}

// Benchmark Get operation
func BenchmarkFilesystemGet(b *testing.B) {
	tempDir, _ := os.MkdirTemp("", "gohoarder-bench-*")
	defer os.RemoveAll(tempDir)

	fs, _ := New(tempDir, 1024*1024*1024)
	defer fs.Close() // #nosec G104 -- Cleanup, error not critical

	ctx := context.Background()
	data := strings.Repeat("x", 1024)

	// Setup: Create test file
	fs.Put(ctx, "bench/test.txt", strings.NewReader(data), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader, _ := fs.Get(ctx, "bench/test.txt")
		if reader != nil {
			io.ReadAll(reader)
			reader.Close() // #nosec G104 -- Cleanup, error not critical
		}
	}
}
