package s3

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type S3StorageTestSuite struct {
	suite.Suite
}

func TestS3StorageTestSuite(t *testing.T) {
	suite.Run(t, new(S3StorageTestSuite))
}

func (s *S3StorageTestSuite) TestNewS3Storage() {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config with credentials",
			config: Config{
				Region:          "us-east-1",
				Bucket:          "test-bucket",
				Prefix:          "packages/",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				MaxSizeBytes:    1024 * 1024,
			},
			expectError: false,
		},
		{
			name: "valid config with custom endpoint",
			config: Config{
				Region:          "us-east-1",
				Bucket:          "test-bucket",
				Endpoint:        "https://minio.example.com",
				AccessKeyID:     "minioadmin",
				SecretAccessKey: "minioadmin",
				ForcePathStyle:  true,
			},
			expectError: false,
		},
		{
			name: "valid config with default region",
			config: Config{
				Bucket:          "test-bucket",
				AccessKeyID:     "test",
				SecretAccessKey: "test",
			},
			expectError: false,
		},
		{
			name: "missing bucket",
			config: Config{
				Region:          "us-east-1",
				AccessKeyID:     "test",
				SecretAccessKey: "test",
			},
			expectError: true,
			errorMsg:    "bucket is required",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			storage, err := New(tt.config)

			if tt.expectError {
				s.Error(err)
				if tt.errorMsg != "" {
					s.Contains(err.Error(), tt.errorMsg)
				}
				s.Nil(storage)
			} else {
				s.NoError(err)
				s.NotNil(storage)
				s.Equal(tt.config.Bucket, storage.bucket)
				s.Equal(tt.config.MaxSizeBytes, storage.maxSizeBytes)

				// Test prefix normalization
				if tt.config.Prefix != "" {
					s.NotContains(storage.prefix, "/", "prefix should not end with /")
				}
			}
		})
	}
}

func (s *S3StorageTestSuite) TestBuildKey() {
	tests := []struct {
		name     string
		prefix   string
		key      string
		expected string
	}{
		{
			name:     "with prefix",
			prefix:   "packages",
			key:      "test/file.txt",
			expected: "packages/test/file.txt",
		},
		{
			name:     "without prefix",
			prefix:   "",
			key:      "test/file.txt",
			expected: "test/file.txt",
		},
		{
			name:     "with trailing slash in prefix",
			prefix:   "packages/",
			key:      "test/file.txt",
			expected: "packages/test/file.txt",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			storage := &S3Storage{
				prefix: tt.prefix,
			}
			// Normalize prefix like in New()
			if storage.prefix != "" && storage.prefix[len(storage.prefix)-1] == '/' {
				storage.prefix = storage.prefix[:len(storage.prefix)-1]
			}

			result := storage.buildKey(tt.key)
			s.Equal(tt.expected, result)
		})
	}
}

func (s *S3StorageTestSuite) TestStripPrefix() {
	tests := []struct {
		name     string
		prefix   string
		key      string
		expected string
	}{
		{
			name:     "with prefix",
			prefix:   "packages",
			key:      "packages/test/file.txt",
			expected: "test/file.txt",
		},
		{
			name:     "without prefix",
			prefix:   "",
			key:      "test/file.txt",
			expected: "test/file.txt",
		},
		{
			name:     "key without prefix but prefix set",
			prefix:   "packages",
			key:      "test/file.txt",
			expected: "test/file.txt",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			storage := &S3Storage{
				prefix: tt.prefix,
			}

			result := storage.stripPrefix(tt.key)
			s.Equal(tt.expected, result)
		})
	}
}

func (s *S3StorageTestSuite) TestIsNotFoundError() {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := isNotFoundError(tt.err)
			s.Equal(tt.expected, result)
		})
	}
}

func (s *S3StorageTestSuite) TestConfigDefaults() {
	config := Config{
		Bucket:          "test-bucket",
		AccessKeyID:     "test",
		SecretAccessKey: "test",
	}

	storage, err := New(config)
	s.Require().NoError(err)
	s.NotNil(storage)

	// Verify defaults
	s.Equal("test-bucket", storage.bucket)
	s.Equal("", storage.prefix)
	s.Equal(int64(0), storage.maxSizeBytes)
}

func (s *S3StorageTestSuite) TestPrefixNormalization() {
	tests := []struct {
		name           string
		inputPrefix    string
		expectedPrefix string
	}{
		{
			name:           "prefix with trailing slash",
			inputPrefix:    "packages/",
			expectedPrefix: "packages",
		},
		{
			name:           "prefix without trailing slash",
			inputPrefix:    "packages",
			expectedPrefix: "packages",
		},
		{
			name:           "empty prefix",
			inputPrefix:    "",
			expectedPrefix: "",
		},
		{
			name:           "nested prefix with trailing slash",
			inputPrefix:    "cache/packages/",
			expectedPrefix: "cache/packages",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			config := Config{
				Bucket:          "test-bucket",
				Prefix:          tt.inputPrefix,
				AccessKeyID:     "test",
				SecretAccessKey: "test",
			}

			storage, err := New(config)
			s.Require().NoError(err)
			s.Equal(tt.expectedPrefix, storage.prefix)
		})
	}
}

func (s *S3StorageTestSuite) TestClose() {
	config := Config{
		Bucket:          "test-bucket",
		AccessKeyID:     "test",
		SecretAccessKey: "test",
	}

	storage, err := New(config)
	s.Require().NoError(err)

	// Close should not error
	err = storage.Close()
	s.NoError(err)
}
