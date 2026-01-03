package s3

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/rs/zerolog/log"
)

// Config holds S3 storage configuration
type Config struct {
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
	Endpoint        string // Optional: for S3-compatible services like MinIO
	ForcePathStyle  bool   // Optional: for S3-compatible services
	MaxSizeBytes    int64
}

// S3Storage implements storage.StorageBackend using AWS S3
type S3Storage struct {
	client       *s3.Client
	bucket       string
	prefix       string
	maxSizeBytes int64
}

// New creates a new S3 storage backend
func New(cfg Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("S3 bucket is required")
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1" // Default region
	}

	// Build AWS config
	var awsConfig aws.Config
	var err error

	// Build config options
	configOpts := []func(*config.LoadOptions) error{
		config.WithRegion(cfg.Region),
	}

	// Add credentials if provided
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		configOpts = append(configOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID,
				cfg.SecretAccessKey,
				"",
			),
		))
	}

	awsConfig, err = config.LoadDefaultConfig(context.Background(), configOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with service-specific options
	client := s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		// Use custom endpoint if provided (for MinIO, S3-compatible services, etc.)
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		if cfg.ForcePathStyle {
			o.UsePathStyle = true
		}
	})

	storage := &S3Storage{
		client:       client,
		bucket:       cfg.Bucket,
		prefix:       strings.TrimSuffix(cfg.Prefix, "/"),
		maxSizeBytes: cfg.MaxSizeBytes,
	}

	log.Info().
		Str("bucket", cfg.Bucket).
		Str("region", cfg.Region).
		Str("prefix", cfg.Prefix).
		Msg("S3 storage initialized")

	return storage, nil
}

// Get retrieves data from S3
func (s *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	fullKey := s.buildKey(key)

	log.Debug().Str("key", fullKey).Msg("Getting object from S3")

	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})

	if err != nil {
		if isNotFoundError(err) {
			return nil, errors.NotFound(fmt.Sprintf("S3 object not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get object from S3")
	}

	return result.Body, nil
}

// Put stores data in S3
func (s *S3Storage) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	fullKey := s.buildKey(key)

	// Read data into buffer to get size
	buf := new(bytes.Buffer)
	size, err := io.Copy(buf, data)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	log.Debug().
		Str("key", fullKey).
		Int64("size", size).
		Msg("Putting object to S3")

	// Check quota if set
	if s.maxSizeBytes > 0 {
		currentUsage, err := s.calculateUsage(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to calculate current usage, skipping quota check")
		} else if currentUsage+size > s.maxSizeBytes {
			return errors.QuotaExceeded(s.maxSizeBytes)
		}
	}

	// Convert metadata to S3 metadata format
	s3Metadata := make(map[string]string)
	if opts != nil && opts.Metadata != nil {
		for k, v := range opts.Metadata {
			s3Metadata[k] = v
		}
	}

	// Upload to S3
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(fullKey),
		Body:     bytes.NewReader(buf.Bytes()),
		Metadata: s3Metadata,
	})

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to put object to S3")
	}

	return nil
}

// Delete removes data from S3
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	fullKey := s.buildKey(key)

	log.Debug().Str("key", fullKey).Msg("Deleting object from S3")

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete object from S3")
	}

	return nil
}

// Exists checks if data exists in S3
func (s *S3Storage) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := s.buildKey(key)

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})

	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to check object existence in S3")
	}

	return true, nil
}

// List returns a list of objects with the given prefix
func (s *S3Storage) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	fullPrefix := s.buildKey(prefix)

	log.Debug().Str("prefix", fullPrefix).Msg("Listing objects in S3")

	var objects []storage.StorageObject
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(fullPrefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list objects in S3")
		}

		for _, obj := range page.Contents {
			if obj.Key != nil {
				// Strip prefix from key
				key := s.stripPrefix(*obj.Key)

				object := storage.StorageObject{
					Key:  key,
					Size: aws.ToInt64(obj.Size),
				}

				if obj.LastModified != nil {
					object.Modified = *obj.LastModified
				}

				if obj.ETag != nil {
					object.ETag = *obj.ETag
				}

				objects = append(objects, object)
			}
		}
	}

	return objects, nil
}

// Stat returns metadata about stored data
func (s *S3Storage) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	fullKey := s.buildKey(key)

	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})

	if err != nil {
		if isNotFoundError(err) {
			return nil, errors.NotFound(fmt.Sprintf("S3 object not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat object in S3")
	}

	info := &storage.StorageInfo{
		Key:  key,
		Size: aws.ToInt64(result.ContentLength),
	}

	if result.LastModified != nil {
		info.Modified = *result.LastModified
	}

	if result.ETag != nil {
		info.ETag = *result.ETag
	}

	if result.ContentType != nil {
		info.ContentType = *result.ContentType
	}

	return info, nil
}

// GetQuota returns current usage and quota information
func (s *S3Storage) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
	usage, err := s.calculateUsage(ctx)
	if err != nil {
		return nil, err
	}

	return &storage.QuotaInfo{
		Used:  usage,
		Limit: s.maxSizeBytes,
	}, nil
}

// Health checks if the S3 backend is healthy
func (s *S3Storage) Health(ctx context.Context) error {
	// Try to list objects (lightweight operation)
	_, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		MaxKeys: aws.Int32(1),
	})

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "S3 health check failed")
	}

	return nil
}

// Close closes the S3 storage backend
func (s *S3Storage) Close() error {
	log.Info().Msg("S3 storage closed")
	return nil
}

// buildKey constructs the full S3 key with prefix
func (s *S3Storage) buildKey(key string) string {
	if s.prefix == "" {
		return key
	}
	return s.prefix + "/" + key
}

// stripPrefix removes the prefix from an S3 key
func (s *S3Storage) stripPrefix(key string) string {
	if s.prefix == "" {
		return key
	}
	return strings.TrimPrefix(key, s.prefix+"/")
}

// calculateUsage calculates total storage usage
func (s *S3Storage) calculateUsage(ctx context.Context) (int64, error) {
	var totalSize int64

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s.prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, fmt.Errorf("failed to calculate usage: %w", err)
		}

		for _, obj := range page.Contents {
			if obj.Size != nil {
				totalSize += aws.ToInt64(obj.Size)
			}
		}
	}

	return totalSize, nil
}

// isNotFoundError checks if an error is a "not found" error
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	// Check for specific S3 error types
	var notFound *types.NotFound
	var noSuchKey *types.NoSuchKey

	// Use errors.As to check for wrapped errors
	if ok := stderrors.As(err, &notFound); ok {
		return true
	}
	if ok := stderrors.As(err, &noSuchKey); ok {
		return true
	}

	// Check error message as fallback
	errMsg := err.Error()
	return strings.Contains(errMsg, "NoSuchKey") ||
		strings.Contains(errMsg, "NotFound") ||
		strings.Contains(errMsg, "404")
}
