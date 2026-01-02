package s3

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- MD5 used for S3 Content-MD5 header, not cryptographic security
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/rs/zerolog/log"
)

// S3Storage implements storage.StorageBackend for AWS S3
type S3Storage struct {
	client *s3.Client
	bucket string
	prefix string
	quota  int64
	mu     sync.RWMutex
	used   int64
}

// Config holds S3 configuration
type Config struct {
	Bucket          string
	Region          string
	Endpoint        string // For S3-compatible services (MinIO, etc.)
	AccessKeyID     string
	SecretAccessKey string
	Prefix          string // Optional prefix for all keys
	Quota           int64  // Quota in bytes (0 = unlimited)
	ForcePathStyle  bool   // For S3-compatible services
}

// New creates a new S3 storage backend
func New(ctx context.Context, cfg Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "S3 bucket is required")
	}

	if cfg.Region == "" {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "S3 region is required")
	}

	// Build AWS config
	var awsCfg aws.Config
	var err error

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		// Use static credentials
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID,
				cfg.SecretAccessKey,
				"",
			)),
		)
	} else {
		// Use default credential chain
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.Region),
		)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to load AWS config")
	}

	// Create S3 client
	var s3Options []func(*s3.Options)

	if cfg.Endpoint != "" {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.ForcePathStyle
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Options...)

	s3Storage := &S3Storage{
		client: client,
		bucket: cfg.Bucket,
		prefix: strings.TrimSuffix(cfg.Prefix, "/"),
		quota:  cfg.Quota,
	}

	// Calculate initial usage
	if err := s3Storage.calculateUsage(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to calculate initial S3 storage usage")
	}

	return s3Storage, nil
}

// Get retrieves a file from S3
func (s *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	s3Key := s.buildKey(key)

	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	result, err := s.client.GetObject(ctx, input)
	if err != nil {
		if isNotFoundError(err) {
			metrics.RecordStorageOperation("s3", "get", "not_found")
			return nil, errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		metrics.RecordStorageOperation("s3", "get", "error")
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get object from S3")
	}

	metrics.RecordStorageOperation("s3", "get", "success")
	return result.Body, nil
}

// Put stores a file in S3
func (s *S3Storage) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	s3Key := s.buildKey(key)

	// Read data into buffer to calculate checksums and size
	var buf bytes.Buffer
	md5Hash := md5.New() // #nosec G401 -- MD5 used for S3 integrity check, not cryptographic security
	sha256Hash := sha256.New()
	multiWriter := io.MultiWriter(&buf, md5Hash, sha256Hash)

	written, err := io.Copy(multiWriter, data)
	if err != nil {
		metrics.RecordStorageOperation("s3", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read data")
	}

	// Check quota before upload
	if s.quota > 0 {
		s.mu.RLock()
		used := s.used
		s.mu.RUnlock()

		if used+written > s.quota {
			metrics.RecordStorageOperation("s3", "put", "quota_exceeded")
			return errors.QuotaExceeded(s.quota)
		}
	}

	// Verify checksums if provided
	if opts != nil {
		md5Sum := hex.EncodeToString(md5Hash.Sum(nil))
		sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))

		if opts.ChecksumMD5 != "" && opts.ChecksumMD5 != md5Sum {
			metrics.RecordStorageOperation("s3", "put", "checksum_error")
			return errors.New(errors.ErrCodeChecksumMismatch, "MD5 checksum mismatch")
		}

		if opts.ChecksumSHA256 != "" && opts.ChecksumSHA256 != sha256Sum {
			metrics.RecordStorageOperation("s3", "put", "checksum_error")
			return errors.New(errors.ErrCodeChecksumMismatch, "SHA256 checksum mismatch")
		}
	}

	// Prepare metadata
	metadata := make(map[string]string)
	if opts != nil && opts.Metadata != nil {
		metadata = opts.Metadata
	}

	// Build put input
	input := &s3.PutObjectInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(s3Key),
		Body:     bytes.NewReader(buf.Bytes()),
		Metadata: metadata,
	}

	if opts != nil && opts.ContentType != "" {
		input.ContentType = aws.String(opts.ContentType)
	}

	// Upload to S3
	_, err = s.client.PutObject(ctx, input)
	if err != nil {
		metrics.RecordStorageOperation("s3", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to upload to S3")
	}

	// Update usage
	s.mu.Lock()
	s.used += written
	currentUsed := s.used
	s.mu.Unlock()

	metrics.RecordStorageOperation("s3", "put", "success")
	metrics.UpdateCacheSize("s3", currentUsed)
	return nil
}

// Delete removes a file from S3
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	s3Key := s.buildKey(key)

	// Get size before deletion for quota tracking
	statInfo, err := s.Stat(ctx, key)
	if err != nil {
		return err
	}

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	_, err = s.client.DeleteObject(ctx, input)
	if err != nil {
		metrics.RecordStorageOperation("s3", "delete", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete from S3")
	}

	// Update usage
	s.mu.Lock()
	s.used -= statInfo.Size
	currentUsed := s.used
	s.mu.Unlock()

	metrics.RecordStorageOperation("s3", "delete", "success")
	metrics.UpdateCacheSize("s3", currentUsed)
	return nil
}

// Exists checks if a file exists in S3
func (s *S3Storage) Exists(ctx context.Context, key string) (bool, error) {
	s3Key := s.buildKey(key)

	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	_, err := s.client.HeadObject(ctx, input)
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to check existence in S3")
	}

	return true, nil
}

// List lists files with prefix in S3
func (s *S3Storage) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	s3Prefix := s.buildKey(prefix)

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(s3Prefix),
	}

	var objects []storage.StorageObject
	paginator := s3.NewListObjectsV2Paginator(s.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list objects in S3")
		}

		for _, obj := range page.Contents {
			key := s.stripPrefix(*obj.Key)
			objects = append(objects, storage.StorageObject{
				Key:      key,
				Size:     *obj.Size,
				Modified: *obj.LastModified,
				ETag:     strings.Trim(*obj.ETag, "\""),
			})
		}
	}

	// Apply pagination if requested
	if opts != nil {
		start := opts.Offset
		end := len(objects)
		if opts.MaxResults > 0 && start+opts.MaxResults < end {
			end = start + opts.MaxResults
		}
		if start < len(objects) {
			objects = objects[start:end]
		} else {
			objects = []storage.StorageObject{}
		}
	}

	return objects, nil
}

// Stat gets file metadata from S3
func (s *S3Storage) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	s3Key := s.buildKey(key)

	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}

	result, err := s.client.HeadObject(ctx, input)
	if err != nil {
		if isNotFoundError(err) {
			return nil, errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat object in S3")
	}

	info := &storage.StorageInfo{
		Key:      key,
		Size:     *result.ContentLength,
		Modified: *result.LastModified,
		ETag:     strings.Trim(*result.ETag, "\""),
		Metadata: result.Metadata,
	}

	if result.ContentType != nil {
		info.ContentType = *result.ContentType
	}

	return info, nil
}

// GetQuota returns quota information
func (s *S3Storage) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
	s.mu.RLock()
	used := s.used
	s.mu.RUnlock()

	available := s.quota - used
	if available < 0 {
		available = 0
	}

	return &storage.QuotaInfo{
		Used:      used,
		Available: available,
		Limit:     s.quota,
	}, nil
}

// Health checks S3 health
func (s *S3Storage) Health(ctx context.Context) error {
	// Try to list bucket to verify connectivity
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		MaxKeys: aws.Int32(1),
	}

	_, err := s.client.ListObjectsV2(ctx, input)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "S3 health check failed")
	}

	return nil
}

// Close closes the storage backend
func (s *S3Storage) Close() error {
	// No cleanup needed for S3 client
	return nil
}

// buildKey builds the full S3 key with prefix
func (s *S3Storage) buildKey(key string) string {
	key = strings.TrimPrefix(key, "/")
	if s.prefix != "" {
		return s.prefix + "/" + key
	}
	return key
}

// stripPrefix removes the configured prefix from an S3 key
func (s *S3Storage) stripPrefix(s3Key string) string {
	if s.prefix != "" {
		return strings.TrimPrefix(s3Key, s.prefix+"/")
	}
	return s3Key
}

// calculateUsage calculates current S3 storage usage
func (s *S3Storage) calculateUsage(ctx context.Context) error {
	var total int64

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	}

	if s.prefix != "" {
		input.Prefix = aws.String(s.prefix + "/")
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, obj := range page.Contents {
			total += *obj.Size
		}
	}

	s.mu.Lock()
	s.used = total
	s.mu.Unlock()

	metrics.UpdateCacheSize("s3", total)
	return nil
}

// isNotFoundError checks if an error is a "not found" error
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	var notFound *types.NotFound
	var noSuchKey *types.NoSuchKey

	return stderrors.As(err, &notFound) || stderrors.As(err, &noSuchKey)
}
