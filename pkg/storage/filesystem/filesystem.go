package filesystem

import (
	"context"
	"crypto/md5" // #nosec G501 -- MD5 used for file checksums, not cryptographic security
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/rs/zerolog/log"
)

// FilesystemStorage implements storage.StorageBackend for local filesystem
type FilesystemStorage struct {
	basePath string
	quota    int64
	mu       sync.RWMutex
	used     int64
}

// New creates a new filesystem storage backend
func New(basePath string, quota int64) (*FilesystemStorage, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create base directory")
	}

	fs := &FilesystemStorage{
		basePath: basePath,
		quota:    quota,
	}

	// Calculate initial usage
	if err := fs.calculateUsage(); err != nil {
		log.Warn().Err(err).Msg("Failed to calculate initial storage usage")
	}

	return fs, nil
}

// Get retrieves a file
func (fs *FilesystemStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	// Check context
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	path := fs.keyToPath(key)

	file, err := os.Open(path) // #nosec G304 -- Path is sanitized storage key
	if err != nil {
		if os.IsNotExist(err) {
			metrics.RecordStorageOperation("filesystem", "get", "not_found")
			return nil, errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		metrics.RecordStorageOperation("filesystem", "get", "error")
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to open file")
	}

	metrics.RecordStorageOperation("filesystem", "get", "success")
	return file, nil
}

// Put stores a file atomically
func (fs *FilesystemStorage) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	// Check context
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	path := fs.keyToPath(key)
	dir := filepath.Dir(path)

	// Create directory
	if err := os.MkdirAll(dir, 0750); err != nil {
		metrics.RecordStorageOperation("filesystem", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create directory")
	}

	// Create temp file for atomic write
	tempPath := path + ".tmp"
	tempFile, err := os.Create(tempPath) // #nosec G304 -- Temp path is constructed from sanitized storage key
	if err != nil {
		metrics.RecordStorageOperation("filesystem", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create temp file")
	}

	// Calculate checksums while writing
	// NOTE: MD5 is used for integrity verification (checksums), not cryptographic security
	md5Hash := md5.New() // #nosec G401 -- MD5 used for file integrity check, not cryptographic security
	sha256Hash := sha256.New()
	multiWriter := io.MultiWriter(tempFile, md5Hash, sha256Hash)

	written, err := io.Copy(multiWriter, data)
	if err != nil {
		tempFile.Close()        // #nosec G104 -- Cleanup, error not critical
		_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical
		metrics.RecordStorageOperation("filesystem", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to write data")
	}

	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical
		metrics.RecordStorageOperation("filesystem", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to close temp file")
	}

	// Check quota
	fs.mu.Lock()
	if fs.quota > 0 && fs.used+written > fs.quota {
		fs.mu.Unlock()
		_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical
		metrics.RecordStorageOperation("filesystem", "put", "quota_exceeded")
		return errors.QuotaExceeded(fs.quota)
	}
	fs.used += written
	fs.mu.Unlock()

	// Verify checksums if provided
	if opts != nil {
		md5Sum := hex.EncodeToString(md5Hash.Sum(nil))
		sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))

		if opts.ChecksumMD5 != "" && opts.ChecksumMD5 != md5Sum {
			_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical
			metrics.RecordStorageOperation("filesystem", "put", "checksum_error")
			return errors.New(errors.ErrCodeChecksumMismatch, "MD5 checksum mismatch")
		}

		if opts.ChecksumSHA256 != "" && opts.ChecksumSHA256 != sha256Sum {
			_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical
			metrics.RecordStorageOperation("filesystem", "put", "checksum_error")
			return errors.New(errors.ErrCodeChecksumMismatch, "SHA256 checksum mismatch")
		}
	}

	// Atomic rename
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical
		fs.mu.Lock()
		fs.used -= written
		currentUsed := fs.used
		fs.mu.Unlock()
		metrics.RecordStorageOperation("filesystem", "put", "error")
		metrics.UpdateCacheSize("filesystem", currentUsed)
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to rename temp file")
	}

	fs.mu.RLock()
	currentUsed := fs.used
	fs.mu.RUnlock()

	metrics.RecordStorageOperation("filesystem", "put", "success")
	metrics.UpdateCacheSize("filesystem", currentUsed)
	return nil
}

// Delete removes a file
func (fs *FilesystemStorage) Delete(ctx context.Context, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	path := fs.keyToPath(key)

	// Get size before deletion
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			metrics.RecordStorageOperation("filesystem", "delete", "not_found")
			return errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		metrics.RecordStorageOperation("filesystem", "delete", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat file")
	}

	size := info.Size()

	if err := os.Remove(path); err != nil {
		metrics.RecordStorageOperation("filesystem", "delete", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete file")
	}

	fs.mu.Lock()
	fs.used -= size
	currentUsed := fs.used
	fs.mu.Unlock()

	metrics.RecordStorageOperation("filesystem", "delete", "success")
	metrics.UpdateCacheSize("filesystem", currentUsed)
	return nil
}

// Exists checks if a file exists
func (fs *FilesystemStorage) Exists(ctx context.Context, key string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	path := fs.keyToPath(key)
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to check existence")
	}
	return true, nil
}

// List lists files with prefix
func (fs *FilesystemStorage) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	searchPath := fs.keyToPath(prefix)
	var objects []storage.StorageObject

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			return nil
		}

		// Convert path back to key
		relPath, _ := filepath.Rel(fs.basePath, path)
		key := filepath.ToSlash(relPath)

		objects = append(objects, storage.StorageObject{
			Key:      key,
			Size:     info.Size(),
			Modified: info.ModTime(),
		})

		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list files")
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
		}
	}

	return objects, nil
}

// Stat gets file metadata
func (fs *FilesystemStorage) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	path := fs.keyToPath(key)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat file")
	}

	return &storage.StorageInfo{
		Key:      key,
		Size:     info.Size(),
		Modified: info.ModTime(),
	}, nil
}

// GetQuota returns quota information
func (fs *FilesystemStorage) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
	fs.mu.RLock()
	used := fs.used
	fs.mu.RUnlock()

	available := fs.quota - used
	if available < 0 {
		available = 0
	}

	return &storage.QuotaInfo{
		Used:      used,
		Available: available,
		Limit:     fs.quota,
	}, nil
}

// Health checks filesystem health
func (fs *FilesystemStorage) Health(ctx context.Context) error {
	// Check if base path is accessible
	if _, err := os.Stat(fs.basePath); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "base path not accessible")
	}

	// Try to create a temp file (sanitize path to prevent traversal)
	tempPath := filepath.Clean(filepath.Join(fs.basePath, ".health_check"))
	f, err := os.Create(tempPath)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "cannot write to storage")
	}
	f.Close()               // #nosec G104 -- Cleanup, error not critical
	_ = os.Remove(tempPath) // #nosec G104 -- Cleanup, error not critical

	return nil
}

// Close closes the storage backend
func (fs *FilesystemStorage) Close() error {
	// Nothing to close for filesystem
	return nil
}

// GetLocalPath returns the local filesystem path for a storage key
// This implements storage.LocalPathProvider interface
func (fs *FilesystemStorage) GetLocalPath(ctx context.Context, key string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	path := fs.keyToPath(key)

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		return "", errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat file")
	}

	return path, nil
}

// keyToPath converts a storage key to filesystem path
func (fs *FilesystemStorage) keyToPath(key string) string {
	// Sanitize key to prevent path traversal
	key = filepath.Clean(key)

	// Remove any leading slashes or dots
	key = strings.TrimPrefix(key, "/")

	// Keep removing ../ until there are no more
	for strings.HasPrefix(key, "../") || strings.HasPrefix(key, "..\\") {
		key = strings.TrimPrefix(key, "../")
		key = strings.TrimPrefix(key, "..\\")
	}

	// Final clean and ensure it's within base path
	key = filepath.Clean(key)
	if key == ".." || strings.HasPrefix(key, "../") || strings.HasPrefix(key, "..\\") {
		key = ""
	}

	return filepath.Join(fs.basePath, key)
}

// calculateUsage calculates current storage usage
func (fs *FilesystemStorage) calculateUsage() error {
	var total int64

	err := filepath.Walk(fs.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})

	if err != nil {
		return err
	}

	fs.mu.Lock()
	fs.used = total
	fs.mu.Unlock()

	metrics.UpdateCacheSize("filesystem", total)
	return nil
}
