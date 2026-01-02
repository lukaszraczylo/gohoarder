package storage

import (
	"context"
	"io"
	"time"
)

// StorageBackend defines the interface for package storage
type StorageBackend interface {
	// Get retrieves a package by key
	Get(ctx context.Context, key string) (io.ReadCloser, error)

	// Put stores a package
	Put(ctx context.Context, key string, data io.Reader, opts *PutOptions) error

	// Delete removes a package
	Delete(ctx context.Context, key string) error

	// Exists checks if a package exists
	Exists(ctx context.Context, key string) (bool, error)

	// List lists packages with prefix
	List(ctx context.Context, prefix string, opts *ListOptions) ([]StorageObject, error)

	// Stat gets package metadata
	Stat(ctx context.Context, key string) (*StorageInfo, error)

	// GetQuota returns quota information
	GetQuota(ctx context.Context) (*QuotaInfo, error)

	// Health checks backend health
	Health(ctx context.Context) error

	// Close closes the backend
	Close() error
}

// PutOptions contains options for Put operations
type PutOptions struct {
	ContentType    string
	Metadata       map[string]string
	ChecksumMD5    string
	ChecksumSHA256 string
}

// ListOptions contains options for List operations
type ListOptions struct {
	MaxResults int
	Offset     int
}

// StorageObject represents a stored object
type StorageObject struct {
	Key      string
	Size     int64
	Modified time.Time
	ETag     string
}

// StorageInfo contains detailed object information
type StorageInfo struct {
	Key         string
	Size        int64
	Modified    time.Time
	ETag        string
	ContentType string
	Metadata    map[string]string
	Checksums   *Checksums
}

// Checksums contains file checksums
type Checksums struct {
	MD5    string
	SHA256 string
}

// QuotaInfo contains quota information
type QuotaInfo struct {
	Used      int64
	Available int64
	Limit     int64
}

// LocalPathProvider is an optional interface that storage backends can implement
// to provide direct file system paths for scanning without creating temp copies
type LocalPathProvider interface {
	// GetLocalPath returns the local filesystem path for a storage key
	// Returns empty string if the backend doesn't support local paths (e.g., S3, SMB)
	GetLocalPath(ctx context.Context, key string) (string, error)
}
