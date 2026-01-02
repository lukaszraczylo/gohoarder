package smb

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/rs/zerolog/log"
)

// SMBStorage implements storage.StorageBackend for SMB/CIFS shares
type SMBStorage struct {
	host     string
	share    string
	basePath string
	username string
	password string
	quota    int64
	mu       sync.RWMutex
	used     int64
	connPool chan *smbConnection
	poolSize int
}

// smbConnection wraps an SMB session and share
type smbConnection struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
	lastUse time.Time
}

// Config holds SMB configuration
type Config struct {
	Host     string // SMB server hostname or IP
	Port     int    // SMB server port (default: 445)
	Share    string // SMB share name
	BasePath string // Base path within the share
	Username string // SMB username
	Password string // SMB password
	Domain   string // SMB domain (optional)
	Quota    int64  // Quota in bytes (0 = unlimited)
	PoolSize int    // Connection pool size (default: 5)
}

// New creates a new SMB storage backend
func New(ctx context.Context, cfg Config) (*SMBStorage, error) {
	if cfg.Host == "" {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "SMB host is required")
	}

	if cfg.Share == "" {
		return nil, errors.New(errors.ErrCodeInvalidConfig, "SMB share is required")
	}

	if cfg.Port == 0 {
		cfg.Port = 445 // Default SMB port
	}

	if cfg.PoolSize == 0 {
		cfg.PoolSize = 5 // Default pool size
	}

	smbStorage := &SMBStorage{
		host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		share:    cfg.Share,
		basePath: strings.Trim(cfg.BasePath, "/\\"),
		username: cfg.Username,
		password: cfg.Password,
		quota:    cfg.Quota,
		connPool: make(chan *smbConnection, cfg.PoolSize),
		poolSize: cfg.PoolSize,
	}

	// Initialize connection pool
	for i := 0; i < cfg.PoolSize; i++ {
		conn, err := smbStorage.createConnection(ctx)
		if err != nil {
			// Clean up any created connections
			close(smbStorage.connPool)
			for c := range smbStorage.connPool {
				c.close()
			}
			return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create SMB connection pool")
		}
		smbStorage.connPool <- conn
	}

	// Calculate initial usage
	if err := smbStorage.calculateUsage(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to calculate initial SMB storage usage")
	}

	return smbStorage, nil
}

// createConnection creates a new SMB connection
func (s *SMBStorage) createConnection(ctx context.Context) (*smbConnection, error) {
	conn, err := net.Dial("tcp", s.host)
	if err != nil {
		return nil, err
	}

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.username,
			Password: s.password,
		},
	}

	session, err := dialer.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	share, err := session.Mount(s.share)
	if err != nil {
		session.Logoff()
		conn.Close()
		return nil, err
	}

	return &smbConnection{
		conn:    conn,
		session: session,
		share:   share,
		lastUse: time.Now(),
	}, nil
}

// getConnection gets a connection from the pool
func (s *SMBStorage) getConnection(ctx context.Context) (*smbConnection, error) {
	select {
	case conn := <-s.connPool:
		conn.lastUse = time.Now()
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, errors.New(errors.ErrCodeStorageFailure, "timeout waiting for SMB connection")
	}
}

// returnConnection returns a connection to the pool
func (s *SMBStorage) returnConnection(conn *smbConnection) {
	select {
	case s.connPool <- conn:
	default:
		// Pool is full, close the connection
		conn.close()
	}
}

// close closes an SMB connection
func (c *smbConnection) close() {
	if c.share != nil {
		c.share.Umount()
	}
	if c.session != nil {
		c.session.Logoff()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// Get retrieves a file from SMB share
func (s *SMBStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	path := s.keyToPath(key)

	// Open file
	file, err := conn.share.Open(path)
	if err != nil {
		s.returnConnection(conn)
		if os.IsNotExist(err) {
			metrics.RecordStorageOperation("smb", "get", "not_found")
			return nil, errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		metrics.RecordStorageOperation("smb", "get", "error")
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to open SMB file")
	}

	// Read entire file into memory and close SMB connection
	// This is necessary because we need to return the connection to the pool
	data, err := io.ReadAll(file)
	file.Close()
	s.returnConnection(conn)

	if err != nil {
		metrics.RecordStorageOperation("smb", "get", "error")
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read SMB file")
	}

	metrics.RecordStorageOperation("smb", "get", "success")
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Put stores a file on SMB share
func (s *SMBStorage) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return err
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)
	dir := filepath.Dir(path)

	// Create directory structure
	if err := conn.share.MkdirAll(dir, 0755); err != nil {
		metrics.RecordStorageOperation("smb", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create SMB directory")
	}

	// Read data into buffer to calculate checksums and size
	var buf bytes.Buffer
	md5Hash := md5.New()
	sha256Hash := sha256.New()
	multiWriter := io.MultiWriter(&buf, md5Hash, sha256Hash)

	written, err := io.Copy(multiWriter, data)
	if err != nil {
		metrics.RecordStorageOperation("smb", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read data")
	}

	// Check quota
	if s.quota > 0 {
		s.mu.RLock()
		used := s.used
		s.mu.RUnlock()

		if used+written > s.quota {
			metrics.RecordStorageOperation("smb", "put", "quota_exceeded")
			return errors.QuotaExceeded(s.quota)
		}
	}

	// Verify checksums if provided
	if opts != nil {
		md5Sum := hex.EncodeToString(md5Hash.Sum(nil))
		sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))

		if opts.ChecksumMD5 != "" && opts.ChecksumMD5 != md5Sum {
			metrics.RecordStorageOperation("smb", "put", "checksum_error")
			return errors.New(errors.ErrCodeChecksumMismatch, "MD5 checksum mismatch")
		}

		if opts.ChecksumSHA256 != "" && opts.ChecksumSHA256 != sha256Sum {
			metrics.RecordStorageOperation("smb", "put", "checksum_error")
			return errors.New(errors.ErrCodeChecksumMismatch, "SHA256 checksum mismatch")
		}
	}

	// Create temp file for atomic write
	tempPath := path + ".tmp"
	file, err := conn.share.Create(tempPath)
	if err != nil {
		metrics.RecordStorageOperation("smb", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create SMB temp file")
	}

	// Write data
	_, err = io.Copy(file, bytes.NewReader(buf.Bytes()))
	file.Close()

	if err != nil {
		conn.share.Remove(tempPath)
		metrics.RecordStorageOperation("smb", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to write SMB file")
	}

	// Atomic rename
	if err := conn.share.Rename(tempPath, path); err != nil {
		conn.share.Remove(tempPath)
		metrics.RecordStorageOperation("smb", "put", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to rename SMB temp file")
	}

	// Update usage
	s.mu.Lock()
	s.used += written
	currentUsed := s.used
	s.mu.Unlock()

	metrics.RecordStorageOperation("smb", "put", "success")
	metrics.UpdateCacheSize("smb", currentUsed)
	return nil
}

// Delete removes a file from SMB share
func (s *SMBStorage) Delete(ctx context.Context, key string) error {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return err
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	// Get size before deletion
	info, err := conn.share.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			metrics.RecordStorageOperation("smb", "delete", "not_found")
			return errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		metrics.RecordStorageOperation("smb", "delete", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat SMB file")
	}

	size := info.Size()

	if err := conn.share.Remove(path); err != nil {
		metrics.RecordStorageOperation("smb", "delete", "error")
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete SMB file")
	}

	// Update usage
	s.mu.Lock()
	s.used -= size
	currentUsed := s.used
	s.mu.Unlock()

	metrics.RecordStorageOperation("smb", "delete", "success")
	metrics.UpdateCacheSize("smb", currentUsed)
	return nil
}

// Exists checks if a file exists on SMB share
func (s *SMBStorage) Exists(ctx context.Context, key string) (bool, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return false, err
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	_, err = conn.share.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to check SMB file existence")
	}

	return true, nil
}

// List lists files with prefix on SMB share
func (s *SMBStorage) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return nil, err
	}
	defer s.returnConnection(conn)

	searchPath := s.keyToPath(prefix)
	var objects []storage.StorageObject

	err = s.walkPath(conn.share, searchPath, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			return nil
		}

		key := s.pathToKey(path)
		objects = append(objects, storage.StorageObject{
			Key:      key,
			Size:     info.Size(),
			Modified: info.ModTime(),
		})
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list SMB files")
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

// Stat gets file metadata from SMB share
func (s *SMBStorage) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return nil, err
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	info, err := conn.share.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound(fmt.Sprintf("file not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat SMB file")
	}

	return &storage.StorageInfo{
		Key:      key,
		Size:     info.Size(),
		Modified: info.ModTime(),
	}, nil
}

// GetQuota returns quota information
func (s *SMBStorage) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
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

// Health checks SMB health
func (s *SMBStorage) Health(ctx context.Context) error {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "SMB health check failed - connection error")
	}
	defer s.returnConnection(conn)

	// Try to stat the base path
	path := s.keyToPath("")
	_, err = conn.share.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "SMB health check failed")
	}

	return nil
}

// Close closes the storage backend
func (s *SMBStorage) Close() error {
	close(s.connPool)
	for conn := range s.connPool {
		conn.close()
	}
	return nil
}

// keyToPath converts a storage key to SMB path
func (s *SMBStorage) keyToPath(key string) string {
	key = strings.TrimPrefix(key, "/")
	key = filepath.Clean(key)

	// Remove path traversal attempts
	for strings.HasPrefix(key, "../") || strings.HasPrefix(key, "..\\") {
		key = strings.TrimPrefix(key, "../")
		key = strings.TrimPrefix(key, "..\\")
	}

	key = filepath.Clean(key)
	if key == ".." || strings.HasPrefix(key, "../") || strings.HasPrefix(key, "..\\") {
		key = ""
	}

	if s.basePath != "" {
		return filepath.Join(s.basePath, key)
	}
	return key
}

// pathToKey converts an SMB path back to a storage key
func (s *SMBStorage) pathToKey(path string) string {
	if s.basePath != "" {
		path = strings.TrimPrefix(path, s.basePath)
		path = strings.TrimPrefix(path, "/")
		path = strings.TrimPrefix(path, "\\")
	}
	return filepath.ToSlash(path)
}

// walkPath recursively walks an SMB directory
func (s *SMBStorage) walkPath(share *smb2.Share, path string, fn func(string, os.FileInfo) error) error {
	info, err := share.Stat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fn(path, info)
	}

	entries, err := share.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			if err := s.walkPath(share, entryPath, fn); err != nil {
				return err
			}
		} else {
			if err := fn(entryPath, entry); err != nil {
				return err
			}
		}
	}

	return nil
}

// calculateUsage calculates current SMB storage usage
func (s *SMBStorage) calculateUsage(ctx context.Context) error {
	conn, err := s.getConnection(ctx)
	if err != nil {
		return err
	}
	defer s.returnConnection(conn)

	var total int64
	basePath := s.keyToPath("")

	err = s.walkPath(conn.share, basePath, func(path string, info os.FileInfo) error {
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return err
	}

	s.mu.Lock()
	s.used = total
	s.mu.Unlock()

	metrics.UpdateCacheSize("smb", total)
	return nil
}
