package smb

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/rs/zerolog/log"
)

// Config holds SMB storage configuration
type Config struct {
	Host         string
	Share        string
	Path         string
	Username     string
	Password     string
	Domain       string
	Port         int
	MaxSizeBytes int64
	PoolSize     int
}

// SMBStorage implements storage.StorageBackend using SMB/CIFS
type SMBStorage struct {
	connPool     chan *smbConnection
	config       Config
	maxSizeBytes int64
	poolSize     int
}

// smbConnection represents a pooled SMB connection
type smbConnection struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
	lastUse time.Time
}

// New creates a new SMB storage backend
func New(cfg Config) (*SMBStorage, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("SMB host is required")
	}

	if cfg.Share == "" {
		return nil, fmt.Errorf("SMB share is required")
	}

	if cfg.Port == 0 {
		cfg.Port = 445 // Default SMB port
	}

	if cfg.PoolSize == 0 {
		cfg.PoolSize = 5 // Default pool size
	}

	// Normalize path
	cfg.Path = strings.Trim(cfg.Path, "/\\")

	storage := &SMBStorage{
		config:       cfg,
		maxSizeBytes: cfg.MaxSizeBytes,
		poolSize:     cfg.PoolSize,
		connPool:     make(chan *smbConnection, cfg.PoolSize),
	}

	// Pre-populate connection pool
	for i := 0; i < cfg.PoolSize; i++ {
		conn, err := storage.createConnection()
		if err != nil {
			log.Warn().Err(err).Int("attempt", i).Msg("Failed to create initial SMB connection")
			continue
		}
		storage.connPool <- conn
	}

	log.Info().
		Str("host", cfg.Host).
		Int("port", cfg.Port).
		Str("share", cfg.Share).
		Str("path", cfg.Path).
		Int("pool_size", cfg.PoolSize).
		Msg("SMB storage initialized")

	return storage, nil
}

// createConnection creates a new SMB connection
func (s *SMBStorage) createConnection() (*smbConnection, error) {
	// Connect to SMB server (use net.JoinHostPort for IPv6 compatibility)
	addr := net.JoinHostPort(s.config.Host, fmt.Sprintf("%d", s.config.Port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMB server: %w", err)
	}

	// Create SMB dialer
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.config.Username,
			Password: s.config.Password,
			Domain:   s.config.Domain,
		},
	}

	// Establish SMB session
	session, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to establish SMB session: %w", err)
	}

	// Mount share
	share, err := session.Mount(s.config.Share)
	if err != nil {
		_ = session.Logoff()
		_ = conn.Close()
		return nil, fmt.Errorf("failed to mount SMB share: %w", err)
	}

	return &smbConnection{
		conn:    conn,
		session: session,
		share:   share,
		lastUse: time.Now(),
	}, nil
}

// getConnection gets a connection from the pool or creates a new one
func (s *SMBStorage) getConnection() (*smbConnection, error) {
	select {
	case conn := <-s.connPool:
		// Check if connection is still valid (not older than 5 minutes idle)
		if time.Since(conn.lastUse) > 5*time.Minute {
			conn.close()
			return s.createConnection()
		}
		conn.lastUse = time.Now()
		return conn, nil
	default:
		// Pool is empty, create new connection
		return s.createConnection()
	}
}

// returnConnection returns a connection to the pool
func (s *SMBStorage) returnConnection(conn *smbConnection) {
	if conn == nil {
		return
	}

	select {
	case s.connPool <- conn:
		// Successfully returned to pool
	default:
		// Pool is full, close connection
		conn.close()
	}
}

// close closes an SMB connection
func (c *smbConnection) close() {
	if c.share != nil {
		if err := c.share.Umount(); err != nil {
			log.Warn().Err(err).Msg("Failed to unmount SMB share")
		}
	}
	if c.session != nil {
		if err := c.session.Logoff(); err != nil {
			log.Warn().Err(err).Msg("Failed to logoff SMB session")
		}
	}
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close SMB connection")
		}
	}
}

// Get retrieves data from SMB share
func (s *SMBStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	log.Debug().Str("key", path).Msg("Getting file from SMB")

	// Open file
	file, err := conn.share.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound(fmt.Sprintf("SMB file not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to open SMB file")
	}

	// Read entire file into memory (SMB files must be read completely before closing connection)
	data, err := io.ReadAll(file)
	if closeErr := file.Close(); closeErr != nil {
		log.Warn().Err(closeErr).Str("path", path).Msg("Failed to close SMB file after reading")
	}
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read SMB file")
	}

	// Return as ReadCloser
	return io.NopCloser(strings.NewReader(string(data))), nil
}

// Put stores data on SMB share
func (s *SMBStorage) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	conn, err := s.getConnection()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	log.Debug().Str("key", path).Msg("Putting file to SMB")

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := s.ensureDir(conn, dir); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create SMB directory")
	}

	// Read data into buffer to check quota
	buf := new(strings.Builder)
	size, err := io.Copy(buf, data)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to read data")
	}

	// Check quota if set
	if s.maxSizeBytes > 0 {
		currentUsage, err := s.calculateUsage(conn)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to calculate current usage, skipping quota check")
		} else if currentUsage+size > s.maxSizeBytes {
			return errors.QuotaExceeded(s.maxSizeBytes)
		}
	}

	// Create/overwrite file
	file, err := conn.share.Create(path)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to create SMB file")
	}
	defer file.Close()

	// Write data
	_, err = file.Write([]byte(buf.String()))
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to write SMB file")
	}

	return nil
}

// ensureDir ensures a directory exists on SMB share
func (s *SMBStorage) ensureDir(conn *smbConnection, path string) error {
	if path == "" || path == "." || path == "/" {
		return nil
	}

	// Try to stat the directory
	_, err := conn.share.Stat(path)
	if err == nil {
		return nil // Directory exists
	}

	// Create parent directory first
	parent := filepath.Dir(path)
	if parent != path && parent != "." && parent != "/" {
		if err := s.ensureDir(conn, parent); err != nil {
			return err
		}
	}

	// Create this directory
	err = conn.share.Mkdir(path, 0755)
	if err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

// Delete removes data from SMB share
func (s *SMBStorage) Delete(ctx context.Context, key string) error {
	conn, err := s.getConnection()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	log.Debug().Str("key", path).Msg("Deleting file from SMB")

	err = conn.share.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to delete SMB file")
	}

	return nil
}

// Exists checks if data exists on SMB share
func (s *SMBStorage) Exists(ctx context.Context, key string) (bool, error) {
	conn, err := s.getConnection()
	if err != nil {
		return false, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
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

// List returns a list of objects with the given prefix
func (s *SMBStorage) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
	}
	defer s.returnConnection(conn)

	basePath := s.keyToPath(prefix)

	log.Debug().Str("prefix", basePath).Msg("Listing files in SMB")

	var objects []storage.StorageObject

	// Walk the directory tree
	err = s.walkPath(conn, basePath, func(path string, info os.FileInfo) error {
		if info.IsDir() {
			return nil
		}

		// Convert path back to key
		key := s.pathToKey(path)

		objects = append(objects, storage.StorageObject{
			Key:      key,
			Size:     info.Size(),
			Modified: info.ModTime(),
		})

		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to list SMB files")
	}

	return objects, nil
}

// walkPath walks a directory tree on SMB share
func (s *SMBStorage) walkPath(conn *smbConnection, root string, fn func(string, os.FileInfo) error) error {
	// Check if root exists
	info, err := conn.share.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Empty directory
		}
		return err
	}

	// If root is a file, process it directly
	if !info.IsDir() {
		return fn(root, info)
	}

	// List directory contents
	entries, err := conn.share.ReadDir(root)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := filepath.Join(root, entry.Name())

		if err := fn(fullPath, entry); err != nil {
			return err
		}

		// Recurse into subdirectories
		if entry.IsDir() {
			if err := s.walkPath(conn, fullPath, fn); err != nil {
				return err
			}
		}
	}

	return nil
}

// Stat returns metadata about stored data
func (s *SMBStorage) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
	}
	defer s.returnConnection(conn)

	path := s.keyToPath(key)

	info, err := conn.share.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.NotFound(fmt.Sprintf("SMB file not found: %s", key))
		}
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to stat SMB file")
	}

	return &storage.StorageInfo{
		Key:      key,
		Size:     info.Size(),
		Modified: info.ModTime(),
	}, nil
}

// GetQuota returns current usage and quota information
func (s *SMBStorage) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
	conn, err := s.getConnection()
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to get SMB connection")
	}
	defer s.returnConnection(conn)

	usage, err := s.calculateUsage(conn)
	if err != nil {
		return nil, err
	}

	return &storage.QuotaInfo{
		Used:  usage,
		Limit: s.maxSizeBytes,
	}, nil
}

// Health checks if the SMB backend is healthy
func (s *SMBStorage) Health(ctx context.Context) error {
	conn, err := s.getConnection()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "SMB health check failed: cannot get connection")
	}
	defer s.returnConnection(conn)

	// Try to stat the base path
	_, err = conn.share.Stat(s.config.Path)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "SMB health check failed")
	}

	return nil
}

// Close closes the SMB storage backend
func (s *SMBStorage) Close() error {
	close(s.connPool)

	// Close all connections in pool
	for conn := range s.connPool {
		conn.close()
	}

	log.Info().Msg("SMB storage closed")
	return nil
}

// keyToPath converts a storage key to SMB path
func (s *SMBStorage) keyToPath(key string) string {
	// Normalize separators to backslash for SMB
	key = strings.ReplaceAll(key, "/", "\\")

	if s.config.Path == "" {
		return key
	}

	// Use backslash for SMB paths
	return s.config.Path + "\\" + key
}

// pathToKey converts an SMB path to storage key
func (s *SMBStorage) pathToKey(path string) string {
	// Remove base path
	if s.config.Path != "" {
		path = strings.TrimPrefix(path, s.config.Path+"\\")
	}

	// Convert backslashes to forward slashes for consistency
	return strings.ReplaceAll(path, "\\", "/")
}

// calculateUsage calculates total storage usage
func (s *SMBStorage) calculateUsage(conn *smbConnection) (int64, error) {
	var totalSize int64

	basePath := s.config.Path
	if basePath == "" {
		basePath = "\\"
	}

	err := s.walkPath(conn, basePath, func(path string, info os.FileInfo) error {
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to calculate usage: %w", err)
	}

	return totalSize, nil
}
