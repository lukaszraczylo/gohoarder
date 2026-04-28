// Package nfs implements an NFS-backed storage backend.
//
// NFS is, from Go's perspective, an ordinary mounted filesystem. The user is
// expected to mount the export at cfg.Path before starting the application;
// this package does NOT perform mount(8) calls. It wraps the filesystem
// backend and adds NFS-specific safety:
//
//   - Best-effort mount-type detection (Linux: /proc/mounts). On non-Linux
//     platforms detection is skipped silently. A non-NFS mount is logged at
//     Warn level but is NOT a fatal error so tests/CI can run on local
//     filesystems.
//
//   - Optional per-write fsync (SyncWrites, default true) to flush NFS client
//     caches and improve durability across NFS-cached metadata. Stale handles
//     and "silent" write losses are common NFS pitfalls.
//
//   - A richer Health probe that round-trips a marker file (write, fsync,
//     read, delete) to surface stale handles or read-after-write
//     inconsistencies the bare filesystem health check would miss.
package nfs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/lukaszraczylo/gohoarder/pkg/storage/filesystem"
	"github.com/rs/zerolog"
)

// Config holds NFS storage configuration. The struct is intentionally
// self-contained so callers can map their own config (e.g.
// pkg/config.StorageConfig) without import cycles.
type Config struct {
	// Path is the local mount point of the NFS export. Required.
	Path string
	// MaxSize is the optional quota in bytes (0 = unlimited). Forwarded to
	// the underlying filesystem backend.
	MaxSize int64
	// SyncWrites, when true (default), forces fsync after every successful
	// Put so data is flushed through the NFS client cache to the server.
	SyncWrites bool
}

// Storage implements storage.StorageBackend on top of an NFS-mounted path.
type Storage struct {
	fs         *filesystem.FilesystemStorage
	logger     zerolog.Logger
	path       string
	syncWrites bool
}

// New constructs an NFS storage backend rooted at cfg.Path.
//
// cfg.Path must already exist and be a directory; the caller is responsible
// for the actual NFS mount. Mount-type detection is best-effort.
func New(cfg Config, logger zerolog.Logger) (*Storage, error) {
	if cfg.Path == "" {
		return nil, errors.New(errors.ErrCodeStorageFailure, "nfs: path is required")
	}

	info, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeStorageFailure, "nfs: path does not exist or is inaccessible")
	}
	if !info.IsDir() {
		return nil, errors.New(errors.ErrCodeStorageFailure, fmt.Sprintf("nfs: path is not a directory: %s", cfg.Path))
	}

	// Best-effort mount-type detection. Non-fatal: warn only.
	if mountType, ok := detectMountType(cfg.Path); ok {
		if !isNFSMountType(mountType) {
			logger.Warn().
				Str("path", cfg.Path).
				Str("mount_type", mountType).
				Msg("nfs: configured path is not on an NFS mount; proceeding anyway")
		} else {
			logger.Info().
				Str("path", cfg.Path).
				Str("mount_type", mountType).
				Msg("nfs: detected NFS mount")
		}
	} else {
		// Detection unavailable (non-Linux or /proc/mounts unreadable).
		logger.Debug().
			Str("path", cfg.Path).
			Str("os", runtime.GOOS).
			Msg("nfs: mount-type detection skipped")
	}

	fs, err := filesystem.New(cfg.Path, cfg.MaxSize)
	if err != nil {
		return nil, err
	}

	return &Storage{
		fs:         fs,
		logger:     logger,
		path:       cfg.Path,
		syncWrites: cfg.SyncWrites,
	}, nil
}

// Get delegates to the underlying filesystem backend.
func (s *Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return s.fs.Get(ctx, key)
}

// Put delegates to the filesystem backend and, when SyncWrites is enabled,
// fsyncs the resulting file to flush the NFS client cache.
func (s *Storage) Put(ctx context.Context, key string, data io.Reader, opts *storage.PutOptions) error {
	if err := s.fs.Put(ctx, key, data, opts); err != nil {
		return err
	}
	if !s.syncWrites {
		return nil
	}

	// Resolve the on-disk path via the LocalPathProvider contract the
	// filesystem backend implements. Failure to fsync is logged but not
	// returned: the write itself succeeded; durability is best-effort.
	path, err := s.fs.GetLocalPath(ctx, key)
	if err != nil {
		s.logger.Warn().Err(err).Str("key", key).Msg("nfs: post-put path lookup failed; skipping fsync")
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) // #nosec G304 -- path resolved by sanitizing backend
	if err != nil {
		s.logger.Warn().Err(err).Str("key", key).Msg("nfs: post-put open failed; skipping fsync")
		return nil
	}
	if syncErr := f.Sync(); syncErr != nil {
		s.logger.Warn().Err(syncErr).Str("key", key).Msg("nfs: post-put fsync failed")
	}
	_ = f.Close() // #nosec G104 -- close after sync, error not actionable
	return nil
}

// Delete delegates to the underlying filesystem backend.
func (s *Storage) Delete(ctx context.Context, key string) error {
	return s.fs.Delete(ctx, key)
}

// Exists delegates to the underlying filesystem backend.
func (s *Storage) Exists(ctx context.Context, key string) (bool, error) {
	return s.fs.Exists(ctx, key)
}

// List delegates to the underlying filesystem backend.
func (s *Storage) List(ctx context.Context, prefix string, opts *storage.ListOptions) ([]storage.StorageObject, error) {
	return s.fs.List(ctx, prefix, opts)
}

// Stat delegates to the underlying filesystem backend.
func (s *Storage) Stat(ctx context.Context, key string) (*storage.StorageInfo, error) {
	return s.fs.Stat(ctx, key)
}

// GetQuota delegates to the underlying filesystem backend.
func (s *Storage) GetQuota(ctx context.Context) (*storage.QuotaInfo, error) {
	return s.fs.GetQuota(ctx)
}

// Health checks both the underlying filesystem and runs an NFS-specific
// round-trip probe (write, fsync, read, delete) to surface stale handles or
// cache-coherency issues that a bare stat would miss.
func (s *Storage) Health(ctx context.Context) error {
	if err := s.fs.Health(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	probePath := filepath.Join(s.path, ".nfs_health_probe")
	payload := []byte("nfs-health-probe")

	f, err := os.Create(probePath) // #nosec G304 -- path under configured base, fixed name
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "nfs: cannot create health probe file")
	}
	if _, writeErr := f.Write(payload); writeErr != nil {
		_ = f.Close()            // #nosec G104 -- cleanup
		_ = os.Remove(probePath) // #nosec G104 -- cleanup
		return errors.Wrap(writeErr, errors.ErrCodeStorageFailure, "nfs: cannot write health probe")
	}
	if syncErr := f.Sync(); syncErr != nil {
		_ = f.Close()            // #nosec G104 -- cleanup
		_ = os.Remove(probePath) // #nosec G104 -- cleanup
		return errors.Wrap(syncErr, errors.ErrCodeStorageFailure, "nfs: fsync of health probe failed")
	}
	if closeErr := f.Close(); closeErr != nil {
		_ = os.Remove(probePath) // #nosec G104 -- cleanup
		return errors.Wrap(closeErr, errors.ErrCodeStorageFailure, "nfs: close of health probe failed")
	}

	got, err := os.ReadFile(probePath) // #nosec G304 -- fixed probe path
	if err != nil {
		_ = os.Remove(probePath) // #nosec G104 -- cleanup
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "nfs: read-back of health probe failed (possible stale handle)")
	}
	if string(got) != string(payload) {
		_ = os.Remove(probePath) // #nosec G104 -- cleanup
		return errors.New(errors.ErrCodeStorageFailure, "nfs: health probe payload mismatch (cache coherency issue?)")
	}
	if err := os.Remove(probePath); err != nil {
		return errors.Wrap(err, errors.ErrCodeStorageFailure, "nfs: cannot remove health probe file")
	}
	return nil
}

// Close delegates to the underlying filesystem backend.
func (s *Storage) Close() error {
	return s.fs.Close()
}

// GetLocalPath exposes direct on-disk paths for scanning (NFS exports look
// like local files to callers). Implements storage.LocalPathProvider.
func (s *Storage) GetLocalPath(ctx context.Context, key string) (string, error) {
	return s.fs.GetLocalPath(ctx, key)
}

// detectMountType returns the filesystem type backing path. Linux-only: on
// other platforms the second return value is false. Implementation walks
// /proc/mounts and selects the longest matching mount point, which is the
// canonical way to find which mount owns a path.
func detectMountType(path string) (string, bool) {
	if runtime.GOOS != "linux" {
		return "", false
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}

	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", false
	}

	var (
		bestMount string
		bestType  string
	)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mountPoint := fields[1]
		fsType := fields[2]
		if abs == mountPoint || strings.HasPrefix(abs, strings.TrimRight(mountPoint, "/")+"/") {
			if len(mountPoint) > len(bestMount) {
				bestMount = mountPoint
				bestType = fsType
			}
		}
	}
	if bestMount == "" {
		return "", false
	}
	return bestType, true
}

// isNFSMountType returns true for NFS family mount types.
func isNFSMountType(t string) bool {
	switch t {
	case "nfs", "nfs4":
		return true
	default:
		return false
	}
}
