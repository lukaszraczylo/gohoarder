package scanner

import (
	stderrors "errors"
	"fmt"
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
)

var errLowDiskSpace = stderrors.New("not enough free disk space to scan")

// checkDiskSpace refuses a scan while the temp dir, where scanners unpack packages, is short
// of space. A failed measurement never blocks scans.
func (m *Manager) checkDiskSpace() error {
	if m.config.MinFreeBytes <= 0 || m.freeBytes == nil {
		return nil
	}
	dir := os.TempDir()
	free, err := m.freeBytes(dir)
	if err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("Cannot measure free disk space")
		return nil
	}
	if need := uint64(m.config.MinFreeBytes); free < need {
		return fmt.Errorf("%w: %d bytes free in %s, need %d", errLowDiskSpace, free, dir, need)
	}
	return nil
}

func diskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), nil // #nosec G115 -- block size is never negative
}
