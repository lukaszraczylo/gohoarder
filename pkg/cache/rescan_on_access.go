package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/rs/zerolog/log"
)

// refreshStaleScan rescans a cache hit whose scan result is missing or older than
// Config.RescanAfter, so the verdict served is never older than that interval. It
// waits up to ScanWaitTimeout; on a timeout or scan failure the previous verdict
// stands, or the miss-path rule applies when there is none.
func (m *Manager) refreshStaleScan(ctx context.Context, registry, name, version string) error {
	if m.config.RescanAfter <= 0 {
		return nil
	}

	prev, err := m.metadata.GetScanResult(ctx, registry, name, version)
	hasPrev := err == nil && prev != nil
	if hasPrev && m.now().Sub(prev.ScannedAt) < m.config.RescanAfter {
		return nil
	}

	key := fmt.Sprintf("%s/%s/%s", registry, name, version)
	done := m.rescanSF.DoChan(key, func() (interface{}, error) {
		return nil, m.rescanArtifact(registry, name, version)
	})

	timer := time.NewTimer(m.config.ScanWaitTimeout)
	defer timer.Stop()

	select {
	case res := <-done:
		if res.Err == nil {
			return nil
		}
		log.Warn().Err(res.Err).Str("package", name).Str("version", version).Msg("Rescan on access failed")
	case <-timer.C:
		log.Warn().Str("package", name).Str("version", version).Msg("Rescan on access timed out, scan continues in background")
	case <-ctx.Done():
		return ctx.Err()
	}

	if hasPrev {
		log.Warn().Str("package", name).Str("version", version).Time("scanned_at", prev.ScannedAt).
			Msg("Serving decision uses the previous scan result")
		return nil
	}
	if m.config.FailClosed {
		log.Warn().Str("package", name).Str("version", version).
			Msg("No scan result and rescan unfinished - refusing to serve (fail-closed)")
		return errors.New(errors.ErrCodeServiceUnavailable, "package scan in progress, retry shortly")
	}
	log.Warn().Str("package", name).Str("version", version).
		Msg("No scan result and rescan unfinished - serving package, scan continues in background")
	return nil
}

// rescanArtifact scans the cached artifact under the manager's background context so a
// client disconnect does not abort it.
func (m *Manager) rescanArtifact(registry, name, version string) error {
	path, cleanup, err := m.ScanFile(m.bgCtx, registry, name, version)
	if err != nil {
		return err
	}
	defer cleanup()
	return m.scanner.ScanPackage(m.bgCtx, registry, name, version, path)
}
