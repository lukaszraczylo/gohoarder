package app

import (
	"context"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/proxy/pypi"
	"github.com/rs/zerolog/log"
)

const pypiRegistry = "pypi"

// migrateLegacyPyPIRecords repairs rows written before PyPI records carried a
// release version. Sidecar rows (".metadata" versions) were never packages, so
// they are deleted with their storage. Other file rows keep their key, and so
// their storage key and cached bytes, and gain the parsed release version.
// Failures are logged: the rows stay usable either way.
func (a *App) migrateLegacyPyPIRecords(ctx context.Context) {
	packages, err := a.metadata.ListPackages(ctx, &metadata.ListOptions{Registry: pypiRegistry})
	if err != nil {
		log.Warn().Err(err).Msg("Skipping legacy PyPI record migration")
		return
	}

	var removed, updated int
	for _, pkg := range packages {
		switch {
		case strings.HasSuffix(pkg.Version, ".metadata"):
			if err := a.cache.Delete(ctx, pypiRegistry, pkg.Name, pkg.Version); err != nil {
				log.Warn().Err(err).Str("package", pkg.Name).Str("version", pkg.Version).Msg("Failed to remove legacy PyPI sidecar row")
				continue
			}
			removed++
		case pkg.ReleaseVersion == "" && isDistributionFile(pkg.Version):
			pkg.ReleaseVersion = pypi.ReleaseVersion(pkg.Version)
			if err := a.metadata.SavePackage(ctx, pkg); err != nil {
				log.Warn().Err(err).Str("package", pkg.Name).Str("version", pkg.Version).Msg("Failed to set release version on PyPI row")
				continue
			}
			updated++
		}
	}
	if removed > 0 || updated > 0 {
		log.Info().Int("sidecars_removed", removed).Int("release_versions_set", updated).Msg("Migrated legacy PyPI records")
	}
}

func isDistributionFile(version string) bool {
	for _, ext := range []string{".whl", ".tar.gz", ".zip", ".egg"} {
		if strings.HasSuffix(version, ext) {
			return true
		}
	}
	return false
}
