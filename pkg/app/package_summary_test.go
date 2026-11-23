package app

import (
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

func TestPackageSummaryCarriesReleaseVersion(t *testing.T) {
	withRelease := packageSummary(&metadata.Package{Name: "six", Version: "six-1.17.0.tar.gz", ReleaseVersion: "1.17.0"})
	if got := withRelease["release_version"]; got != "1.17.0" {
		t.Errorf("release_version = %v, want 1.17.0", got)
	}
	if got := withRelease["version"]; got != "six-1.17.0.tar.gz" {
		t.Errorf("version = %v, want the cache key", got)
	}
	if _, ok := packageSummary(&metadata.Package{Name: "left-pad", Version: "1.3.0"})["release_version"]; ok {
		t.Error("a row without a release version must not send the field")
	}
}
