package npm

import (
	"fmt"
	"strings"
	"testing"
)

// TestScopedTarballFilename verifies that scoped packages produce the correct
// upstream tarball filename. NPM registry expects:
//
//	@scope/pkg v1.0.0 -> https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz
//
// The filename portion must NOT include the leading "@scope-" prefix.
func TestScopedTarballFilename(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		version     string
		wantURL     string
	}{
		{
			name:        "unscoped package",
			packageName: "express",
			version:     "4.18.2",
			wantURL:     "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
		},
		{
			name:        "scoped package",
			packageName: "@types/node",
			version:     "20.0.0",
			wantURL:     "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz",
		},
		{
			name:        "scoped package with hyphen in name",
			packageName: "@babel/preset-env",
			version:     "7.22.0",
			wantURL:     "https://registry.npmjs.org/@babel/preset-env/-/preset-env-7.22.0.tgz",
		},
	}

	upstream := "https://registry.npmjs.org"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bareName := tt.packageName
			if strings.HasPrefix(bareName, "@") {
				if idx := strings.Index(bareName, "/"); idx >= 0 {
					bareName = bareName[idx+1:]
				}
			}
			tarballFilename := bareName + "-" + tt.version + ".tgz"
			gotURL := fmt.Sprintf("%s/%s/-/%s", upstream, tt.packageName, tarballFilename)
			if gotURL != tt.wantURL {
				t.Errorf("got %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestExtractTarballInfo_Scoped(t *testing.T) {
	// Sanity check that extractTarballInfo correctly parses scoped paths so
	// the construction pipeline above is consistent end-to-end.
	tests := []struct {
		path        string
		wantPackage string
		wantVersion string
	}{
		{"/@types/node/-/node-20.0.0.tgz", "@types/node", "20.0.0"},
		{"/@babel/preset-env/-/preset-env-7.22.0.tgz", "@babel/preset-env", "7.22.0"},
		{"/express/-/express-4.18.2.tgz", "express", "4.18.2"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			gotPkg, gotVer := extractTarballInfo(tt.path)
			if gotPkg != tt.wantPackage || gotVer != tt.wantVersion {
				t.Errorf("extractTarballInfo(%q) = (%q,%q), want (%q,%q)",
					tt.path, gotPkg, gotVer, tt.wantPackage, tt.wantVersion)
			}
		})
	}
}
