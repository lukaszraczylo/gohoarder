package metadata

import "testing"

func TestIsMetadataEntry(t *testing.T) {
	tests := []struct {
		registry, name, version string
		want                    bool
	}{
		{"npm", "lodash", "metadata", true},
		{"pypi", "foo", "page", true},
		{"go", "example.com/m/@v/list", "list", true},
		{"go", "example.com/m/@v/v1.0.0.mod", "v1.0.0", true},
		{"go", "example.com/m/@v/v1.0.0.info", "v1.0.0", true},
		{"go", "example.com/m/@v/v1.0.0.zip", "v1.0.0", false},
		{"npm", "left.info", "1.0.0", false},
		{"pypi", "foo.mod", "foo.mod-1.0.tar.gz", false},
	}
	for _, tt := range tests {
		if got := IsMetadataEntry(tt.registry, tt.name, tt.version); got != tt.want {
			t.Errorf("IsMetadataEntry(%q, %q, %q) = %v, want %v", tt.registry, tt.name, tt.version, got, tt.want)
		}
	}
}
