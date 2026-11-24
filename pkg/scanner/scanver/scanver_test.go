package scanver

import "testing"

func TestRecord(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{name: "trivy", output: "Version: 0.58.1\nVulnerability DB:\n  Version: 2\n", want: "0.58.1"},
		{name: "grype", output: "Application:         grype\nVersion:             0.87.0\n", want: "0.87.0"},
		{name: "npm", output: "10.9.2\n", want: "10.9.2"},
		{name: "prerelease", output: "pip-audit 2.8.0rc1", want: "2.8.0rc1"},
		{name: "no version", output: "command not found", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c Cache
			c.Record(tt.output)
			if got := c.Version(); got != tt.want {
				t.Fatalf("Version() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecordKeepsLastGoodVersion(t *testing.T) {
	var c Cache
	c.Record("1.2.3")
	c.Record("garbage")
	if got := c.Version(); got != "1.2.3" {
		t.Fatalf("Version() = %q, want 1.2.3", got)
	}
}
