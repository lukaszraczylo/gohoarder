package pypi

import "testing"

func TestNegotiateFormat(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   format
		wantOK bool
	}{
		{"no header serves html", "", formatHTML, true},
		{"wildcard serves html", "*/*", formatHTML, true},
		{"browser", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", formatHTML, true},
		{"uv", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.01", formatJSON, true},
		{"pip", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01", formatJSON, true},
		{"explicit html", "application/vnd.pypi.simple.v1+html", formatHTML, true},
		{"latest json alias", "application/vnd.pypi.simple.latest+json", formatJSON, true},
		{"html preferred by q", "application/vnd.pypi.simple.v1+json;q=0.1, text/html", formatHTML, true},
		{"json q zero refused", "application/vnd.pypi.simple.v1+json;q=0, text/html;q=0.5", formatHTML, true},
		{"unsupported only", "application/xml", formatHTML, false},
		{"tie prefers json", "text/html, application/vnd.pypi.simple.v1+json", formatJSON, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := negotiateFormat(tt.accept)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Errorf("negotiateFormat(%q) = (%v, %v), want (%v, %v)", tt.accept, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
