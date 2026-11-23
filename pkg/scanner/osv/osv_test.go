package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

// A host-only api_url (the previously documented value) must still reach the
// query endpoint.
func TestScan_HostOnlyAPIURLUsesQueryEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	s := New(config.OSVConfig{APIURL: srv.URL})
	if _, err := s.Scan(context.Background(), "npm", "left-pad", "1.0.0", ""); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if gotPath != "/v1/query" {
		t.Errorf("request path = %q, want /v1/query", gotPath)
	}
}

func TestScan_FullQueryURLIsKept(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	s := New(config.OSVConfig{APIURL: srv.URL + "/v1/query"})
	if _, err := s.Scan(context.Background(), "npm", "left-pad", "1.0.0", ""); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if gotPath != "/v1/query" {
		t.Errorf("request path = %q, want /v1/query", gotPath)
	}
}
