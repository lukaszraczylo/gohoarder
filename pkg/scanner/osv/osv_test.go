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

// An advisory that covers the stdlib and x/net lists the stdlib range first; the fixed version
// shown for x/net must come from the x/net range.
func TestScan_FixedVersionComesFromTheQueriedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GO-2026-6612","summary":"s","affected":[
			{"package":{"name":"stdlib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.26.9"}]}]},
			{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.60.0"}]}]}]}]}`))
	}))
	t.Cleanup(srv.Close)

	res, err := New(config.OSVConfig{APIURL: srv.URL}).Scan(context.Background(), "go", "golang.org/x/net/@v/v0.56.0.zip", "v0.56.0", "")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Vulnerabilities) != 1 || res.Vulnerabilities[0].FixedIn != "0.60.0" {
		t.Fatalf("vulnerabilities = %+v, want one fixed in 0.60.0", res.Vulnerabilities)
	}
}
