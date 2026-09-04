package app

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func reqWithOrigin(origin string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/ws", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Host = "app.example.com"
	return r
}

// TestBuildCheckOrigin_DefaultPortNormalization verifies that scheme-default
// ports (443/80) are ignored, so "https://app.example.com" and
// "https://app.example.com:443" are treated as the same origin.
func TestBuildCheckOrigin_DefaultPortNormalization(t *testing.T) {
	check := buildCheckOrigin([]string{"https://app.example.com"})

	assert.True(t, check(reqWithOrigin("https://app.example.com")))
	assert.True(t, check(reqWithOrigin("https://app.example.com:443")))
	assert.False(t, check(reqWithOrigin("https://app.example.com:8443")))

	// Default http port strips too.
	checkHTTP := buildCheckOrigin([]string{"http://app.example.com"})
	assert.True(t, checkHTTP(reqWithOrigin("http://app.example.com:80")))
	assert.True(t, checkHTTP(reqWithOrigin("http://app.example.com")))
}

// TestBuildCheckOrigin_NonDefaultPortPreserved verifies a non-default port is
// not stripped and must match exactly.
func TestBuildCheckOrigin_NonDefaultPortPreserved(t *testing.T) {
	check := buildCheckOrigin([]string{"https://app.example.com:8443"})

	assert.True(t, check(reqWithOrigin("https://app.example.com:8443")))
	assert.False(t, check(reqWithOrigin("https://app.example.com")))
}

// TestBuildCheckOrigin_Wildcard verifies wildcard host patterns match the apex
// and subdomains, and are unaffected by ports on the incoming origin.
func TestBuildCheckOrigin_Wildcard(t *testing.T) {
	check := buildCheckOrigin([]string{"https://*.example.com"})

	assert.True(t, check(reqWithOrigin("https://example.com")))
	assert.True(t, check(reqWithOrigin("https://cdn.example.com")))
	assert.True(t, check(reqWithOrigin("https://cdn.example.com:443")))
	assert.False(t, check(reqWithOrigin("https://example.org")))
}

// TestBuildCheckOrigin_SchemeMismatch verifies the scheme must match.
func TestBuildCheckOrigin_SchemeMismatch(t *testing.T) {
	check := buildCheckOrigin([]string{"https://app.example.com"})

	assert.False(t, check(reqWithOrigin("http://app.example.com")))
}

// TestBuildCheckOrigin_SameOriginFallback verifies that with an empty allowlist
// only a same-origin upgrade (matching Host) is permitted.
func TestBuildCheckOrigin_SameOriginFallback(t *testing.T) {
	check := buildCheckOrigin(nil)

	r := reqWithOrigin("https://app.example.com")
	assert.True(t, check(r))

	// Host defaults to app.example.com; a different Origin host is rejected.
	r2 := reqWithOrigin("https://other.example.com")
	assert.False(t, check(r2))
}
