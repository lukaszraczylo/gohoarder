package auth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// CredentialExtractor extracts authentication credentials from HTTP requests
type CredentialExtractor struct{}

// NewCredentialExtractor creates a new credential extractor
func NewCredentialExtractor() *CredentialExtractor {
	return &CredentialExtractor{}
}

// Extract extracts authentication credentials from an HTTP request
// Returns the full Authorization header value or constructed auth string
func (e *CredentialExtractor) Extract(r *http.Request) string {
	// Try Authorization header first (most common)
	if auth := r.Header.Get("Authorization"); auth != "" {
		return auth
	}

	// Try Basic auth from URL (for PyPI compatibility)
	if username, password, ok := r.BasicAuth(); ok {
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		return "Basic " + auth
	}

	// No credentials found
	return ""
}

// ExtractScheme returns the authentication scheme (Bearer, Basic, Token)
func (e *CredentialExtractor) ExtractScheme(r *http.Request) string {
	auth := e.Extract(r)
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 {
		return parts[0]
	}

	return ""
}

// ExtractToken extracts just the token part (without scheme)
func (e *CredentialExtractor) ExtractToken(r *http.Request) string {
	auth := e.Extract(r)
	if auth == "" {
		return ""
	}

	// Remove scheme prefix
	auth = strings.TrimPrefix(auth, "Bearer ")
	auth = strings.TrimPrefix(auth, "Token ")
	auth = strings.TrimPrefix(auth, "Basic ")

	return auth
}

// HasCredentials checks if request has any credentials
func (e *CredentialExtractor) HasCredentials(r *http.Request) bool {
	return e.Extract(r) != ""
}
