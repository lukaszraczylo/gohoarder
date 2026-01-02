package common

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewBaseHandler tests base handler creation
func TestNewBaseHandler(t *testing.T) {
	// Use nil for cache and client since we're only testing structure
	handler := NewBaseHandler(nil, nil, "npm", "https://registry.npmjs.org")

	require.NotNil(t, handler)
	assert.Equal(t, "npm", handler.Registry)
	assert.Equal(t, "https://registry.npmjs.org", handler.Upstream)
	assert.Nil(t, handler.Cache)
	assert.Nil(t, handler.Client)
}

// TestGetRegistry tests registry type retrieval
func TestGetRegistry(t *testing.T) {
	tests := []struct {
		name     string
		registry string
	}{
		{"npm registry", "npm"},
		{"pypi registry", "pypi"},
		{"go registry", "go"},
		{"custom registry", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &BaseHandler{Registry: tt.registry}
			assert.Equal(t, tt.registry, handler.GetRegistry())
		})
	}
}

// TestHandleUpstreamError tests upstream error handling
func TestHandleUpstreamError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		url         string
		context     string
		wantStatus  int
		wantContain string
	}{
		// GOOD: Standard error
		{
			name:        "connection error",
			err:         errors.New("connection refused"),
			url:         "https://registry.npmjs.org/react",
			context:     "package",
			wantStatus:  http.StatusBadGateway,
			wantContain: "Failed to fetch package",
		},
		// WRONG: Timeout error
		{
			name:        "timeout error",
			err:         context.DeadlineExceeded,
			url:         "https://registry.npmjs.org/lodash",
			context:     "metadata",
			wantStatus:  http.StatusBadGateway,
			wantContain: "Failed to fetch metadata",
		},
		// EDGE: Empty context
		{
			name:        "empty context",
			err:         errors.New("error"),
			url:         "https://example.com",
			context:     "",
			wantStatus:  http.StatusBadGateway,
			wantContain: "Failed to fetch",
		},
		// EDGE: Long URL
		{
			name:        "long URL",
			err:         errors.New("error"),
			url:         "https://registry.npmjs.org/@scope/very-long-package-name/versions/1.2.3",
			context:     "package",
			wantStatus:  http.StatusBadGateway,
			wantContain: "Failed to fetch package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			HandleUpstreamError(w, tt.err, tt.url, tt.context)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantContain)
		})
	}
}

// TestCheckUpstreamStatus tests upstream status validation
func TestCheckUpstreamStatus(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		body        io.ReadCloser
		wantErr     bool
		errContains string
		bodyClosed  bool
	}{
		// GOOD: OK status
		{
			name:       "200 OK",
			statusCode: http.StatusOK,
			body:       io.NopCloser(strings.NewReader("success")),
			wantErr:    false,
		},
		// WRONG: Not found
		{
			name:        "404 Not Found",
			statusCode:  http.StatusNotFound,
			body:        io.NopCloser(strings.NewReader("not found")),
			wantErr:     true,
			errContains: "upstream returned status 404",
		},
		// WRONG: Server error
		{
			name:        "500 Internal Server Error",
			statusCode:  http.StatusInternalServerError,
			body:        io.NopCloser(strings.NewReader("error")),
			wantErr:     true,
			errContains: "upstream returned status 500",
		},
		// BAD: Unauthorized
		{
			name:        "401 Unauthorized",
			statusCode:  http.StatusUnauthorized,
			body:        io.NopCloser(strings.NewReader("unauthorized")),
			wantErr:     true,
			errContains: "upstream returned status 401",
		},
		// EDGE: Nil body
		{
			name:        "nil body with error",
			statusCode:  http.StatusNotFound,
			body:        nil,
			wantErr:     true,
			errContains: "upstream returned status 404",
		},
		// EDGE: Redirect status
		{
			name:        "302 Found",
			statusCode:  http.StatusFound,
			body:        io.NopCloser(strings.NewReader("redirect")),
			wantErr:     true,
			errContains: "upstream returned status 302",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckUpstreamStatus(tt.statusCode, tt.body)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestHandleInvalidRequest tests invalid request handling
func TestHandleInvalidRequest(t *testing.T) {
	tests := []struct {
		name        string
		registry    string
		wantStatus  int
		wantContain string
	}{
		{
			name:        "npm invalid request",
			registry:    "npm",
			wantStatus:  http.StatusBadRequest,
			wantContain: "Invalid npm request",
		},
		{
			name:        "pypi invalid request",
			registry:    "pypi",
			wantStatus:  http.StatusBadRequest,
			wantContain: "Invalid pypi request",
		},
		{
			name:        "go invalid request",
			registry:    "go",
			wantStatus:  http.StatusBadRequest,
			wantContain: "Invalid go request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			HandleInvalidRequest(w, tt.registry)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantContain)
		})
	}
}

// TestHandleInternalError tests internal error handling
func TestHandleInternalError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		context     string
		wantStatus  int
		wantContain string
	}{
		{
			name:        "database error",
			err:         errors.New("database connection failed"),
			context:     "database",
			wantStatus:  http.StatusInternalServerError,
			wantContain: "Internal error: database",
		},
		{
			name:        "cache error",
			err:         errors.New("cache write failed"),
			context:     "cache",
			wantStatus:  http.StatusInternalServerError,
			wantContain: "Internal error: cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			HandleInternalError(w, tt.err, tt.context)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.wantContain)
		})
	}
}

// Note: FetchFromUpstream tests would require mocking cache.Manager and network.Client
// which requires concrete implementations. Integration tests cover this functionality.

// TestWriteResponse tests HTTP response writing
func TestWriteResponse(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		contentType string
		wantStatus  int
		wantBody    string
		wantErr     bool
	}{
		// GOOD: Write tarball
		{
			name:        "write tarball",
			data:        "package data here",
			contentType: "application/octet-stream",
			wantStatus:  http.StatusOK,
			wantBody:    "package data here",
			wantErr:     false,
		},
		// GOOD: Write JSON
		{
			name:        "write JSON metadata",
			data:        `{"name":"react","version":"18.2.0"}`,
			contentType: "application/json",
			wantStatus:  http.StatusOK,
			wantBody:    `{"name":"react","version":"18.2.0"}`,
			wantErr:     false,
		},
		// EDGE: Empty data
		{
			name:        "empty data",
			data:        "",
			contentType: "text/plain",
			wantStatus:  http.StatusOK,
			wantBody:    "",
			wantErr:     false,
		},
		// EDGE: Large data
		{
			name:        "large data",
			data:        strings.Repeat("x", 100000),
			contentType: "application/octet-stream",
			wantStatus:  http.StatusOK,
			wantBody:    strings.Repeat("x", 100000),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			entry := &cache.CacheEntry{
				Data: io.NopCloser(bytes.NewReader([]byte(tt.data))),
			}

			err := WriteResponse(w, entry, tt.contentType)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.contentType, w.Header().Get("Content-Type"))
				assert.Equal(t, tt.wantBody, w.Body.String())
			}
		})
	}
}

// TestBaseHandlerFields tests that BaseHandler fields are properly set
func TestBaseHandlerFields(t *testing.T) {
	handler := NewBaseHandler(nil, nil, "npm", "https://registry.npmjs.org")

	tests := []struct {
		name     string
		field    string
		expected interface{}
	}{
		{"registry field", "registry", "npm"},
		{"upstream field", "upstream", "https://registry.npmjs.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.field {
			case "registry":
				assert.Equal(t, tt.expected, handler.Registry)
			case "upstream":
				assert.Equal(t, tt.expected, handler.Upstream)
			}
		})
	}
}

// TestProxyHandlerInterface tests that BaseHandler can be used as ProxyHandler
func TestProxyHandlerInterface(t *testing.T) {
	handler := NewBaseHandler(nil, nil, "npm", "https://registry.npmjs.org")

	// Verify GetRegistry works
	registry := handler.GetRegistry()
	assert.Equal(t, "npm", registry)
}

// TestConcurrentWriteResponse tests that WriteResponse is safe for concurrent use
func TestConcurrentWriteResponse(t *testing.T) {
	const numGoroutines = 10

	errs := make(chan error, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			w := httptest.NewRecorder()
			data := strings.Repeat("x", 1000)
			entry := &cache.CacheEntry{
				Data: io.NopCloser(bytes.NewReader([]byte(data))),
			}

			err := WriteResponse(w, entry, "text/plain")
			errs <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errs
		assert.NoError(t, err)
	}
}
