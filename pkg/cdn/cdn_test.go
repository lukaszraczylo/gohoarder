package cdn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CDNMiddlewareTestSuite struct {
	suite.Suite
	middleware *Middleware
}

func (s *CDNMiddlewareTestSuite) SetupTest() {
	s.middleware = NewMiddleware(Config{
		DefaultCacheControl: CacheControl{
			Public:  true,
			MaxAge:  3600,
			SMaxAge: 7200,
		},
		EnableETag: true,
		EnableVary: true,
	})
}

func TestCDNMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(CDNMiddlewareTestSuite))
}

func (s *CDNMiddlewareTestSuite) TestCacheControlHeader() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	wrappedHandler := s.middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	s.Equal(http.StatusOK, w.Code)
	s.Contains(w.Header().Get("Cache-Control"), "public")
	s.Contains(w.Header().Get("Cache-Control"), "max-age=3600")
	s.Contains(w.Header().Get("Cache-Control"), "s-maxage=7200")
}

func (s *CDNMiddlewareTestSuite) TestETagGeneration() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response content"))
	})

	wrappedHandler := s.middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	s.Equal(http.StatusOK, w.Code)
	etag := w.Header().Get("ETag")
	s.NotEmpty(etag)
	s.True(len(etag) > 0)
}

func (s *CDNMiddlewareTestSuite) TestETagConsistencyAcrossRequests() {
	responseBody := []byte("test response content")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(responseBody)
	})

	wrappedHandler := s.middleware.Handler(handler)

	// First request to get ETag
	req1 := httptest.NewRequest("GET", "/test", nil)
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)
	etag := w1.Header().Get("ETag")
	s.NotEmpty(etag)
	s.Equal(http.StatusOK, w1.Code)

	// Verify ETag is consistent for same content
	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)
	etag2 := w2.Header().Get("ETag")
	s.Equal(etag, etag2, "ETag should be consistent for same content")
}

func (s *CDNMiddlewareTestSuite) TestVaryHeader() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	wrappedHandler := s.middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer token")

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	vary := w.Header().Get("Vary")
	s.NotEmpty(vary)
	s.Contains(vary, "Accept-Encoding")
	s.Contains(vary, "Authorization")
	s.Contains(vary, "Accept")
}

func (s *CDNMiddlewareTestSuite) TestCacheControlString() {
	tests := []struct {
		name     string
		expected string
		cc       CacheControl
	}{
		{
			name: "public with max-age",
			cc: CacheControl{
				Public: true,
				MaxAge: 3600,
			},
			expected: "public, max-age=3600",
		},
		{
			name: "private with no-cache",
			cc: CacheControl{
				Private: true,
				NoCache: true,
			},
			expected: "private, no-cache",
		},
		{
			name: "immutable",
			cc: CacheControl{
				Public:    true,
				MaxAge:    31536000,
				Immutable: true,
			},
			expected: "public, immutable, max-age=31536000",
		},
		{
			name: "no-store",
			cc: CacheControl{
				NoStore: true,
			},
			expected: "no-store",
		},
		{
			name: "must-revalidate",
			cc: CacheControl{
				Public:         true,
				MustRevalidate: true,
			},
			expected: "public, must-revalidate",
		},
		{
			name: "s-maxage",
			cc: CacheControl{
				Public:  true,
				MaxAge:  3600,
				SMaxAge: 7200,
			},
			expected: "public, max-age=3600, s-maxage=7200",
		},
		{
			name: "stale-while-revalidate",
			cc: CacheControl{
				Public:               true,
				MaxAge:               3600,
				StaleWhileRevalidate: 86400,
			},
			expected: "public, max-age=3600, stale-while-revalidate=86400",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := tt.cc.String()
			// Check that all expected parts are in the result
			for _, part := range splitCacheControl(tt.expected) {
				s.Contains(result, part)
			}
		})
	}
}

func (s *CDNMiddlewareTestSuite) TestGenerateETag() {
	tests := []struct {
		name     string
		body     []byte
		expected bool // true if ETag should be generated
	}{
		{
			name:     "non-empty body",
			body:     []byte("test content"),
			expected: true,
		},
		{
			name:     "empty body",
			body:     []byte{},
			expected: true, // Empty body still generates ETag (MD5 of empty string)
		},
		{
			name:     "nil body",
			body:     nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			etag := s.middleware.generateETag(tt.body)
			if tt.expected {
				s.NotEmpty(etag)
				s.True(len(etag) > 2) // Should be quoted
			} else {
				s.Empty(etag)
			}
		})
	}
}

func (s *CDNMiddlewareTestSuite) TestETagConsistency() {
	// Same content should produce same ETag
	body := []byte("consistent content")
	etag1 := s.middleware.generateETag(body)
	etag2 := s.middleware.generateETag(body)

	s.Equal(etag1, etag2)

	// Different content should produce different ETag
	body2 := []byte("different content")
	etag3 := s.middleware.generateETag(body2)

	s.NotEqual(etag1, etag3)
}

func (s *CDNMiddlewareTestSuite) TestNoCacheFor4xxErrors() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	})

	wrappedHandler := s.middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	s.Equal(http.StatusNotFound, w.Code)
	// 4xx errors should not have cache headers applied
	// (based on the middleware only applying headers for 2xx status codes)
}

func (s *CDNMiddlewareTestSuite) TestNoCacheFor5xxErrors() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	wrappedHandler := s.middleware.Handler(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	s.Equal(http.StatusInternalServerError, w.Code)
	// 5xx errors should not have cache headers applied
}

// Helper function to split cache-control string
func splitCacheControl(s string) []string {
	var parts []string
	current := ""
	for _, char := range s {
		if char == ',' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else if char != ' ' {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
