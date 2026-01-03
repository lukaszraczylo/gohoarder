package cdn

import (
	"crypto/md5" // #nosec G501 -- MD5 used for ETag generation, not cryptographic security
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// CacheControl represents cache control directives
type CacheControl struct {
	MaxAge               int  // max-age in seconds
	SMaxAge              int  // s-maxage in seconds (for shared caches)
	Public               bool // public directive
	Private              bool // private directive
	NoCache              bool // no-cache directive
	NoStore              bool // no-store directive
	MustRevalidate       bool // must-revalidate directive
	ProxyRevalidate      bool // proxy-revalidate directive
	Immutable            bool // immutable directive
	StaleWhileRevalidate int  // stale-while-revalidate in seconds
}

// String returns the Cache-Control header value
func (cc CacheControl) String() string {
	var parts []string

	if cc.Public {
		parts = append(parts, "public")
	}
	if cc.Private {
		parts = append(parts, "private")
	}
	if cc.NoCache {
		parts = append(parts, "no-cache")
	}
	if cc.NoStore {
		parts = append(parts, "no-store")
	}
	if cc.MustRevalidate {
		parts = append(parts, "must-revalidate")
	}
	if cc.ProxyRevalidate {
		parts = append(parts, "proxy-revalidate")
	}
	if cc.Immutable {
		parts = append(parts, "immutable")
	}
	if cc.MaxAge > 0 {
		parts = append(parts, fmt.Sprintf("max-age=%d", cc.MaxAge))
	}
	if cc.SMaxAge > 0 {
		parts = append(parts, fmt.Sprintf("s-maxage=%d", cc.SMaxAge))
	}
	if cc.StaleWhileRevalidate > 0 {
		parts = append(parts, fmt.Sprintf("stale-while-revalidate=%d", cc.StaleWhileRevalidate))
	}

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += ", "
		}
		result += part
	}
	return result
}

// Middleware provides CDN and HTTP caching functionality
type Middleware struct {
	defaultCacheControl CacheControl
	enableETag          bool
	enableVary          bool
}

// Config holds CDN middleware configuration
type Config struct {
	DefaultCacheControl CacheControl
	EnableETag          bool
	EnableVary          bool
}

// NewMiddleware creates a new CDN middleware
func NewMiddleware(cfg Config) *Middleware {
	return &Middleware{
		defaultCacheControl: cfg.DefaultCacheControl,
		enableETag:          cfg.EnableETag,
		enableVary:          cfg.EnableVary,
	}
}

// Handler wraps an HTTP handler with CDN caching support
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap response writer to capture response for ETag generation
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			body:           nil,
		}

		// Call next handler
		next.ServeHTTP(rw, r)

		// Apply caching headers if successful response
		if rw.statusCode >= 200 && rw.statusCode < 300 {
			m.applyCachingHeaders(rw, r)
		}
	})
}

// applyCachingHeaders applies appropriate caching headers to the response
func (m *Middleware) applyCachingHeaders(w *responseWriter, r *http.Request) {
	// Set Cache-Control header if not already set
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", m.defaultCacheControl.String())
	}

	// Set Vary header for content negotiation
	if m.enableVary {
		m.setVaryHeader(w, r)
	}

	// Generate and check ETag if enabled
	if m.enableETag && w.body != nil {
		m.handleETag(w, r)
	}
}

// setVaryHeader sets the Vary header based on request
func (m *Middleware) setVaryHeader(w *responseWriter, r *http.Request) {
	varies := []string{}

	// Vary on Accept-Encoding for compression
	if r.Header.Get("Accept-Encoding") != "" {
		varies = append(varies, "Accept-Encoding")
	}

	// Vary on Authorization for authenticated requests
	if r.Header.Get("Authorization") != "" {
		varies = append(varies, "Authorization")
	}

	// Vary on Accept for content negotiation
	if r.Header.Get("Accept") != "" {
		varies = append(varies, "Accept")
	}

	if len(varies) > 0 {
		varyHeader := ""
		for i, v := range varies {
			if i > 0 {
				varyHeader += ", "
			}
			varyHeader += v
		}
		w.Header().Set("Vary", varyHeader)
	}
}

// handleETag generates ETag and handles conditional requests
func (m *Middleware) handleETag(w *responseWriter, r *http.Request) {
	// Generate ETag from response body
	etag := m.generateETag(w.body)
	w.Header().Set("ETag", etag)

	// Handle conditional requests
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if ifNoneMatch == etag {
			// ETag matches - return 304 Not Modified
			w.WriteHeader(http.StatusNotModified)
			w.body = nil // Clear body for 304 response
			log.Debug().
				Str("path", r.URL.Path).
				Str("etag", etag).
				Msg("ETag match - returning 304 Not Modified")
			return
		}
	}

	// Handle If-Modified-Since
	if lastModified := w.Header().Get("Last-Modified"); lastModified != "" {
		if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
			lastModTime, err := http.ParseTime(lastModified)
			if err == nil {
				ifModTime, err := http.ParseTime(ifModifiedSince)
				if err == nil && !lastModTime.After(ifModTime) {
					// Not modified - return 304
					w.WriteHeader(http.StatusNotModified)
					w.body = nil
					log.Debug().
						Str("path", r.URL.Path).
						Time("last_modified", lastModTime).
						Msg("Not modified - returning 304")
					return
				}
			}
		}
	}
}

// generateETag creates an ETag for HTTP caching
// NOTE: MD5 is used for content fingerprinting (ETag), not cryptographic security
func (m *Middleware) generateETag(body []byte) string {
	if body == nil {
		return ""
	}
	hash := md5.Sum(body) // #nosec G401 -- MD5 used for ETag, not cryptographic security
	return `"` + hex.EncodeToString(hash[:]) + `"`
}

// responseWriter wraps http.ResponseWriter to capture response
type responseWriter struct {
	http.ResponseWriter
	body       []byte
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Capture body for ETag generation
	if rw.body == nil {
		rw.body = make([]byte, 0, len(b))
	}
	rw.body = append(rw.body, b...)
	return rw.ResponseWriter.Write(b)
}
