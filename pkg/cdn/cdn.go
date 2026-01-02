package cdn

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

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
	hash := md5.Sum(body)
	return `"` + hex.EncodeToString(hash[:]) + `"`
}

// SetLastModified sets the Last-Modified header
func SetLastModified(w http.ResponseWriter, t time.Time) {
	w.Header().Set("Last-Modified", t.UTC().Format(http.TimeFormat))
}

// SetCacheControl sets a custom Cache-Control header
func SetCacheControl(w http.ResponseWriter, cc CacheControl) {
	w.Header().Set("Cache-Control", cc.String())
}

// SetNoCache sets headers to prevent caching
func SetNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// SetImmutable sets headers for immutable content (content-addressed files)
func SetImmutable(w http.ResponseWriter, maxAge int) {
	cc := CacheControl{
		Public:    true,
		MaxAge:    maxAge,
		Immutable: true,
	}
	w.Header().Set("Cache-Control", cc.String())
}

// responseWriter wraps http.ResponseWriter to capture response
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       []byte
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

// HandleRange handles HTTP Range requests for partial content
func HandleRange(w http.ResponseWriter, r *http.Request, content io.ReadSeeker, size int64, modTime time.Time) error {
	// Set Last-Modified header
	SetLastModified(w, modTime)

	// Check for Range header
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		// No range request - serve full content
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		_, err := io.Copy(w, content)
		return err
	}

	// Parse range header (simplified - only handles single range)
	// Format: bytes=start-end
	var start, end int64
	n, err := fmt.Sscanf(rangeHeader, "bytes=%d-%d", &start, &end)
	if err != nil || n != 2 {
		// Invalid range - serve full content
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		_, err := io.Copy(w, content)
		return err
	}

	// Validate range
	if start < 0 || start >= size || end < start || end >= size {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return nil
	}

	// Seek to start position
	if _, err := content.Seek(start, io.SeekStart); err != nil {
		return err
	}

	// Calculate content length
	contentLength := end - start + 1

	// Set headers for partial content
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)

	// Copy range to response
	_, err = io.CopyN(w, content, contentLength)
	return err
}

// DefaultCacheControl returns sensible defaults for different content types
func DefaultCacheControl(contentType string, versioned bool) CacheControl {
	if versioned {
		// Content-addressed or versioned resources can be cached forever
		return CacheControl{
			Public:    true,
			MaxAge:    31536000, // 1 year
			Immutable: true,
		}
	}

	// Default caching based on content type
	switch contentType {
	case "application/json":
		return CacheControl{
			Public:  true,
			MaxAge:  3600, // 1 hour
			SMaxAge: 7200, // 2 hours for shared caches
		}
	case "application/octet-stream", "application/x-gzip", "application/zip":
		// Binary packages
		return CacheControl{
			Public:  true,
			MaxAge:  86400,  // 1 day
			SMaxAge: 604800, // 1 week for shared caches
		}
	case "text/html":
		// HTML should revalidate
		return CacheControl{
			Public:         true,
			MaxAge:         0,
			MustRevalidate: true,
		}
	default:
		return CacheControl{
			Public:  true,
			MaxAge:  3600, // 1 hour default
			SMaxAge: 7200,
		}
	}
}
