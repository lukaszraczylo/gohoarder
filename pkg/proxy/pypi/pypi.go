package pypi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/rs/zerolog/log"
)

// Handler implements the PyPI Simple API (PEP 503)
type Handler struct {
	cache    *cache.Manager
	client   *network.Client
	upstream string
}

// Config holds PyPI proxy configuration
type Config struct {
	Upstream string // Upstream PyPI index (e.g., pypi.org/simple)
}

// New creates a new PyPI proxy handler
func New(cacheManager *cache.Manager, client *network.Client, config Config) *Handler {
	if config.Upstream == "" {
		config.Upstream = "https://pypi.org/simple"
	}

	return &Handler{
		cache:    cacheManager,
		client:   client,
		upstream: config.Upstream,
	}
}

// ServeHTTP handles PyPI Simple API requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/pypi")
	// Also trim /simple prefix since upstream already includes it
	path = strings.TrimPrefix(path, "/simple")

	log.Debug().Str("path", path).Str("method", r.Method).Msg("PyPI proxy request")

	// PEP 503 Simple API endpoints:
	// / - index page
	// /{package}/ - package page with links to files

	if path == "/" || path == "" {
		// Index page
		h.handleIndex(ctx, w, r)
	} else if isPackagePage(path) {
		// Package page
		h.handlePackagePage(ctx, w, r, path)
	} else if isPackageFile(path) {
		// Package file download (wheel or sdist)
		h.handlePackageFile(ctx, w, r, path)
	} else {
		http.Error(w, "Invalid PyPI request", http.StatusBadRequest)
	}
}

// handleIndex handles the index page request
func (h *Handler) handleIndex(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	url := h.upstream + "/"

	entry, err := h.cache.Get(ctx, "pypi", "index", "latest", func(ctx context.Context) (io.ReadCloser, string, error) {
		body, statusCode, err := h.client.Get(ctx, url, nil)
		if err != nil {
			return nil, "", err
		}
		if statusCode != http.StatusOK {
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch PyPI index")
		http.Error(w, "Failed to fetch PyPI index", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	io.Copy(w, entry.Data)
}

// handlePackagePage handles package page requests
func (h *Handler) handlePackagePage(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	packageName := extractPackageName(path)

	entry, err := h.cache.Get(ctx, "pypi", packageName, "page", func(ctx context.Context) (io.ReadCloser, string, error) {
		body, statusCode, err := h.client.Get(ctx, url, nil)
		if err != nil {
			return nil, "", err
		}
		if statusCode != http.StatusOK {
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch package page")
		http.Error(w, "Failed to fetch package page", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	// Read page into memory for URL rewriting
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, entry.Data); err != nil {
		log.Error().Err(err).Msg("Failed to read package page")
		http.Error(w, "Failed to read package page", http.StatusInternalServerError)
		return
	}

	// Rewrite package file URLs to point to our proxy
	proxyBaseURL := getProxyBaseURL(r)
	modifiedHTML := rewritePackagePageURLs(buf.String(), packageName, proxyBaseURL)

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write([]byte(modifiedHTML))
}

// handlePackageFile handles package file download requests
func (h *Handler) handlePackageFile(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	packageName, version := extractPackageFileInfo(path)

	// Check if we have the original URL from the rewritten package page
	originalURL := r.URL.Query().Get("original_url")

	// If no original URL provided, fall back to constructing from upstream
	// (this handles direct file requests not from rewritten package pages)
	if originalURL == "" {
		originalURL = h.upstream + path
	} else {
		// Make the URL absolute if it's relative
		if !strings.HasPrefix(originalURL, "http://") && !strings.HasPrefix(originalURL, "https://") {
			originalURL = "https://pypi.org" + originalURL
		}
	}

	entry, err := h.cache.Get(ctx, "pypi", packageName, version, func(ctx context.Context) (io.ReadCloser, string, error) {
		body, statusCode, err := h.client.Get(ctx, originalURL, nil)
		if err != nil {
			return nil, "", err
		}
		if statusCode != http.StatusOK {
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, originalURL, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", originalURL).Msg("Failed to fetch package file")

		// Check if error is a security violation - return 403 Forbidden
		if ghErr, ok := err.(*errors.Error); ok && ghErr.Code == errors.ErrCodeSecurityViolation {
			http.Error(w, fmt.Sprintf("Package blocked: %s", ghErr.Message), http.StatusForbidden)
			return
		}

		// All other errors return 502 Bad Gateway (upstream issues)
		http.Error(w, "Failed to fetch package file", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	// Determine content type based on file extension
	contentType := "application/octet-stream"
	if strings.HasSuffix(path, ".whl") {
		contentType = "application/zip"
	} else if strings.HasSuffix(path, ".tar.gz") {
		contentType = "application/x-gzip"
	} else if strings.HasSuffix(path, ".metadata") {
		contentType = "text/plain; charset=UTF-8"
	}

	w.Header().Set("Content-Type", contentType)
	io.Copy(w, entry.Data)
}

// isPackagePage checks if the request is for a package page
func isPackagePage(path string) bool {
	// Package pages end with /
	return strings.HasSuffix(path, "/")
}

// isPackageFile checks if the request is for a package file
func isPackageFile(path string) bool {
	// Package files (not including .metadata files which need special handling)
	return strings.HasSuffix(path, ".whl") ||
		strings.HasSuffix(path, ".tar.gz") ||
		strings.HasSuffix(path, ".zip") ||
		strings.HasSuffix(path, ".egg")
}

// extractPackageName extracts package name from path
func extractPackageName(path string) string {
	// Remove leading and trailing slashes
	path = strings.Trim(path, "/")

	// Remove /simple/ prefix if present
	path = strings.TrimPrefix(path, "simple/")

	// For package pages: /package-name/
	// For files: /package-name/package-name-version.whl
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return path
}

// extractPackageFileInfo extracts package name and version from file path
func extractPackageFileInfo(path string) (string, string) {
	// Format: /package-name/package-name-version.whl
	// or: /package-name/package-name-version.tar.gz

	packageName := extractPackageName(path)

	// Extract filename
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return packageName, ""
	}

	filename := parts[len(parts)-1]

	// Remove extension
	filename = strings.TrimSuffix(filename, ".whl")
	filename = strings.TrimSuffix(filename, ".tar.gz")
	filename = strings.TrimSuffix(filename, ".zip")
	filename = strings.TrimSuffix(filename, ".egg")

	// Extract version
	// Filename format: package-name-version or package_name-version
	// Version typically starts after last dash before build tags
	versionParts := strings.Split(filename, "-")
	if len(versionParts) >= 2 {
		// Simple heuristic: version is the part that starts with a digit
		for i := 1; i < len(versionParts); i++ {
			if len(versionParts[i]) > 0 && versionParts[i][0] >= '0' && versionParts[i][0] <= '9' {
				return packageName, versionParts[i]
			}
		}
	}

	return packageName, filename
}

// getProxyBaseURL constructs the proxy base URL from the request
func getProxyBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	return fmt.Sprintf("%s://%s/pypi", scheme, host)
}

// rewritePackagePageURLs rewrites package file URLs in HTML to point to proxy
func rewritePackagePageURLs(html, packageName, proxyBaseURL string) string {
	// PyPI Simple API uses href attributes in anchor tags
	// We need to rewrite URLs pointing to files.pythonhosted.org or pypi.org
	// We preserve the original URL as a query parameter so we can fetch from the correct CDN

	// Regex pattern to match href URLs pointing to package files
	// Matches: href="https://files.pythonhosted.org/packages/.../filename.whl"
	// Also matches: href="../../packages/.../filename.whl"
	pattern := regexp.MustCompile(`href="([^"]*?(\.whl|\.tar\.gz|\.zip|\.egg)[^"]*?)"`)

	result := pattern.ReplaceAllStringFunc(html, func(match string) string {
		// Extract the full URL and filename
		urlPattern := regexp.MustCompile(`href="([^"]+)"`)
		urlMatch := urlPattern.FindStringSubmatch(match)
		if len(urlMatch) < 2 {
			return match
		}

		originalURL := urlMatch[1]

		// Extract just the filename
		filenamePattern := regexp.MustCompile(`([^/]+\.(whl|tar\.gz|zip|egg))`)
		filenameMatch := filenamePattern.FindString(originalURL)

		if filenameMatch != "" {
			// Rewrite to proxy URL format: /pypi/package-name/filename?original_url=...
			// This preserves the original CDN URL so we can fetch from the correct location
			baseURL := strings.TrimSuffix(proxyBaseURL, "/simple")

			// URL encode the original URL
			encodedURL := strings.ReplaceAll(originalURL, "&", "%26")
			encodedURL = strings.ReplaceAll(encodedURL, "=", "%3D")

			newURL := fmt.Sprintf(`href="%s/%s/%s?original_url=%s"`, baseURL, packageName, filenameMatch, encodedURL)
			return newURL
		}

		return match
	})

	return result
}
