// Package pypi implements the HTTP handler that proxies PyPI registry
// requests through the GoHoarder cache.
package pypi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/rs/zerolog/log"
)

// defaultAllowedPyPIHosts is the hardcoded SSRF allowlist for hosts that
// original_url query params may target. Subdomains of pythonhosted.org are
// also accepted (handled in isAllowedPyPIHost).
var defaultAllowedPyPIHosts = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"pythonhosted.org",
}

// isAllowedPyPIHost reports whether host is on the allowlist or a subdomain
// of pythonhosted.org. Comparison is case-insensitive on host only.
func isAllowedPyPIHost(host string, allowed []string) bool {
	host = strings.ToLower(host)
	// Strip optional port
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	for _, a := range allowed {
		a = strings.ToLower(a)
		if host == a {
			return true
		}
	}
	// Allow any subdomain of pythonhosted.org (e.g. files.pythonhosted.org)
	if strings.HasSuffix(host, ".pythonhosted.org") {
		return true
	}
	return false
}

// Handler implements the PyPI Simple API (PEP 503)
type Handler struct {
	cache           *cache.Manager
	client          *network.Client
	credExtractor   *auth.CredentialExtractor
	credHasher      *auth.CredentialHasher
	credValidator   *auth.PyPIValidator
	validationCache *auth.ValidationCache
	upstream        string
	allowedHosts    []string
}

// Config holds PyPI proxy configuration
type Config struct {
	Upstream string // Upstream PyPI index (e.g., pypi.org/simple)
	// AllowedHosts is an SSRF allowlist for hosts that original_url query
	// params may target. If empty, defaultAllowedPyPIHosts is used.
	AllowedHosts []string
}

// New creates a new PyPI proxy handler
func New(cacheManager *cache.Manager, client *network.Client, config Config) *Handler {
	if config.Upstream == "" {
		config.Upstream = "https://pypi.org/simple"
	}

	allowed := config.AllowedHosts
	if len(allowed) == 0 {
		allowed = defaultAllowedPyPIHosts
	}

	return &Handler{
		cache:           cacheManager,
		client:          client,
		upstream:        config.Upstream,
		allowedHosts:    allowed,
		credExtractor:   auth.NewCredentialExtractor(),
		credHasher:      auth.NewCredentialHasher(),
		credValidator:   auth.NewPyPIValidator(),
		validationCache: auth.NewValidationCache(5 * time.Minute),
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

	entry, err := h.cache.Get(ctx, "pypi", "index", "latest", func(ctx context.Context) (*cache.FetchResult, error) {
		body, statusCode, err := h.client.Get(ctx, url, nil)
		if err != nil {
			return nil, err
		}
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			return &cache.FetchResult{Data: body, UpstreamURL: url, RequiresAuth: true, AuthProvider: h.credValidator.Provider()}, nil
		}
		if statusCode != http.StatusOK {
			_ = body.Close()
			return nil, fmt.Errorf("upstream returned status %d", statusCode)
		}
		return &cache.FetchResult{Data: body, UpstreamURL: url}, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch PyPI index")
		http.Error(w, "Failed to fetch PyPI index", http.StatusBadGateway)
		return
	}
	defer func() {
		if cerr := entry.Data.Close(); cerr != nil {
			log.Warn().Err(cerr).Msg("Failed to close PyPI index body")
		}
	}()

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	_, _ = io.Copy(w, entry.Data) // #nosec G104 -- HTTP response write
}

// handlePackagePage handles package page requests
func (h *Handler) handlePackagePage(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	packageName := extractPackageName(path)
	entry, err := h.cache.Get(ctx, "pypi", packageName, "page", func(ctx context.Context) (*cache.FetchResult, error) {
		body, statusCode, err := h.client.Get(ctx, url, nil)
		if err != nil {
			return nil, err
		}
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			return &cache.FetchResult{Data: body, UpstreamURL: url, RequiresAuth: true, AuthProvider: h.credValidator.Provider()}, nil
		}
		if statusCode != http.StatusOK {
			_ = body.Close()
			return nil, fmt.Errorf("upstream returned status %d", statusCode)
		}
		return &cache.FetchResult{Data: body, UpstreamURL: url}, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch package page")
		http.Error(w, "Failed to fetch package page", http.StatusBadGateway)
		return
	}
	defer func() {
		if cerr := entry.Data.Close(); cerr != nil {
			log.Warn().Err(cerr).Msg("Failed to close PyPI package page body")
		}
	}()

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
	_, _ = w.Write([]byte(modifiedHTML)) // #nosec G104 -- Websocket buffer write
}

// handlePackageFile handles package file download requests
func (h *Handler) handlePackageFile(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	packageName, version := extractPackageFileInfo(path)

	// cacheVersion is the cache key's version portion. It must be unique per
	// distinct artifact. PyPI publishes many files per release (multiple
	// wheels with different build tags, sdists, zips, .egg files, and
	// .metadata files for PEP 658), so the bare version is too coarse:
	// distinct files of the same version would collide on the same cache
	// key. The full unique basename guarantees one cache entry per artifact.
	filename := path
	if i := strings.LastIndex(filename, "/"); i >= 0 {
		filename = filename[i+1:]
	}
	cacheVersion := filename

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)
	credHash := h.credHasher.Hash(credentials)

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

		// SSRF protection: validate parsed host against allowlist before
		// fetching. Rejects 169.254.169.254, internal services, etc.
		parsed, parseErr := url.Parse(originalURL)
		if parseErr != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			log.Warn().Str("original_url", originalURL).Msg("Rejected invalid original_url")
			http.Error(w, "Invalid original_url", http.StatusBadRequest)
			return
		}
		if !isAllowedPyPIHost(parsed.Host, h.allowedHosts) {
			log.Warn().
				Str("original_url", originalURL).
				Str("host", parsed.Host).
				Msg("Rejected original_url host not on allowlist")
			http.Error(w, "original_url host not allowed", http.StatusBadRequest)
			return
		}
	}

	log.Debug().
		Str("path", path).
		Str("package", packageName).
		Str("version", version).
		Str("cache_version", cacheVersion).
		Str("url", originalURL).
		Str("cred_hash", credHash).
		Bool("has_credentials", credentials != "").
		Msg("Handling PyPI package file request")

	entry, err := h.cache.Get(ctx, "pypi", packageName, cacheVersion, func(ctx context.Context) (*cache.FetchResult, error) {
		// Prepare headers for upstream request
		headers := make(map[string]string)
		if credentials != "" {
			headers["Authorization"] = credentials
		}

		body, statusCode, err := h.client.Get(ctx, originalURL, headers)
		if err != nil {
			return nil, err
		}
		if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
			return &cache.FetchResult{Data: body, UpstreamURL: originalURL, RequiresAuth: true, AuthProvider: h.credValidator.Provider()}, nil
		}
		if statusCode != http.StatusOK {
			_ = body.Close()
			return nil, fmt.Errorf("upstream returned status %d", statusCode)
		}
		return &cache.FetchResult{Data: body, UpstreamURL: originalURL}, nil
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
	defer func() {
		if cerr := entry.Data.Close(); cerr != nil {
			log.Warn().Err(cerr).Msg("Failed to close PyPI package file body")
		}
	}()

	// CRITICAL SECURITY CHECK: If package requires auth, validate credentials
	// The validation cache is owned by this handler instance only, so the key
	// uses the upstream artifact URL (originalURL). Uniquely identifies the
	// artifact within this registry; no cross-registry collision (goproxy/npm
	// keep their own independent instances).
	if entry.Package != nil && entry.Package.RequiresAuth {
		// Check validation cache first
		allowed, cached, reason := h.validationCache.Get(credHash, originalURL)
		if cached {
			if !allowed {
				log.Warn().
					Str("package", packageName).
					Str("version", version).
					Str("reason", reason).
					Msg("Access denied (cached validation)")
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
			log.Debug().
				Str("package", packageName).
				Str("version", version).
				Msg("Access granted (cached validation)")
		} else {
			// Validate with upstream
			log.Debug().
				Str("package", packageName).
				Str("version", version).
				Str("provider", entry.Package.AuthProvider).
				Msg("Validating credentials with upstream")

			allowed, err := h.credValidator.ValidateAccess(ctx, originalURL, credentials)
			if err != nil {
				reason = err.Error()
			}

			// Cache validation result
			h.validationCache.Set(credHash, originalURL, allowed, reason)

			if !allowed {
				log.Warn().
					Str("package", packageName).
					Str("version", version).
					Err(err).
					Msg("Access denied by upstream")
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}

			log.Debug().
				Str("package", packageName).
				Str("version", version).
				Msg("Access granted by upstream")
		}
	}

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
	_, _ = io.Copy(w, entry.Data) // #nosec G104 -- HTTP response write
}

// isPackagePage checks if the request is for a package page
func isPackagePage(path string) bool {
	// Package pages end with /
	return strings.HasSuffix(path, "/")
}

// isPackageFile checks if the request is for a package file
func isPackageFile(path string) bool {
	// Package files including .metadata files for PEP 658 support
	return strings.HasSuffix(path, ".whl") ||
		strings.HasSuffix(path, ".tar.gz") ||
		strings.HasSuffix(path, ".zip") ||
		strings.HasSuffix(path, ".egg") ||
		strings.HasSuffix(path, ".metadata")
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

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return packageName, ""
	}

	base := parts[len(parts)-1]
	isWheel := strings.HasSuffix(base, ".whl")
	base = strings.TrimSuffix(base, ".whl")
	base = strings.TrimSuffix(base, ".tar.gz")
	base = strings.TrimSuffix(base, ".zip")
	base = strings.TrimSuffix(base, ".egg")
	base = strings.TrimSuffix(base, ".metadata")

	return packageName, extractVersionFromFilename(base, isWheel)
}

// extractVersionFromFilename extracts the version from a PyPI distribution
// filename with the extension already stripped.
//
// Wheels (PEP 427) are formatted as
//
//	{distribution}-{version}(-{build})?-{python}-{abi}-{platform}
//
// and the distribution is normalized (lowercase, runs of '-', '.', '_'
// collapsed to '_'), so it never contains '-' and the version is always the
// second dash-separated segment. For sdists/zips/eggs the filename is
// {name}-{version}; PyPI normalizes name separators to '_', so the version
// is always the last dash-separated segment (PEP 440 versions never contain
// '-').
//
// The historical first-digit-segment heuristic is avoided because it mangles
// digit-embedded distribution names (e.g. "2captcha-1.0.0" → "2captcha") and
// intermediate digit segments (e.g. "foo-2019bar-1.0" → "2019bar"). The last
// digit-starting segment is correct for those cases.
func extractVersionFromFilename(base string, isWheel bool) string {
	if isWheel {
		// The distribution never contains '-', so the version immediately
		// follows the first '-'.
		if parts := strings.SplitN(base, "-", 3); len(parts) >= 2 && parts[1] != "" && parts[1][0] >= '0' && parts[1][0] <= '9' {
			return parts[1]
		}
	}

	// Non-wheel fallback (and defensive wheel edge case): the last
	// dash-separated segment that starts with a digit.
	parts := strings.Split(base, "-")
	for i := len(parts) - 1; i >= 1; i-- {
		if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
			return parts[i]
		}
	}
	return base
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

			// URL encode the original URL — covers &, =, ?, #, +, /, etc.
			encodedURL := url.QueryEscape(originalURL)

			newURL := fmt.Sprintf(`href="%s/%s/%s?original_url=%s"`, baseURL, packageName, filenameMatch, encodedURL)
			return newURL
		}

		return match
	})

	return result
}
