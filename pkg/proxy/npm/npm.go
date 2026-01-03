package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/rs/zerolog/log"
)

// Handler implements the NPM registry protocol
type Handler struct {
	cache           *cache.Manager
	client          *network.Client
	credExtractor   *auth.CredentialExtractor
	credHasher      *auth.CredentialHasher
	credValidator   *auth.NPMValidator
	validationCache *auth.ValidationCache
	upstream        string
}

// Config holds NPM proxy configuration
type Config struct {
	Upstream string // Upstream NPM registry (e.g., registry.npmjs.org)
}

// New creates a new NPM proxy handler
func New(cacheManager *cache.Manager, client *network.Client, config Config) *Handler {
	if config.Upstream == "" {
		config.Upstream = "https://registry.npmjs.org"
	}

	return &Handler{
		cache:           cacheManager,
		client:          client,
		upstream:        config.Upstream,
		credExtractor:   auth.NewCredentialExtractor(),
		credHasher:      auth.NewCredentialHasher(),
		credValidator:   auth.NewNPMValidator(),
		validationCache: auth.NewValidationCache(5 * time.Minute),
	}
}

// ServeHTTP handles NPM registry requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/npm")

	log.Debug().Str("path", path).Str("method", r.Method).Msg("NPM proxy request")

	// Handle different NPM request types
	// Check for tarballs FIRST before special endpoints (tarballs also contain "/-/")
	if isTarballRequest(path) {
		// Package tarball: /@scope/package/-/package-version.tgz
		h.handleTarball(ctx, w, r, path)
	} else if strings.Contains(path, "/-/") {
		// Special NPM endpoints (e.g., /-/ping, /-/user/token)
		h.handleSpecial(ctx, w, r, path)
	} else if isPackageMetadata(path) {
		// Package metadata: /@scope/package or /package
		h.handleMetadata(ctx, w, r, path)
	} else {
		http.Error(w, "Invalid NPM request", http.StatusBadRequest)
	}
}

// handleMetadata handles package metadata requests
func (h *Handler) handleMetadata(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	packageName := extractPackageName(path)

	entry, err := h.cache.Get(ctx, "npm", packageName, "metadata", func(ctx context.Context) (io.ReadCloser, string, error) {
		body, statusCode, err := h.client.Get(ctx, url, nil)
		if err != nil {
			return nil, "", err
		}
		if statusCode != http.StatusOK {
			body.Close() // #nosec G104 -- Cleanup, error not critical
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch package metadata")
		http.Error(w, "Failed to fetch package metadata", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close() // #nosec G104 -- Cleanup, error not critical

	// Read metadata into memory for URL rewriting
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, entry.Data); err != nil {
		log.Error().Err(err).Msg("Failed to read metadata")
		http.Error(w, "Failed to read metadata", http.StatusInternalServerError)
		return
	}

	// Parse JSON metadata
	var metadata map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &metadata); err != nil {
		log.Error().Err(err).Msg("Failed to parse metadata JSON")
		http.Error(w, "Failed to parse metadata", http.StatusInternalServerError)
		return
	}

	// Rewrite tarball URLs to point to our proxy
	proxyBaseURL := getProxyBaseURL(r)
	rewriteMetadataURLs(metadata, h.upstream, proxyBaseURL)

	// Serialize modified metadata
	modifiedJSON, err := json.Marshal(metadata)
	if err != nil {
		log.Error().Err(err).Msg("Failed to serialize modified metadata")
		http.Error(w, "Failed to serialize metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_, _ = w.Write(modifiedJSON) // #nosec G104 -- Websocket buffer write
}

// handleTarball handles package tarball requests
func (h *Handler) handleTarball(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	packageName, version := extractTarballInfo(path)

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)
	credHash := h.credHasher.Hash(credentials)

	// Construct proper upstream URL with /-/ format
	// Format: https://registry.npmjs.org/package/-/package-version.tgz
	tarballFilename := strings.ReplaceAll(packageName, "/", "-") + "-" + version + ".tgz"
	url := fmt.Sprintf("%s/%s/-/%s", h.upstream, packageName, tarballFilename)

	log.Debug().
		Str("path", path).
		Str("package", packageName).
		Str("version", version).
		Str("upstream_url", url).
		Str("cred_hash", credHash).
		Bool("has_credentials", credentials != "").
		Msg("Handling tarball request")

	// Try to get from cache first (with credential-aware key)
	entry, err := h.cache.Get(ctx, "npm", packageName, version, func(ctx context.Context) (io.ReadCloser, string, error) {
		// Prepare headers for upstream request
		headers := make(map[string]string)
		if credentials != "" {
			headers["Authorization"] = credentials
		}

		body, statusCode, err := h.client.Get(ctx, url, headers)
		if err != nil {
			return nil, "", err
		}
		if statusCode != http.StatusOK {
			body.Close() // #nosec G104 -- Cleanup, error not critical
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch package tarball")

		// Check if error is a security violation - return 403 Forbidden
		if ghErr, ok := err.(*errors.Error); ok && ghErr.Code == errors.ErrCodeSecurityViolation {
			http.Error(w, fmt.Sprintf("Package blocked: %s", ghErr.Message), http.StatusForbidden)
			return
		}

		// All other errors return 502 Bad Gateway (upstream issues)
		http.Error(w, "Failed to fetch package tarball", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close() // #nosec G104 -- Cleanup, error not critical

	// CRITICAL SECURITY CHECK: If package requires auth, validate credentials
	if entry.Package != nil && entry.Package.RequiresAuth {
		// Check validation cache first
		allowed, cached, reason := h.validationCache.Get(credHash, url)
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

			allowed, err := h.credValidator.ValidateAccess(ctx, url, credentials)
			if err != nil {
				reason = err.Error()
			}

			// Cache validation result
			h.validationCache.Set(credHash, url, allowed, reason)

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

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, entry.Data) // #nosec G104 -- HTTP response write
}

// handleSpecial handles special NPM endpoints
func (h *Handler) handleSpecial(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path

	// Don't cache special endpoints, proxy directly
	body, statusCode, err := h.client.Get(ctx, url, nil)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch special endpoint")
		http.Error(w, "Failed to fetch from upstream", http.StatusBadGateway)
		return
	}
	defer body.Close() // #nosec G104 -- Cleanup, error not critical

	w.WriteHeader(statusCode)
	_, _ = io.Copy(w, body) // #nosec G104 -- HTTP response write
}

// isTarballRequest checks if the request is for a tarball
func isTarballRequest(path string) bool {
	return strings.HasSuffix(path, ".tgz") || strings.HasSuffix(path, ".tar.gz")
}

// isPackageMetadata checks if the request is for package metadata
func isPackageMetadata(path string) bool {
	// Package metadata doesn't have file extensions
	return !isTarballRequest(path) && !strings.Contains(path, "/-/")
}

// extractPackageName extracts package name from path
func extractPackageName(path string) string {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Handle scoped packages (@scope/package)
	if strings.HasPrefix(path, "@") {
		parts := strings.Split(path, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}

	// Regular package
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return path
}

// extractTarballInfo extracts package name and version from tarball path
func extractTarballInfo(path string) (string, string) {
	// Format: /@scope/package/-/package-version.tgz
	// or: /package/-/package-version.tgz
	// Also handle: /package/package-version.tgz (fallback)

	// Try standard format with /-/
	parts := strings.Split(path, "/-/")
	if len(parts) == 2 {
		packageName := extractPackageName(parts[0])
		tarballName := parts[1]
		tarballName = strings.TrimSuffix(tarballName, ".tgz")
		tarballName = strings.TrimSuffix(tarballName, ".tar.gz")

		// Remove package name prefix to get version
		prefix := strings.ReplaceAll(packageName, "/", "-") + "-"
		version := strings.TrimPrefix(tarballName, prefix)

		return packageName, version
	}

	// Fallback: parse path without /-/
	// Format: /package/package-version.tgz or /@scope/package/package-version.tgz
	path = strings.TrimPrefix(path, "/")
	pathParts := strings.Split(path, "/")

	if len(pathParts) < 2 {
		return "", ""
	}

	var packageName, tarballName string

	// Handle scoped packages
	if strings.HasPrefix(pathParts[0], "@") && len(pathParts) >= 3 {
		packageName = pathParts[0] + "/" + pathParts[1]
		tarballName = pathParts[len(pathParts)-1]
	} else {
		packageName = pathParts[0]
		tarballName = pathParts[len(pathParts)-1]
	}

	tarballName = strings.TrimSuffix(tarballName, ".tgz")
	tarballName = strings.TrimSuffix(tarballName, ".tar.gz")

	// Remove package name prefix to get version
	prefix := strings.ReplaceAll(packageName, "/", "-") + "-"
	version := strings.TrimPrefix(tarballName, prefix)

	return packageName, version
}

// getProxyBaseURL constructs the proxy base URL from the request
func getProxyBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	return fmt.Sprintf("%s://%s/npm", scheme, host)
}

// rewriteMetadataURLs recursively rewrites upstream URLs to proxy URLs in metadata
func rewriteMetadataURLs(data interface{}, upstream, proxyBaseURL string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			if key == "tarball" || key == "dist" {
				// Rewrite tarball URL
				if strVal, ok := value.(string); ok {
					v[key] = strings.Replace(strVal, upstream, proxyBaseURL, 1)
				} else if distMap, ok := value.(map[string]interface{}); ok {
					// Handle dist object with tarball field
					rewriteMetadataURLs(distMap, upstream, proxyBaseURL)
				}
			} else {
				// Recursively process nested objects
				rewriteMetadataURLs(value, upstream, proxyBaseURL)
			}
		}
	case []interface{}:
		for _, item := range v {
			rewriteMetadataURLs(item, upstream, proxyBaseURL)
		}
	}
}
