package goproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/auth"
	"github.com/lukaszraczylo/gohoarder/pkg/cache"
	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/lukaszraczylo/gohoarder/pkg/vcs"
	"github.com/rs/zerolog/log"
)

// Handler implements the GOPROXY protocol
type Handler struct {
	cache           *cache.Manager
	client          *network.Client
	upstream        string
	sumDBURL        string
	credExtractor   *auth.CredentialExtractor
	credHasher      *auth.CredentialHasher
	credValidator   *auth.GoValidator
	validationCache *auth.ValidationCache
	gitFetcher      *vcs.GitFetcher
	moduleBuilder   *vcs.ModuleBuilder
}

// Config holds Go proxy configuration
type Config struct {
	Upstream  string               // Upstream Go proxy (e.g., proxy.golang.org)
	SumDBURL  string               // Checksum database URL
	CredStore *vcs.CredentialStore // Optional credential store for git access
}

// New creates a new Go proxy handler
func New(cacheManager *cache.Manager, client *network.Client, config Config) *Handler {
	if config.Upstream == "" {
		config.Upstream = "https://proxy.golang.org"
	}

	if config.SumDBURL == "" {
		config.SumDBURL = "https://sum.golang.org"
	}

	// Use provided credential store or create empty one
	credStore := config.CredStore
	if credStore == nil {
		credStore = vcs.NewCredentialStore()
	}

	return &Handler{
		cache:           cacheManager,
		client:          client,
		upstream:        config.Upstream,
		sumDBURL:        config.SumDBURL,
		credExtractor:   auth.NewCredentialExtractor(),
		credHasher:      auth.NewCredentialHasher(),
		credValidator:   auth.NewGoValidator(),
		validationCache: auth.NewValidationCache(5 * time.Minute),
		gitFetcher:      vcs.NewGitFetcher("", credStore),
		moduleBuilder:   vcs.NewModuleBuilder(),
	}
}

// ServeHTTP handles GOPROXY protocol requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Path is already stripped by http.StripPrefix in app.go
	path := r.URL.Path

	log.Debug().
		Str("path", path).
		Msg("Processing Go proxy request")

	// Parse GOPROXY request
	// Formats:
	// /@v/list - list versions
	// /@v/$version.info - version info
	// /@v/$version.mod - go.mod file
	// /@v/$version.zip - module zip
	// /@latest - latest version

	log.Debug().Str("path", path).Msg("Go proxy request")

	// Route request based on path
	if strings.HasPrefix(path, "/sumdb/") {
		h.handleSumDB(ctx, w, r, path)
	} else if strings.HasSuffix(path, "/@v/list") {
		h.handleList(ctx, w, r, path)
	} else if strings.Contains(path, "/@v/") && strings.HasSuffix(path, ".info") {
		h.handleInfo(ctx, w, r, path)
	} else if strings.Contains(path, "/@v/") && strings.HasSuffix(path, ".mod") {
		h.handleMod(ctx, w, r, path)
	} else if strings.Contains(path, "/@v/") && strings.HasSuffix(path, ".zip") {
		h.handleZip(ctx, w, r, path)
	} else if strings.HasSuffix(path, "/@latest") {
		h.handleLatest(ctx, w, r, path)
	} else {
		http.Error(w, "Invalid Go proxy request", http.StatusBadRequest)
	}
}

// handleList handles /@v/list requests
func (h *Handler) handleList(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	modulePath := h.extractModulePath(path)

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)

	entry, err := h.cache.Get(ctx, "go", modulePath, "list", func(ctx context.Context) (io.ReadCloser, string, error) {
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
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch version list")
		http.Error(w, "Failed to fetch version list", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	io.Copy(w, entry.Data)
}

// handleInfo handles /@v/$version.info requests
func (h *Handler) handleInfo(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	modulePath := h.extractModulePath(path)
	version := h.extractVersion(path, ".info")
	// Use .info suffix to distinguish from .mod and .zip in cache
	cacheKey := modulePath + "/@v/" + version + ".info"

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)

	entry, err := h.cache.Get(ctx, "go", cacheKey, version, func(ctx context.Context) (io.ReadCloser, string, error) {
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
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch version info")
		http.Error(w, "Failed to fetch version info", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	io.Copy(w, entry.Data)
}

// handleMod handles /@v/$version.mod requests
func (h *Handler) handleMod(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	modulePath := h.extractModulePath(path)
	version := h.extractVersion(path, ".mod")
	// Use .mod suffix to distinguish from .info and .zip in cache
	cacheKey := modulePath + "/@v/" + version + ".mod"

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)

	entry, err := h.cache.Get(ctx, "go", cacheKey, version, func(ctx context.Context) (io.ReadCloser, string, error) {
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
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch go.mod")
		http.Error(w, "Failed to fetch go.mod", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	io.Copy(w, entry.Data)
}

// handleZip handles /@v/$version.zip requests
func (h *Handler) handleZip(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	modulePath := h.extractModulePath(path)
	version := h.extractVersion(path, ".zip")
	// Use .zip suffix to distinguish from .info and .mod in cache
	cacheKey := modulePath + "/@v/" + version + ".zip"

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)
	credHash := h.credHasher.Hash(credentials)

	log.Debug().
		Str("path", path).
		Str("module", modulePath).
		Str("version", version).
		Str("url", url).
		Str("cred_hash", credHash).
		Bool("has_credentials", credentials != "").
		Msg("Handling Go module zip request")

	entry, err := h.cache.Get(ctx, "go", cacheKey, version, func(ctx context.Context) (io.ReadCloser, string, error) {
		// Prepare headers for upstream request
		headers := make(map[string]string)
		if credentials != "" {
			headers["Authorization"] = credentials
		}

		// Try upstream proxy first (fast path for public modules)
		body, statusCode, err := h.client.Get(ctx, url, headers)
		if err == nil && statusCode == http.StatusOK {
			return body, url, nil
		}

		// If upstream failed with 404 or 403, try git fallback (private modules)
		if statusCode == http.StatusNotFound || statusCode == http.StatusForbidden {
			if body != nil {
				body.Close()
			}

			log.Debug().
				Str("module", modulePath).
				Str("version", version).
				Int("upstream_status", statusCode).
				Msg("Upstream proxy returned not found, trying git fallback")

			return h.fetchModuleFromGit(ctx, modulePath, version, credentials)
		}

		// Other errors
		if body != nil {
			body.Close()
		}
		if err != nil {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch module zip")

		// Check if error is a security violation - return 403 Forbidden
		if ghErr, ok := err.(*errors.Error); ok && ghErr.Code == errors.ErrCodeSecurityViolation {
			http.Error(w, fmt.Sprintf("Package blocked: %s", ghErr.Message), http.StatusForbidden)
			return
		}

		// All other errors return 502 Bad Gateway (upstream issues)
		http.Error(w, "Failed to fetch module zip", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	// CRITICAL SECURITY CHECK: If module requires auth, validate credentials
	if entry.Package != nil && entry.Package.RequiresAuth {
		// Check validation cache first
		allowed, cached, reason := h.validationCache.Get(credHash, modulePath)
		if cached {
			if !allowed {
				log.Warn().
					Str("module", modulePath).
					Str("version", version).
					Str("reason", reason).
					Msg("Access denied (cached validation)")
				http.Error(w, "Module not found", http.StatusNotFound)
				return
			}
			log.Debug().
				Str("module", modulePath).
				Str("version", version).
				Msg("Access granted (cached validation)")
		} else {
			// Validate with upstream using git ls-remote
			log.Debug().
				Str("module", modulePath).
				Str("version", version).
				Str("provider", entry.Package.AuthProvider).
				Msg("Validating credentials with upstream")

			allowed, err := h.credValidator.ValidateAccess(ctx, modulePath, credentials)
			if err != nil {
				reason = err.Error()
			}

			// Cache validation result
			h.validationCache.Set(credHash, modulePath, allowed, reason)

			if !allowed {
				log.Warn().
					Str("module", modulePath).
					Str("version", version).
					Err(err).
					Msg("Access denied by upstream")
				// Return 404 (same as GitHub does for private repos)
				http.Error(w, "Module not found", http.StatusNotFound)
				return
			}

			log.Debug().
				Str("module", modulePath).
				Str("version", version).
				Msg("Access granted by upstream")
		}
	}

	w.Header().Set("Content-Type", "application/zip")
	io.Copy(w, entry.Data)
}

// handleLatest handles /@latest requests
func (h *Handler) handleLatest(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	url := h.upstream + path
	modulePath := h.extractModulePath(path)

	// Extract credentials from request
	credentials := h.credExtractor.Extract(r)

	entry, err := h.cache.Get(ctx, "go", modulePath, "latest", func(ctx context.Context) (io.ReadCloser, string, error) {
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
			body.Close()
			return nil, "", fmt.Errorf("upstream returned status %d", statusCode)
		}
		return body, url, nil
	})

	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch latest version")
		http.Error(w, "Failed to fetch latest version", http.StatusBadGateway)
		return
	}
	defer entry.Data.Close()

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	io.Copy(w, entry.Data)
}

// handleSumDB handles sumdb requests (checksum database)
func (h *Handler) handleSumDB(ctx context.Context, w http.ResponseWriter, r *http.Request, path string) {
	// path format: /sumdb/sum.golang.org/...
	// Remove /sumdb/ prefix and proxy to sumdb URL
	sumdbPath := strings.TrimPrefix(path, "/sumdb/sum.golang.org")
	url := h.sumDBURL + sumdbPath

	log.Debug().Str("url", url).Msg("Proxying sumdb request")

	// Sumdb requests should not be cached, proxy directly
	body, statusCode, err := h.client.Get(ctx, url, nil)
	if err != nil {
		log.Error().Err(err).Str("url", url).Msg("Failed to fetch from sumdb")
		http.Error(w, "Failed to fetch from sumdb", http.StatusBadGateway)
		return
	}
	defer body.Close()

	if statusCode != http.StatusOK {
		log.Error().Int("status", statusCode).Str("url", url).Msg("Sumdb returned non-OK status")
		http.Error(w, "Sumdb error", statusCode)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	io.Copy(w, body)
}

// extractVersion extracts version from path
func (h *Handler) extractVersion(path, suffix string) string {
	// path format: /module/path/@v/v1.2.3.suffix
	parts := strings.Split(path, "/@v/")
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSuffix(parts[1], suffix)
}

// extractModulePath extracts the clean module path from a GOPROXY path
// Examples:
//
//	/github.com/avast/retry-go/v4/@v/v4.6.1.zip -> github.com/avast/retry-go/v4
//	/golang.org/x/net/@v/v0.40.0.mod -> golang.org/x/net
//	/github.com/user/repo/@v/list -> github.com/user/repo
func (h *Handler) extractModulePath(path string) string {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Split on /@v/ to get the module path
	parts := strings.Split(path, "/@v/")
	if len(parts) > 0 {
		return parts[0]
	}

	// Fallback: remove /@latest suffix if present
	return strings.TrimSuffix(path, "/@latest")
}

// fetchModuleFromGit fetches a Go module directly from git repository
func (h *Handler) fetchModuleFromGit(ctx context.Context, modulePath, version, credentials string) (io.ReadCloser, string, error) {
	log.Info().
		Str("module", modulePath).
		Str("version", version).
		Msg("Fetching module from git repository")

	// 1. Fetch module source from git
	srcPath, err := h.gitFetcher.FetchModule(ctx, modulePath, version, credentials)
	if err != nil {
		return nil, "", fmt.Errorf("git fetch failed: %w", err)
	}
	defer h.gitFetcher.Cleanup(srcPath)

	// 2. Validate module
	if err := h.moduleBuilder.ValidateModule(ctx, srcPath, modulePath); err != nil {
		return nil, "", fmt.Errorf("module validation failed: %w", err)
	}

	// 3. Build module zip
	zipReader, err := h.moduleBuilder.BuildModuleZip(ctx, srcPath, modulePath, version)
	if err != nil {
		return nil, "", fmt.Errorf("module zip build failed: %w", err)
	}

	// Create source URL for logging
	sourceURL := fmt.Sprintf("git+https://%s@%s", modulePath, version)

	log.Info().
		Str("module", modulePath).
		Str("version", version).
		Str("source", sourceURL).
		Msg("Successfully built module from git")

	return zipReader, sourceURL, nil
}
