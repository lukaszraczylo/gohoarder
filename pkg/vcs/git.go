package vcs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// GitFetcher handles git repository operations
type GitFetcher struct {
	workDir   string
	timeout   time.Duration
	credStore *CredentialStore
}

// NewGitFetcher creates a new git fetcher
func NewGitFetcher(workDir string, credStore *CredentialStore) *GitFetcher {
	if workDir == "" {
		workDir = os.TempDir()
	}

	if credStore == nil {
		credStore = NewCredentialStore()
	}

	return &GitFetcher{
		workDir:   workDir,
		timeout:   30 * time.Second,
		credStore: credStore,
	}
}

// FetchModule clones a git repository and checks out a specific version
// Returns the path to the checked-out source directory
func (g *GitFetcher) FetchModule(ctx context.Context, modulePath, version, credentials string) (string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	// Parse module path to extract repository URL
	repoURL, err := g.modulePathToRepoURL(modulePath)
	if err != nil {
		return "", err
	}

	// Create temporary directory for this clone
	cloneDir, err := os.MkdirTemp(g.workDir, "gohoarder-git-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	log.Debug().
		Str("module", modulePath).
		Str("version", version).
		Str("repo_url", repoURL).
		Str("clone_dir", cloneDir).
		Msg("Fetching module from git")

	// Set up credentials
	credentialHelper, cleanup, err := g.setupCredentials(repoURL, modulePath, credentials)
	if err != nil {
		os.RemoveAll(cloneDir)
		return "", fmt.Errorf("failed to setup credentials: %w", err)
	}
	defer cleanup()

	// Try shallow clone with specific version first (fastest)
	if err := g.shallowClone(ctx, repoURL, version, cloneDir, credentialHelper); err != nil {
		log.Debug().Err(err).Msg("Shallow clone failed, trying full clone")

		// Fallback to full clone
		if err := g.fullClone(ctx, repoURL, cloneDir, credentialHelper); err != nil {
			os.RemoveAll(cloneDir)
			return "", fmt.Errorf("git clone failed: %w", err)
		}

		// Checkout specific version
		if err := g.checkout(ctx, cloneDir, version); err != nil {
			os.RemoveAll(cloneDir)
			return "", fmt.Errorf("git checkout failed: %w", err)
		}
	}

	log.Debug().
		Str("module", modulePath).
		Str("version", version).
		Str("path", cloneDir).
		Msg("Successfully fetched module from git")

	return cloneDir, nil
}

// modulePathToRepoURL converts a Go module path to a git repository URL
// Examples:
//
//	github.com/user/repo → https://github.com/user/repo.git
//	gitlab.com/group/project → https://gitlab.com/group/project.git
func (g *GitFetcher) modulePathToRepoURL(modulePath string) (string, error) {
	// Remove any path components after the repository
	// e.g., github.com/user/repo/v2 → github.com/user/repo
	parts := strings.Split(modulePath, "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid module path: %s", modulePath)
	}

	// For github.com, gitlab.com, bitbucket.org, etc.
	// Format: host/owner/repo
	host := parts[0]
	owner := parts[1]
	repo := parts[2]

	// Remove version suffix if present (e.g., /v2, /v3)
	repo = strings.TrimPrefix(repo, "v")

	repoURL := fmt.Sprintf("https://%s/%s/%s.git", host, owner, repo)
	return repoURL, nil
}

// setupCredentials configures git credentials for authentication
// Returns credential helper configuration and cleanup function
func (g *GitFetcher) setupCredentials(repoURL, modulePath, credentials string) (map[string]string, func(), error) {
	env := make(map[string]string)
	cleanup := func() {}

	// Priority 1: Check credential store for pattern-based credentials
	if g.credStore != nil {
		username, token, found := g.credStore.GetCredentialsForModule(modulePath)
		if found {
			log.Debug().
				Str("module", modulePath).
				Msg("Using credentials from credential store")
			return g.createTempNetrc(repoURL, username, token)
		}
	}

	// Priority 2: Use credentials from HTTP Authorization header (if provided)
	if credentials != "" {
		log.Debug().Msg("Using credentials from Authorization header")
		return g.createTempNetrcFromHeader(repoURL, credentials)
	}

	// Priority 3: Rely on system git config (.netrc, etc.)
	log.Debug().Msg("No credentials provided, using system git config")
	return env, cleanup, nil
}

// createTempNetrc creates a temporary .netrc file with the provided credentials
func (g *GitFetcher) createTempNetrc(repoURL, username, token string) (map[string]string, func(), error) {
	// Create temporary .netrc file
	tempDir, err := os.MkdirTemp("", "gohoarder-netrc-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp netrc directory: %w", err)
	}

	// Extract host from repo URL
	host := g.extractHost(repoURL)

	// Create .netrc file
	netrcPath := filepath.Join(tempDir, ".netrc")
	netrcContent := fmt.Sprintf("machine %s\nlogin %s\npassword %s\n", host, username, token)
	if err := os.WriteFile(netrcPath, []byte(netrcContent), 0600); err != nil {
		os.RemoveAll(tempDir)
		return nil, nil, fmt.Errorf("failed to write .netrc: %w", err)
	}

	env := map[string]string{
		"HOME":                tempDir,
		"GIT_TERMINAL_PROMPT": "0",
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	log.Debug().Str("host", host).Msg("Created temporary .netrc for git authentication")

	return env, cleanup, nil
}

// createTempNetrcFromHeader creates a temporary .netrc from Authorization header credentials
func (g *GitFetcher) createTempNetrcFromHeader(repoURL, credentials string) (map[string]string, func(), error) {
	// Extract token from credentials
	token := strings.TrimPrefix(credentials, "Bearer ")
	token = strings.TrimPrefix(token, "Token ")
	token = strings.TrimPrefix(token, "Private-Token ")

	if token == "" || token == credentials {
		// Not in expected format, rely on system config
		log.Debug().Msg("Credentials not in Bearer/Token format, using system git config")
		return make(map[string]string), func() {}, nil
	}

	// Use oauth2 as default username for token-based auth
	return g.createTempNetrc(repoURL, "oauth2", token)
}

// extractHost extracts the git host from a repository URL
func (g *GitFetcher) extractHost(repoURL string) string {
	if strings.Contains(repoURL, "github.com") {
		return "github.com"
	}
	if strings.Contains(repoURL, "gitlab.com") {
		return "gitlab.com"
	}
	if strings.Contains(repoURL, "bitbucket.org") {
		return "bitbucket.org"
	}

	// Generic extraction
	parts := strings.Split(repoURL, "/")
	if len(parts) >= 3 {
		return strings.TrimPrefix(parts[2], "//")
	}

	return ""
}

// shallowClone performs a shallow clone of a specific version
func (g *GitFetcher) shallowClone(ctx context.Context, repoURL, version, cloneDir string, credentialHelper map[string]string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--branch", version, repoURL, cloneDir)
	cmd.Env = append(os.Environ(), g.envMapToSlice(credentialHelper)...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("shallow clone failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// fullClone performs a full clone of the repository
func (g *GitFetcher) fullClone(ctx context.Context, repoURL, cloneDir string, credentialHelper map[string]string) error {
	cmd := exec.CommandContext(ctx, "git", "clone", repoURL, cloneDir)
	cmd.Env = append(os.Environ(), g.envMapToSlice(credentialHelper)...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("full clone failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// checkout checks out a specific version (tag, branch, or commit)
func (g *GitFetcher) checkout(ctx context.Context, repoDir, version string) error {
	cmd := exec.CommandContext(ctx, "git", "checkout", version)
	cmd.Dir = repoDir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("checkout failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// envMapToSlice converts environment map to slice
func (g *GitFetcher) envMapToSlice(envMap map[string]string) []string {
	var env []string
	for k, v := range envMap {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

// Cleanup removes temporary directories
func (g *GitFetcher) Cleanup(paths ...string) {
	for _, path := range paths {
		if err := os.RemoveAll(path); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Failed to cleanup temporary directory")
		}
	}
}
