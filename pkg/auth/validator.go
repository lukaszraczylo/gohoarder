package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// CredentialValidator validates credentials with upstream registries
type CredentialValidator interface {
	// ValidateAccess checks if credentials grant access to a package
	// Returns (allowed bool, error)
	ValidateAccess(ctx context.Context, packageURL string, credentials string) (bool, error)
}

// NPMValidator validates npm registry credentials
type NPMValidator struct {
	client  *http.Client
	timeout time.Duration
}

// NewNPMValidator creates a new npm credential validator
func NewNPMValidator() *NPMValidator {
	return &NPMValidator{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		timeout: 5 * time.Second,
	}
}

// ValidateAccess validates npm package access using HEAD request
func (v *NPMValidator) ValidateAccess(ctx context.Context, packageURL string, credentials string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", packageURL, nil)
	if err != nil {
		return false, err
	}

	// Add credentials if provided
	if credentials != "" {
		req.Header.Set("Authorization", credentials)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		// Network error - allow cache fallback with warning
		log.Warn().Err(err).Str("url", packageURL).Msg("Validation request failed, allowing cache fallback")
		return true, fmt.Errorf("validation failed: %w (allowing cache fallback)", err)
	}
	defer resp.Body.Close()

	// Check status code
	switch resp.StatusCode {
	case 200, 304:
		// Access granted
		return true, nil
	case 401, 403, 404:
		// Access denied
		return false, fmt.Errorf("access denied: HTTP %d", resp.StatusCode)
	default:
		// Unexpected status - allow cache fallback with warning
		log.Warn().Int("status", resp.StatusCode).Str("url", packageURL).Msg("Unexpected validation status, allowing cache fallback")
		return true, fmt.Errorf("unexpected status %d (allowing cache fallback)", resp.StatusCode)
	}
}

// PyPIValidator validates PyPI registry credentials
type PyPIValidator struct {
	client  *http.Client
	timeout time.Duration
}

// NewPyPIValidator creates a new PyPI credential validator
func NewPyPIValidator() *PyPIValidator {
	return &PyPIValidator{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		timeout: 5 * time.Second,
	}
}

// ValidateAccess validates PyPI package access using HEAD request
func (v *PyPIValidator) ValidateAccess(ctx context.Context, packageURL string, credentials string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", packageURL, nil)
	if err != nil {
		return false, err
	}

	// Add credentials if provided
	if credentials != "" {
		req.Header.Set("Authorization", credentials)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		// Network error - allow cache fallback with warning
		log.Warn().Err(err).Str("url", packageURL).Msg("Validation request failed, allowing cache fallback")
		return true, fmt.Errorf("validation failed: %w (allowing cache fallback)", err)
	}
	defer resp.Body.Close()

	// Check status code
	switch resp.StatusCode {
	case 200, 304:
		// Access granted
		return true, nil
	case 401, 403, 404:
		// Access denied
		return false, fmt.Errorf("access denied: HTTP %d", resp.StatusCode)
	default:
		// Unexpected status - allow cache fallback with warning
		log.Warn().Int("status", resp.StatusCode).Str("url", packageURL).Msg("Unexpected validation status, allowing cache fallback")
		return true, fmt.Errorf("unexpected status %d (allowing cache fallback)", resp.StatusCode)
	}
}

// GoValidator validates Go module credentials
type GoValidator struct {
	timeout time.Duration
}

// NewGoValidator creates a new Go module credential validator
func NewGoValidator() *GoValidator {
	return &GoValidator{
		timeout: 10 * time.Second,
	}
}

// ValidateAccess validates Go module access using git ls-remote
func (v *GoValidator) ValidateAccess(ctx context.Context, modulePath string, credentials string) (bool, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	// Determine repository type and validate accordingly
	if strings.HasPrefix(modulePath, "github.com/") {
		return v.validateGitHub(ctx, modulePath, credentials)
	}

	if strings.HasPrefix(modulePath, "gitlab.com/") {
		return v.validateGitLab(ctx, modulePath, credentials)
	}

	// For other Git providers, use generic git validation
	return v.validateGit(ctx, modulePath, credentials)
}

func (v *GoValidator) validateGitHub(ctx context.Context, modulePath, credentials string) (bool, error) {
	// Extract token from credentials
	token := strings.TrimPrefix(credentials, "Bearer ")
	token = strings.TrimPrefix(token, "Token ")

	if token == "" || token == credentials {
		// No token provided or not in expected format
		return false, fmt.Errorf("no GitHub token provided")
	}

	// Build git URL
	repoURL := fmt.Sprintf("https://%s.git", modulePath)

	// Create temporary directory for .netrc
	tempDir, err := os.MkdirTemp("", "gohoarder-validate-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tempDir)

	// Create .netrc file with credentials
	netrcPath := filepath.Join(tempDir, ".netrc")
	netrcContent := fmt.Sprintf("machine github.com\nlogin oauth2\npassword %s\n", token)
	if err := os.WriteFile(netrcPath, []byte(netrcContent), 0600); err != nil {
		return false, err
	}

	// Run git ls-remote (lightweight, just checks access)
	cmd := exec.CommandContext(ctx, "git", "ls-remote", repoURL, "HEAD")
	cmd.Env = append(os.Environ(),
		"HOME="+tempDir, // Use temp .netrc
		"GIT_TERMINAL_PROMPT=0", // Disable prompts
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check error message
		errMsg := string(output)
		if strings.Contains(errMsg, "could not read Username") ||
			strings.Contains(errMsg, "Authentication failed") ||
			strings.Contains(errMsg, "fatal: repository") ||
			strings.Contains(errMsg, "not found") {
			// Access denied
			return false, fmt.Errorf("access denied: %s", strings.TrimSpace(errMsg))
		}

		// Other error (network, etc.) - allow cache fallback
		log.Warn().Err(err).Str("module", modulePath).Msg("Git validation failed, allowing cache fallback")
		return true, fmt.Errorf("validation error (allowing cache): %w", err)
	}

	// Success - repository accessible
	return true, nil
}

func (v *GoValidator) validateGitLab(ctx context.Context, modulePath, credentials string) (bool, error) {
	// Extract token from credentials
	token := strings.TrimPrefix(credentials, "Bearer ")
	token = strings.TrimPrefix(token, "Token ")
	token = strings.TrimPrefix(token, "Private-Token ")

	if token == "" || token == credentials {
		// No token provided
		return false, fmt.Errorf("no GitLab token provided")
	}

	// Build git URL
	repoURL := fmt.Sprintf("https://%s.git", modulePath)

	// Create temporary directory for .netrc
	tempDir, err := os.MkdirTemp("", "gohoarder-validate-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tempDir)

	// Create .netrc file with credentials
	netrcPath := filepath.Join(tempDir, ".netrc")
	netrcContent := fmt.Sprintf("machine gitlab.com\nlogin oauth2\npassword %s\n", token)
	if err := os.WriteFile(netrcPath, []byte(netrcContent), 0600); err != nil {
		return false, err
	}

	// Run git ls-remote
	cmd := exec.CommandContext(ctx, "git", "ls-remote", repoURL, "HEAD")
	cmd.Env = append(os.Environ(),
		"HOME="+tempDir,
		"GIT_TERMINAL_PROMPT=0",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := string(output)
		if strings.Contains(errMsg, "could not read Username") ||
			strings.Contains(errMsg, "Authentication failed") ||
			strings.Contains(errMsg, "not found") {
			return false, fmt.Errorf("access denied: %s", strings.TrimSpace(errMsg))
		}

		log.Warn().Err(err).Str("module", modulePath).Msg("Git validation failed, allowing cache fallback")
		return true, fmt.Errorf("validation error (allowing cache): %w", err)
	}

	return true, nil
}

func (v *GoValidator) validateGit(ctx context.Context, modulePath, credentials string) (bool, error) {
	// Generic git validation for other providers
	// Similar to GitHub validation but with generic host detection
	repoURL := fmt.Sprintf("https://%s.git", modulePath)

	cmd := exec.CommandContext(ctx, "git", "ls-remote", repoURL, "HEAD")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

	output, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := string(output)
		if strings.Contains(errMsg, "could not read Username") ||
			strings.Contains(errMsg, "Authentication failed") ||
			strings.Contains(errMsg, "not found") {
			return false, fmt.Errorf("access denied: %s", strings.TrimSpace(errMsg))
		}

		log.Warn().Err(err).Str("module", modulePath).Msg("Git validation failed, allowing cache fallback")
		return true, fmt.Errorf("validation error (allowing cache): %w", err)
	}

	return true, nil
}
