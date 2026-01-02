package vcs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// CredentialStore manages git credentials for different repository patterns
type CredentialStore struct {
	credentials []CredentialEntry
}

// CredentialEntry represents credentials for a specific pattern
type CredentialEntry struct {
	Pattern  string `json:"pattern"`  // Glob pattern: "github.com/myorg/*"
	Host     string `json:"host"`     // Git host: "github.com"
	Username string `json:"username"` // Usually "oauth2" for tokens
	Token    string `json:"token"`    // Access token
	Fallback bool   `json:"fallback"` // Use as fallback if no match
}

// CredentialConfig represents the JSON configuration format
type CredentialConfig struct {
	Credentials []CredentialEntry `json:"credentials"`
}

// NewCredentialStore creates a new credential store
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make([]CredentialEntry, 0),
	}
}

// LoadFromFile loads credentials from a JSON file
func (cs *CredentialStore) LoadFromFile(path string) error {
	if path == "" {
		log.Debug().Msg("No credential file specified, using system git config")
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Warn().Str("path", path).Msg("Credential file not found, using system git config")
		return nil
	}

	data, err := os.ReadFile(path) // #nosec G304 -- Path is from config, not user input
	if err != nil {
		return fmt.Errorf("failed to read credential file: %w", err)
	}

	var config CredentialConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse credential file: %w", err)
	}

	cs.credentials = config.Credentials

	log.Info().
		Str("file", path).
		Int("credentials", len(cs.credentials)).
		Msg("Loaded git credentials from file")

	// Log patterns (not tokens!) for debugging
	for i, cred := range cs.credentials {
		log.Debug().
			Int("index", i).
			Str("pattern", cred.Pattern).
			Str("host", cred.Host).
			Bool("fallback", cred.Fallback).
			Msg("Registered credential pattern")
	}

	return nil
}

// GetCredentialsForModule finds the best matching credentials for a module path
// Returns (username, token, found)
func (cs *CredentialStore) GetCredentialsForModule(modulePath string) (string, string, bool) {
	if len(cs.credentials) == 0 {
		// No credentials configured, rely on system git config
		return "", "", false
	}

	// Find best match
	var bestMatch *CredentialEntry
	var fallbackMatch *CredentialEntry
	bestMatchLen := 0

	for i := range cs.credentials {
		cred := &cs.credentials[i]

		// Check for fallback
		if cred.Fallback {
			fallbackMatch = cred
			continue
		}

		// Check if pattern matches
		if cs.matchPattern(cred.Pattern, modulePath) {
			// Use longest matching pattern (most specific)
			if len(cred.Pattern) > bestMatchLen {
				bestMatch = cred
				bestMatchLen = len(cred.Pattern)
			}
		}
	}

	// Use best match if found
	if bestMatch != nil {
		log.Debug().
			Str("module", modulePath).
			Str("pattern", bestMatch.Pattern).
			Str("host", bestMatch.Host).
			Msg("Matched credential pattern")
		return bestMatch.Username, bestMatch.Token, true
	}

	// Use fallback if available
	if fallbackMatch != nil {
		log.Debug().
			Str("module", modulePath).
			Str("pattern", fallbackMatch.Pattern).
			Msg("Using fallback credentials")
		return fallbackMatch.Username, fallbackMatch.Token, true
	}

	// No match found
	log.Debug().
		Str("module", modulePath).
		Msg("No credential pattern matched, using system git config")
	return "", "", false
}

// matchPattern checks if a module path matches a credential pattern
// Supports glob-style patterns:
//   - github.com/myorg/* matches github.com/myorg/repo1, github.com/myorg/repo2
//   - github.com/myorg/repo matches exactly github.com/myorg/repo
//   - * matches everything
func (cs *CredentialStore) matchPattern(pattern, modulePath string) bool {
	// Exact match
	if pattern == modulePath {
		return true
	}

	// Wildcard match all
	if pattern == "*" {
		return true
	}

	// Glob-style matching
	matched, err := filepath.Match(pattern, modulePath)
	if err != nil {
		log.Warn().Err(err).Str("pattern", pattern).Msg("Invalid pattern")
		return false
	}

	if matched {
		return true
	}

	// Prefix matching with /*
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(modulePath, prefix+"/")
	}

	return false
}

// CreateNetrcContent creates .netrc file content for a specific host
func (cs *CredentialStore) CreateNetrcContent(host, username, token string) string {
	return fmt.Sprintf("machine %s\nlogin %s\npassword %s\n", host, username, token)
}

// GetCredentialsForHost finds credentials for a specific git host (e.g., "github.com")
// This is useful when you need credentials for a host but don't have a full module path
func (cs *CredentialStore) GetCredentialsForHost(host string) (string, string, bool) {
	if len(cs.credentials) == 0 {
		return "", "", false
	}

	// Look for exact host match first
	for i := range cs.credentials {
		cred := &cs.credentials[i]
		if cred.Host == host && !cred.Fallback {
			log.Debug().
				Str("host", host).
				Str("pattern", cred.Pattern).
				Msg("Found credentials for host")
			return cred.Username, cred.Token, true
		}
	}

	// Try fallback
	for i := range cs.credentials {
		cred := &cs.credentials[i]
		if cred.Fallback {
			log.Debug().
				Str("host", host).
				Msg("Using fallback credentials for host")
			return cred.Username, cred.Token, true
		}
	}

	return "", "", false
}

// ValidateConfig validates the credential configuration
func (cs *CredentialStore) ValidateConfig() error {
	hostPatterns := make(map[string]bool)

	for i, cred := range cs.credentials {
		// Check required fields
		if cred.Pattern == "" {
			return fmt.Errorf("credential entry %d: pattern is required", i)
		}
		if cred.Host == "" && cred.Pattern != "*" {
			return fmt.Errorf("credential entry %d: host is required (pattern: %s)", i, cred.Pattern)
		}
		if cred.Token == "" {
			return fmt.Errorf("credential entry %d: token is required (pattern: %s)", i, cred.Pattern)
		}

		// Set default username if not provided
		if cred.Username == "" {
			cs.credentials[i].Username = "oauth2"
		}

		// Check for duplicate patterns
		key := cred.Pattern + ":" + cred.Host
		if hostPatterns[key] && !cred.Fallback {
			log.Warn().
				Str("pattern", cred.Pattern).
				Str("host", cred.Host).
				Msg("Duplicate credential pattern, last one wins")
		}
		hostPatterns[key] = true
	}

	return nil
}
