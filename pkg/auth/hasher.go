package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// CredentialHasher generates hashes of credentials for cache keys
type CredentialHasher struct{}

// NewCredentialHasher creates a new credential hasher
func NewCredentialHasher() *CredentialHasher {
	return &CredentialHasher{}
}

// Hash generates a short hash of credentials for use in cache keys
// Returns "public" if no credentials provided
func (h *CredentialHasher) Hash(credentials string) string {
	if credentials == "" {
		return "public"
	}

	// Use SHA256 and take first 16 characters (8 bytes)
	hash := sha256.Sum256([]byte(credentials))
	return hex.EncodeToString(hash[:8])
}

// GenerateCacheKey generates a cache key that includes credential hash
func (h *CredentialHasher) GenerateCacheKey(registry, packageName, version, credentials string) string {
	credHash := h.Hash(credentials)
	return fmt.Sprintf("%s:%s:%s:%s", registry, packageName, version, credHash)
}

// IsPublicKey checks if a cache key is for public packages (no credentials)
func (h *CredentialHasher) IsPublicKey(cacheKey string) bool {
	return len(cacheKey) > 0 && cacheKey[len(cacheKey)-6:] == "public"
}
