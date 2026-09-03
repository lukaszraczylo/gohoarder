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

// Hash generates a hash of credentials for use in cache keys.
// Returns "public" if no credentials provided.
// Returns the full 64-char SHA256 hex digest otherwise: truncating to 8 bytes
// gives a ~2^32 birthday bound which is unsafe for a security-sensitive
// cache key (cross-credential cache poisoning).
func (h *CredentialHasher) Hash(credentials string) string {
	if credentials == "" {
		return "public"
	}

	hash := sha256.Sum256([]byte(credentials))
	return hex.EncodeToString(hash[:])
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
