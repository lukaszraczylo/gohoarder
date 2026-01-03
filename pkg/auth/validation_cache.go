package auth

import (
	"sync"
	"time"
)

// ValidationResult represents a cached credential validation result
type ValidationResult struct {
	ExpiresAt time.Time
	Reason    string
	Allowed   bool
}

// ValidationCache caches credential validation results to reduce upstream checks
type ValidationCache struct {
	cache map[string]*ValidationResult
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewValidationCache creates a new validation cache
func NewValidationCache(ttl time.Duration) *ValidationCache {
	vc := &ValidationCache{
		cache: make(map[string]*ValidationResult),
		ttl:   ttl,
	}

	// Start cleanup goroutine
	go vc.cleanupExpired()

	return vc
}

// Get retrieves a validation result from cache
// Returns (allowed bool, cached bool, reason string)
func (vc *ValidationCache) Get(credHash, packageURL string) (bool, bool, string) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	key := credHash + ":" + packageURL
	result, exists := vc.cache[key]

	if !exists {
		return false, false, ""
	}

	// Check if expired
	if time.Now().After(result.ExpiresAt) {
		return false, false, ""
	}

	return result.Allowed, true, result.Reason
}

// Set stores a validation result in cache
func (vc *ValidationCache) Set(credHash, packageURL string, allowed bool, reason string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	key := credHash + ":" + packageURL
	vc.cache[key] = &ValidationResult{
		Allowed:   allowed,
		ExpiresAt: time.Now().Add(vc.ttl),
		Reason:    reason,
	}
}

// Invalidate removes a specific entry from cache
func (vc *ValidationCache) Invalidate(credHash, packageURL string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	key := credHash + ":" + packageURL
	delete(vc.cache, key)
}

// InvalidateAll clears the entire cache
func (vc *ValidationCache) InvalidateAll() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.cache = make(map[string]*ValidationResult)
}

// Size returns the number of cached entries
func (vc *ValidationCache) Size() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	return len(vc.cache)
}

// cleanupExpired removes expired entries periodically
func (vc *ValidationCache) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		vc.mu.Lock()
		now := time.Now()
		for key, result := range vc.cache {
			if now.After(result.ExpiresAt) {
				delete(vc.cache, key)
			}
		}
		vc.mu.Unlock()
	}
}
