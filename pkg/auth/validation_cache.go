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

// ValidationCache caches credential validation results to reduce upstream checks.
//
// Scope: each instance is owned by exactly one proxy handler (goproxy, npm,
// or pypi) and caches only that registry's credential checks. Because the
// instances are never shared across handlers, the second key component may be
// whatever uniquely identifies the resource for that registry: goproxy passes
// a module path, npm and pypi pass a URL. There is no cross-registry key
// collision even though the resource shapes differ, because each handler has
// its own map. Callers must pass the same resource value to every Get/Set for
// a given resource so the cache miss wrapper (Get then Set) is internally
// consistent.
type ValidationCache struct {
	cache    map[string]*ValidationResult
	stopCh   chan struct{}
	stopOnce sync.Once
	mu       sync.RWMutex
	ttl      time.Duration
}

// NewValidationCache creates a new validation cache. Callers must call Stop()
// during shutdown to terminate the background cleanup goroutine.
func NewValidationCache(ttl time.Duration) *ValidationCache {
	vc := &ValidationCache{
		cache:  make(map[string]*ValidationResult),
		stopCh: make(chan struct{}),
		ttl:    ttl,
	}

	// Start cleanup goroutine
	go vc.cleanupExpired()
	return vc
}

// Get retrieves a validation result from cache.
// resource names the registry resource the check was for (a module path for
// goproxy, or a URL for npm/pypi). It is only meaningful within this cache
// instance. Returns (allowed bool, cached bool, reason string).
func (vc *ValidationCache) Get(credHash, resource string) (bool, bool, string) {
	key := credHash + ":" + resource

	// Fast path: read-locked lookup.
	vc.mu.RLock()
	result, exists := vc.cache[key]
	if !exists {
		vc.mu.RUnlock()
		return false, false, ""
	}
	expired := time.Now().After(result.ExpiresAt)
	if !expired {
		allowed, reason := result.Allowed, result.Reason
		vc.mu.RUnlock()
		return allowed, true, reason
	}
	vc.mu.RUnlock()

	// Expired: drop it under the write lock so callers don't all stampede
	// the upstream while waiting for the periodic cleanup goroutine.
	vc.mu.Lock()
	if cur, ok := vc.cache[key]; ok && time.Now().After(cur.ExpiresAt) {
		delete(vc.cache, key)
	}
	vc.mu.Unlock()
	return false, false, ""
}

// Set stores a validation result in cache.
// resource is the registry resource the result belongs to; it must match the
// resource value passed to the corresponding Get.
func (vc *ValidationCache) Set(credHash, resource string, allowed bool, reason string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	key := credHash + ":" + resource
	vc.cache[key] = &ValidationResult{
		Allowed:   allowed,
		ExpiresAt: time.Now().Add(vc.ttl),
		Reason:    reason,
	}
}

// Invalidate removes a specific entry from cache.
func (vc *ValidationCache) Invalidate(credHash, resource string) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	key := credHash + ":" + resource
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

// cleanupExpired removes expired entries periodically. Exits when Stop is
// called.
func (vc *ValidationCache) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-vc.stopCh:
			return
		case <-ticker.C:
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
}
