// Package auth implements API key issuance, validation, and credential
// extraction for upstream-registry pass-through authentication.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// Config controls Manager behaviour. Zero value is valid: bcrypt cost defaults
// to bcrypt.DefaultCost, store is nil (in-memory only).
type Config struct {
	// BcryptCost is the cost parameter passed to bcrypt.GenerateFromPassword.
	// 0 means use bcrypt.DefaultCost. Tests typically use bcrypt.MinCost.
	BcryptCost int
}

// Manager handles authentication and authorization.
//
// Persistence model:
//   - All keys live in an in-memory map keyed by APIKey.ID for O(1) revoke
//     and fast bcrypt iteration during validation.
//   - When a metadata.MetadataStore is wired in via NewWithStore, mutations
//     (Generate, Revoke) are mirrored to the store synchronously and
//     LastUsedAt updates are flushed asynchronously to avoid blocking the
//     hot validation path on a DB round-trip.
//   - When the store is nil, Manager is purely in-memory (back-compat for
//     tests and unconfigured deployments).
type Manager struct {
	keys   map[string]*APIKey
	store  metadata.MetadataStore
	cfg    Config
	mu     sync.RWMutex
	bgWG   sync.WaitGroup
	closed bool
}

// APIKey represents an API key
type APIKey struct {
	ID          string
	Name        string
	HashedKey   string
	Role        Role
	Project     string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	LastUsedAt  time.Time
	Permissions []Permission
}

// Role represents user role
type Role string

const (
	RoleReadOnly  Role = "readonly"
	RoleReadWrite Role = "readwrite"
	RoleAdmin     Role = "admin"
)

// Persistent role identifiers stored in metadata.APIKey.Role. Different from
// the in-memory Role values for backward compatibility with existing API
// surfaces while matching the storage schema described in the spec.
const (
	storedRoleReadOnly  = "read_only"
	storedRoleReadWrite = "read_write"
	storedRoleAdmin     = "admin"
)

// Permission represents a specific permission
type Permission string

const (
	PermissionReadPackage    Permission = "package:read"
	PermissionWritePackage   Permission = "package:write"
	PermissionDeletePackage  Permission = "package:delete"
	PermissionViewStats      Permission = "stats:view"
	PermissionManageKeys     Permission = "keys:manage"
	PermissionManageSettings Permission = "settings:manage"
	PermissionScanPackages   Permission = "scan:execute"
	PermissionManageBypasses Permission = "bypasses:manage"
)

// New creates a new authentication manager (in-memory only).
// Equivalent to NewWithStore(Config{}, nil).
func New() *Manager {
	return NewWithStore(Config{}, nil)
}

// NewWithStore creates a Manager backed by an optional metadata store.
// Pass store=nil for purely in-memory mode (tests, ephemeral setups).
func NewWithStore(cfg Config, store metadata.MetadataStore) *Manager {
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcrypt.DefaultCost
	}
	return &Manager{
		keys:  make(map[string]*APIKey),
		store: store,
		cfg:   cfg,
	}
}

// Load pulls all non-revoked keys from the store into the in-memory map.
// Safe to call multiple times: it replaces the in-memory snapshot.
// No-op when store is nil or returns ErrNotImplemented.
func (m *Manager) Load(ctx context.Context) error {
	if m.store == nil {
		return nil
	}

	stored, err := m.store.ListAPIKeys(ctx)
	if err != nil {
		if stderrors.Is(err, metadata.ErrNotImplemented) {
			return nil
		}
		return err
	}

	loaded := make(map[string]*APIKey, len(stored))
	for _, k := range stored {
		if k == nil || k.Revoked {
			continue
		}
		loaded[k.ID] = storedToMemory(k)
	}

	m.mu.Lock()
	m.keys = loaded
	m.mu.Unlock()

	log.Info().Int("count", len(loaded)).Msg("Loaded API keys from metadata store")
	return nil
}

// GenerateAPIKey generates a new API key.
//
// When a store is configured, the key is persisted before returning. If the
// store rejects the write the in-memory state is rolled back and the error
// is propagated; we never return a key the caller cannot actually use after
// a restart.
func (m *Manager) GenerateAPIKey(name string, role Role, expiresIn *time.Duration) (*APIKey, string, error) {
	// Generate random key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeInternalServer, "failed to generate random key")
	}

	secret := base64.URLEncoding.EncodeToString(keyBytes)
	id := keyPrefix + generateID()
	rawKey := id + keySeparator + secret

	// Hash the key with the configured cost.
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(secret), m.cfg.BcryptCost)
	if err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeInternalServer, "failed to hash key")
	}

	var expiresAt *time.Time
	if expiresIn != nil {
		t := time.Now().Add(*expiresIn)
		expiresAt = &t
	}

	apiKey := &APIKey{
		ID:          id,
		Name:        name,
		HashedKey:   string(hashedKey),
		Role:        role,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Permissions: getPermissionsForRole(role),
	}

	m.mu.Lock()
	m.keys[apiKey.ID] = apiKey
	m.mu.Unlock()

	if m.store != nil {
		stored := memoryToStored(apiKey)
		if err := m.store.SaveAPIKey(context.Background(), stored); err != nil {
			if !stderrors.Is(err, metadata.ErrNotImplemented) {
				// Rollback in-memory insert so caller sees a consistent failure.
				m.mu.Lock()
				delete(m.keys, apiKey.ID)
				m.mu.Unlock()
				return nil, "", errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to persist api key")
			}
		}
	}

	return apiKey, rawKey, nil
}

// Key format: "<id>.<secret>" with id "ghk_<random>". The id is public and selects one stored
// key; the bcrypt hash covers the secret only. Keys minted before the format
// existed have no id in the raw key and hash the whole raw key.
const (
	keyPrefix    = "ghk_"
	keySeparator = "."
	// maxLegacyCompares bounds concurrent bcrypt checks against pre-id keys,
	// which can only be found by trying each one.
	maxLegacyCompares = 4
	// legacyIDLen is the length of base64url(16 bytes).
	legacyIDLen = 24
)

var (
	bcryptCompare = bcrypt.CompareHashAndPassword
	legacySlots   = make(chan struct{}, maxLegacyCompares)
	// dummyHash keeps the cost of an unknown id equal to a wrong secret.
	dummyHash = mustHash("gohoarder-dummy-secret")
)

func mustHash(s string) []byte {
	h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("auth: dummy hash: %v", err))
	}
	return h
}

// ValidateAPIKey validates an API key and returns the associated key object.
// A key with an id costs exactly one bcrypt compare, whatever the number of
// stored keys. LastUsedAt is updated in-memory under the write lock and
// flushed to the store via a fire-and-forget goroutine.
func (m *Manager) ValidateAPIKey(ctx context.Context, rawKey string) (*APIKey, error) {
	var apiKey *APIKey
	if id, secret, ok := splitKey(rawKey); ok {
		apiKey = m.validateByID(id, secret)
	} else {
		apiKey = m.validateLegacy(ctx, rawKey)
	}
	if apiKey == nil {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid API key")
	}

	// Re-check the key still exists to avoid resurrecting a revoked key's metadata.
	usedAt := time.Now()
	m.mu.Lock()
	if _, ok := m.keys[apiKey.ID]; ok {
		apiKey.LastUsedAt = usedAt
	}
	m.mu.Unlock()

	// Async store update: never block validation on a DB write.
	m.persistLastUsedAsync(apiKey.ID, usedAt)
	return apiKey, nil
}

func splitKey(rawKey string) (id, secret string, ok bool) {
	if !strings.HasPrefix(rawKey, keyPrefix) {
		return "", "", false
	}
	return strings.Cut(rawKey, keySeparator)
}

// hasKeyID reports whether k was minted with an id embedded in its raw key.
// Legacy ids are bare generateID output, which is always legacyIDLen long.
func hasKeyID(k *APIKey) bool {
	return strings.HasPrefix(k.ID, keyPrefix) && len(k.ID) > legacyIDLen
}

func (m *Manager) validateByID(id, secret string) *APIKey {
	m.mu.RLock()
	apiKey := m.keys[id]
	m.mu.RUnlock()

	hash := dummyHash
	if apiKey != nil {
		hash = []byte(apiKey.HashedKey)
	}
	err := bcryptCompare(hash, []byte(secret))
	if apiKey == nil || err != nil || expired(apiKey, time.Now()) {
		return nil
	}
	return apiKey
}

func (m *Manager) validateLegacy(ctx context.Context, rawKey string) *APIKey {
	m.mu.RLock()
	candidates := make([]*APIKey, 0, len(m.keys))
	now := time.Now()
	for _, k := range m.keys {
		if !hasKeyID(k) && !expired(k, now) {
			candidates = append(candidates, k)
		}
	}
	m.mu.RUnlock()

	for _, k := range candidates {
		select {
		case legacySlots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		err := bcryptCompare([]byte(k.HashedKey), []byte(rawKey))
		<-legacySlots
		if err == nil {
			return k
		}
	}
	return nil
}

func expired(k *APIKey, now time.Time) bool {
	return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
}

// persistLastUsedAsync flushes a LastUsedAt update to the store off the hot
// path. Errors are logged but not propagated — the validation succeeded
// in-memory and that is the source of truth for liveness.
func (m *Manager) persistLastUsedAsync(id string, t time.Time) {
	if m.store == nil {
		return
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.bgWG.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.bgWG.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.store.UpdateAPIKeyLastUsed(ctx, id, t); err != nil {
			if !stderrors.Is(err, metadata.ErrNotImplemented) {
				log.Warn().Err(err).Str("key_id", id).Msg("Failed to persist api key LastUsedAt")
			}
		}
	}()
}

// RevokeAPIKey revokes an API key. With a store configured, revocation is
// persisted (Revoked=true) so the key remains queryable for audit but never
// authenticates again.
func (m *Manager) RevokeAPIKey(keyID string) error {
	m.mu.Lock()
	existing, ok := m.keys[keyID]
	if !ok {
		m.mu.Unlock()
		return errors.NotFound("API key not found")
	}
	delete(m.keys, keyID)
	m.mu.Unlock()

	if m.store != nil {
		stored := memoryToStored(existing)
		stored.Revoked = true
		if err := m.store.SaveAPIKey(context.Background(), stored); err != nil {
			if !stderrors.Is(err, metadata.ErrNotImplemented) {
				// Rollback: re-add to memory so subsequent validation still
				// sees it (rather than silently leaving a window where the
				// key works in-memory only on this replica).
				m.mu.Lock()
				m.keys[keyID] = existing
				m.mu.Unlock()
				return errors.Wrap(err, errors.ErrCodeStorageFailure, "failed to persist revocation")
			}
		}
	}

	return nil
}

// ListAPIKeys lists all API keys
func (m *Manager) ListAPIKeys() []*APIKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*APIKey, 0, len(m.keys))
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys
}

// Close waits for any in-flight background writes (LastUsedAt updates) to
// finish. Safe to call multiple times.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.mu.Unlock()
	m.bgWG.Wait()
}

// HasPermission checks if an API key has a specific permission
func (k *APIKey) HasPermission(permission Permission) bool {
	for _, p := range k.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// getPermissionsForRole returns permissions for a role
func getPermissionsForRole(role Role) []Permission {
	switch role {
	case RoleReadOnly:
		return []Permission{
			PermissionReadPackage,
			PermissionViewStats,
		}
	case RoleReadWrite:
		return []Permission{
			PermissionReadPackage,
			PermissionWritePackage,
			PermissionViewStats,
		}
	case RoleAdmin:
		return []Permission{
			PermissionReadPackage,
			PermissionWritePackage,
			PermissionDeletePackage,
			PermissionViewStats,
			PermissionManageKeys,
			PermissionManageSettings,
			PermissionScanPackages,
			PermissionManageBypasses,
		}
	default:
		return []Permission{}
	}
}

// generateID generates a unique ID. Panics on crypto/rand failure: a
// zero-byte ID would be a security catastrophe (collisions, predictability).
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("auth: crypto/rand read failed: %v", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}

// memoryToStored converts an in-memory APIKey to its metadata-layer form.
// Permissions are deliberately not encoded here: they are derived from Role
// at load time, keeping the persisted representation compact.
func memoryToStored(k *APIKey) *metadata.APIKey {
	var lastUsed *time.Time
	if !k.LastUsedAt.IsZero() {
		t := k.LastUsedAt
		lastUsed = &t
	}

	return &metadata.APIKey{
		ID:         k.ID,
		KeyHash:    k.HashedKey,
		Project:    k.Project,
		Role:       roleToStored(k.Role),
		CreatedAt:  k.CreatedAt,
		ExpiresAt:  k.ExpiresAt,
		LastUsedAt: lastUsed,
		Revoked:    false,
	}
}

// storedToMemory converts a metadata.APIKey to its runtime form. Permissions
// are derived from Role to keep storage minimal.
func storedToMemory(k *metadata.APIKey) *APIKey {
	role := storedToRole(k.Role)
	out := &APIKey{
		ID:          k.ID,
		Name:        "", // not persisted
		HashedKey:   k.KeyHash,
		Role:        role,
		Project:     k.Project,
		CreatedAt:   k.CreatedAt,
		ExpiresAt:   k.ExpiresAt,
		Permissions: getPermissionsForRole(role),
	}
	if k.LastUsedAt != nil {
		out.LastUsedAt = *k.LastUsedAt
	}
	return out
}

// roleToStored maps the in-memory Role enum to its persisted string form.
func roleToStored(r Role) string {
	switch r {
	case RoleReadOnly:
		return storedRoleReadOnly
	case RoleReadWrite:
		return storedRoleReadWrite
	case RoleAdmin:
		return storedRoleAdmin
	default:
		return string(r)
	}
}

// storedToRole inverts roleToStored. Unknown values fall back to RoleReadOnly
// (least-privilege) rather than failing — guards against schema drift.
func storedToRole(s string) Role {
	switch s {
	case storedRoleAdmin:
		return RoleAdmin
	case storedRoleReadWrite:
		return RoleReadWrite
	case storedRoleReadOnly:
		return RoleReadOnly
	}
	// Tolerate legacy in-memory values that may have been persisted.
	switch Role(s) {
	case RoleAdmin, RoleReadWrite, RoleReadOnly:
		return Role(s)
	}
	return RoleReadOnly
}
