package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// Manager handles authentication and authorization
type Manager struct {
	keys map[string]*APIKey
	mu   sync.RWMutex
}

// APIKey represents an API key
type APIKey struct {
	ID          string
	Name        string
	HashedKey   string
	Role        Role
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

// New creates a new authentication manager
func New() *Manager {
	return &Manager{
		keys: make(map[string]*APIKey),
	}
}

// GenerateAPIKey generates a new API key
func (m *Manager) GenerateAPIKey(name string, role Role, expiresIn *time.Duration) (*APIKey, string, error) {
	// Generate random key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeInternalServer, "failed to generate random key")
	}

	rawKey := base64.URLEncoding.EncodeToString(keyBytes)

	// Hash the key
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", errors.Wrap(err, errors.ErrCodeInternalServer, "failed to hash key")
	}

	var expiresAt *time.Time
	if expiresIn != nil {
		t := time.Now().Add(*expiresIn)
		expiresAt = &t
	}

	apiKey := &APIKey{
		ID:          generateID(),
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

	return apiKey, rawKey, nil
}

// ValidateAPIKey validates an API key and returns the associated key object
func (m *Manager) ValidateAPIKey(ctx context.Context, rawKey string) (*APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, apiKey := range m.keys {
		// Check if key is expired
		if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
			continue
		}

		// Compare hashed key
		if err := bcrypt.CompareHashAndPassword([]byte(apiKey.HashedKey), []byte(rawKey)); err == nil {
			// Update last used
			apiKey.LastUsedAt = time.Now()
			return apiKey, nil
		}
	}

	return nil, errors.New(errors.ErrCodeUnauthorized, "invalid API key")
}

// RevokeAPIKey revokes an API key
func (m *Manager) RevokeAPIKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[keyID]; !exists {
		return errors.NotFound("API key not found")
	}

	delete(m.keys, keyID)
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

// generateID generates a unique ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
