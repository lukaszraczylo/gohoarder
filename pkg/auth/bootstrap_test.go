package auth

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"golang.org/x/crypto/bcrypt"
)

func TestBootstrapAdminFromEnv_EnvEmpty_NoOp(t *testing.T) {
	t.Setenv(BootstrapAdminEnvVar, "")
	store := newFakeStore()

	if err := BootstrapAdminFromEnv(context.Background(), store, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}
	if got := len(store.keys); got != 0 {
		t.Errorf("store has %d keys, want 0 when env empty", got)
	}
}

func TestBootstrapAdminFromEnv_NilStore_NoOp(t *testing.T) {
	t.Setenv(BootstrapAdminEnvVar, "secret")
	if err := BootstrapAdminFromEnv(context.Background(), nil, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv(nil store): %v", err)
	}
}

func TestBootstrapAdminFromEnv_FreshStore_CreatesAdmin(t *testing.T) {
	const raw = "super-secret-bootstrap-key"
	t.Setenv(BootstrapAdminEnvVar, raw)
	store := newFakeStore()

	if err := BootstrapAdminFromEnv(context.Background(), store, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}

	if got := len(store.keys); got != 1 {
		t.Fatalf("store has %d keys, want 1", got)
	}

	var created *metadata.APIKey
	for _, k := range store.keys {
		created = k
		break
	}
	if created.Role != storedRoleAdmin {
		t.Errorf("Role = %q, want %q", created.Role, storedRoleAdmin)
	}
	if created.Project != bootstrapProject {
		t.Errorf("Project = %q, want %q", created.Project, bootstrapProject)
	}
	if created.Revoked {
		t.Errorf("Revoked = true, want false")
	}
	if created.ID == "" {
		t.Errorf("ID empty")
	}
	// Hash must verify against the raw env value.
	if err := bcrypt.CompareHashAndPassword([]byte(created.KeyHash), []byte(raw)); err != nil {
		t.Errorf("bcrypt mismatch: %v", err)
	}
	// Hash must NOT equal the raw key (would indicate plaintext storage).
	if created.KeyHash == raw {
		t.Errorf("KeyHash equals raw key — plaintext storage bug")
	}
}

func TestBootstrapAdminFromEnv_AdminAlreadyExists_Idempotent(t *testing.T) {
	t.Setenv(BootstrapAdminEnvVar, "another-secret")
	store := newFakeStore()
	// Pre-existing admin.
	_ = store.SaveAPIKey(context.Background(), &metadata.APIKey{
		ID:        "existing-admin",
		KeyHash:   "$2a$04$dummy",
		Role:      storedRoleAdmin,
		Project:   "default",
		CreatedAt: time.Now(),
	})

	if err := BootstrapAdminFromEnv(context.Background(), store, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}
	if got := len(store.keys); got != 1 {
		t.Errorf("store has %d keys, want 1 (no new admin created)", got)
	}
	if _, ok := store.keys["existing-admin"]; !ok {
		t.Errorf("existing admin was removed/overwritten")
	}
}

func TestBootstrapAdminFromEnv_RevokedAdmin_StillCreatesNewOne(t *testing.T) {
	t.Setenv(BootstrapAdminEnvVar, "fresh-secret")
	store := newFakeStore()
	// Revoked admin should NOT count as "admin already exists".
	_ = store.SaveAPIKey(context.Background(), &metadata.APIKey{
		ID:        "old-admin",
		KeyHash:   "x",
		Role:      storedRoleAdmin,
		Project:   "bootstrap",
		Revoked:   true,
		CreatedAt: time.Now(),
	})

	if err := BootstrapAdminFromEnv(context.Background(), store, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}
	if got := len(store.keys); got != 2 {
		t.Errorf("store has %d keys, want 2 (revoked + fresh)", got)
	}
}

func TestBootstrapAdminFromEnv_NonAdminKeysIgnored(t *testing.T) {
	t.Setenv(BootstrapAdminEnvVar, "secret-x")
	store := newFakeStore()
	_ = store.SaveAPIKey(context.Background(), &metadata.APIKey{
		ID:        "reader",
		KeyHash:   "x",
		Role:      storedRoleReadOnly,
		Project:   "default",
		CreatedAt: time.Now(),
	})

	if err := BootstrapAdminFromEnv(context.Background(), store, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}
	if got := len(store.keys); got != 2 {
		t.Errorf("store has %d keys, want 2 (read-only existing + new admin)", got)
	}
}

func TestBootstrapAdminFromEnv_StoreNotImplemented_NoOp(t *testing.T) {
	t.Setenv(BootstrapAdminEnvVar, "secret-y")
	store := newFakeStore()
	store.disabled = true

	if err := BootstrapAdminFromEnv(context.Background(), store, fastCfg()); err != nil {
		t.Fatalf("BootstrapAdminFromEnv: %v", err)
	}
}
