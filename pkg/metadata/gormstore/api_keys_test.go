package gormstore

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// newAPIKeyTestStore spins up an isolated SQLite store. Each test gets a
// fresh DSN to avoid the shared-cache cross-test bleeding that the suite
// uses elsewhere (we want a clean api_keys table).
func newAPIKeyTestStore(t *testing.T) *GORMStoreV2 {
	t.Helper()
	// Use :memory: in the DSN so NewV2 skips the background aggregation
	// worker (it would otherwise contend on the shared cache and produce
	// "database table is locked" errors mid-test). MaxOpenConns=1 pins the
	// connection so the in-memory database survives across statements
	// (sqlite drops the DB when the only connection closes).
	cfg := Config{
		Driver:          "sqlite",
		DSN:             "file::memory:?_busy_timeout=5000",
		MaxOpenConns:    1,
		MaxIdleConns:    1,
		ConnMaxLifetime: time.Hour,
		LogLevel:        "silent",
	}
	store, err := NewV2(cfg)
	if err != nil {
		t.Fatalf("NewV2: %v", err)
	}
	t.Cleanup(func() {
		// Truncate first so cross-test isolation holds with shared cache.
		store.db.Exec("DELETE FROM api_keys")
		_ = store.Close()
	})
	return store
}

func TestAPIKey_RoundTrip(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	key := &metadata.APIKey{
		ID:        "test-id-1",
		KeyHash:   "$2a$04$abcdefghijklmnopqrstuv",
		Project:   "default",
		Role:      "admin",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		ExpiresAt: &expires,
	}

	if err := store.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("SaveAPIKey: %v", err)
	}

	got, err := store.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey: %v", err)
	}
	if got.ID != key.ID {
		t.Errorf("ID = %q, want %q", got.ID, key.ID)
	}
	if got.KeyHash != key.KeyHash {
		t.Errorf("KeyHash mismatch")
	}
	if got.Project != "default" {
		t.Errorf("Project = %q, want default", got.Project)
	}
	if got.Role != "admin" {
		t.Errorf("Role = %q, want admin", got.Role)
	}
	if got.Revoked {
		t.Errorf("Revoked = true, want false")
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}
}

func TestAPIKey_Upsert(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	key := &metadata.APIKey{
		ID:        "upsert-id",
		KeyHash:   "hash1",
		Project:   "p1",
		Role:      "read_only",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("first SaveAPIKey: %v", err)
	}

	// Update via Save (revoke).
	key.Revoked = true
	key.KeyHash = "hash2"
	if err := store.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("second SaveAPIKey: %v", err)
	}

	got, err := store.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey: %v", err)
	}
	if !got.Revoked {
		t.Errorf("Revoked = false after revoke")
	}
	if got.KeyHash != "hash2" {
		t.Errorf("KeyHash = %q, want hash2", got.KeyHash)
	}
}

func TestAPIKey_List_OrdersByCreatedDesc(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	keys := []*metadata.APIKey{
		{ID: "k-old", KeyHash: "h", Project: "p", Role: "read_only", CreatedAt: now.Add(-2 * time.Hour)},
		{ID: "k-mid", KeyHash: "h", Project: "p", Role: "read_only", CreatedAt: now.Add(-1 * time.Hour)},
		{ID: "k-new", KeyHash: "h", Project: "p", Role: "read_only", CreatedAt: now},
	}
	for _, k := range keys {
		if err := store.SaveAPIKey(ctx, k); err != nil {
			t.Fatalf("save %s: %v", k.ID, err)
		}
	}

	listed, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("len = %d, want 3", len(listed))
	}
	wantOrder := []string{"k-new", "k-mid", "k-old"}
	for i, want := range wantOrder {
		if listed[i].ID != want {
			t.Errorf("listed[%d].ID = %q, want %q", i, listed[i].ID, want)
		}
	}
}

func TestAPIKey_UpdateLastUsed(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	key := &metadata.APIKey{
		ID:        "lu-id",
		KeyHash:   "h",
		Project:   "p",
		Role:      "admin",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("SaveAPIKey: %v", err)
	}

	used := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	if err := store.UpdateAPIKeyLastUsed(ctx, key.ID, used); err != nil {
		t.Fatalf("UpdateAPIKeyLastUsed: %v", err)
	}

	got, err := store.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.Equal(used) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, used)
	}

	// Updating a missing key must not error: validation can race revoke.
	if err := store.UpdateAPIKeyLastUsed(ctx, "no-such-id", used); err != nil {
		t.Errorf("UpdateAPIKeyLastUsed(missing) returned err: %v", err)
	}
}

func TestAPIKey_Delete(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	key := &metadata.APIKey{
		ID:        "del-id",
		KeyHash:   "h",
		Project:   "p",
		Role:      "read_only",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.SaveAPIKey(ctx, key); err != nil {
		t.Fatalf("SaveAPIKey: %v", err)
	}
	if err := store.DeleteAPIKey(ctx, key.ID); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	if _, err := store.GetAPIKey(ctx, key.ID); err == nil {
		t.Errorf("GetAPIKey after delete: want error, got nil")
	}
	// Second delete returns not-found.
	if err := store.DeleteAPIKey(ctx, key.ID); err == nil {
		t.Errorf("second DeleteAPIKey: want error, got nil")
	}
}

func TestAPIKey_SaveAPIKey_RejectsEmptyID(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	err := store.SaveAPIKey(ctx, &metadata.APIKey{KeyHash: "h"})
	if err == nil {
		t.Fatalf("want error for empty ID")
	}
}

func TestAPIKey_GetMissing_ReturnsNotFound(t *testing.T) {
	store := newAPIKeyTestStore(t)
	ctx := context.Background()

	_, err := store.GetAPIKey(ctx, "missing")
	if err == nil {
		t.Fatalf("want error")
	}
	// Sanity: error chain doesn't accidentally surface ErrNotImplemented.
	if stderrors.Is(err, metadata.ErrNotImplemented) {
		t.Errorf("got ErrNotImplemented for missing key, expected not-found")
	}
}
