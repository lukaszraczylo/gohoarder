package auth

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"golang.org/x/crypto/bcrypt"
)

// fakeStore is a minimal in-memory metadata.MetadataStore. Only the API key
// methods are exercised; everything else returns ErrNotImplemented to make
// accidental calls obvious.
type fakeStore struct {
	keys        map[string]*metadata.APIKey
	saveErr     error
	listErr     error
	updateErr   error
	mu          sync.Mutex
	saveCalls   int
	updateCalls int
	disabled    bool // when true, every API key method returns ErrNotImplemented
}

func newFakeStore() *fakeStore {
	return &fakeStore{keys: make(map[string]*metadata.APIKey)}
}

func (f *fakeStore) SaveAPIKey(ctx context.Context, key *metadata.APIKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.disabled {
		return metadata.ErrNotImplemented
	}
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	cp := *key
	f.keys[key.ID] = &cp
	return nil
}

func (f *fakeStore) GetAPIKey(ctx context.Context, id string) (*metadata.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.disabled {
		return nil, metadata.ErrNotImplemented
	}
	k, ok := f.keys[id]
	if !ok {
		return nil, stderrors.New("not found")
	}
	cp := *k
	return &cp, nil
}

func (f *fakeStore) ListAPIKeys(ctx context.Context) ([]*metadata.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.disabled {
		return nil, metadata.ErrNotImplemented
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]*metadata.APIKey, 0, len(f.keys))
	for _, k := range f.keys {
		cp := *k
		out = append(out, &cp)
	}
	return out, nil
}

func (f *fakeStore) DeleteAPIKey(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.disabled {
		return metadata.ErrNotImplemented
	}
	delete(f.keys, id)
	return nil
}

func (f *fakeStore) UpdateAPIKeyLastUsed(ctx context.Context, id string, t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.disabled {
		return metadata.ErrNotImplemented
	}
	f.updateCalls++
	if f.updateErr != nil {
		return f.updateErr
	}
	if k, ok := f.keys[id]; ok {
		tt := t
		k.LastUsedAt = &tt
	}
	return nil
}

// All other methods are unreachable from auth.Manager — return ErrNotImplemented
// so accidental usage in future tests fails loudly.
func (f *fakeStore) SavePackage(context.Context, *metadata.Package) error {
	return metadata.ErrNotImplemented
}
func (f *fakeStore) GetPackage(context.Context, string, string, string) (*metadata.Package, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) DeletePackage(context.Context, string, string, string) error {
	return metadata.ErrNotImplemented
}
func (f *fakeStore) ListPackages(context.Context, *metadata.ListOptions) ([]*metadata.Package, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) UpdateDownloadCount(context.Context, string, string, string) error {
	return metadata.ErrNotImplemented
}
func (f *fakeStore) GetStats(context.Context, string) (*metadata.Stats, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) SaveScanResult(context.Context, *metadata.ScanResult) error {
	return metadata.ErrNotImplemented
}
func (f *fakeStore) GetScanResult(context.Context, string, string, string) (*metadata.ScanResult, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) SaveCVEBypass(context.Context, *metadata.CVEBypass) error {
	return metadata.ErrNotImplemented
}
func (f *fakeStore) GetActiveCVEBypasses(context.Context) ([]*metadata.CVEBypass, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) ListCVEBypasses(context.Context, *metadata.BypassListOptions) ([]*metadata.CVEBypass, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) DeleteCVEBypass(context.Context, string) error { return metadata.ErrNotImplemented }
func (f *fakeStore) CleanupExpiredBypasses(context.Context) (int, error) {
	return 0, metadata.ErrNotImplemented
}
func (f *fakeStore) Count(context.Context) (int, error) { return 0, metadata.ErrNotImplemented }
func (f *fakeStore) Health(context.Context) error       { return metadata.ErrNotImplemented }
func (f *fakeStore) GetTimeSeriesStats(context.Context, string, string) (*metadata.TimeSeriesStats, error) {
	return nil, metadata.ErrNotImplemented
}
func (f *fakeStore) AggregateDownloadData(context.Context) error { return metadata.ErrNotImplemented }
func (f *fakeStore) Close() error                                { return nil }

// fastCfg uses bcrypt.MinCost so tests that hash multiple keys stay snappy.
func fastCfg() Config { return Config{BcryptCost: bcrypt.MinCost} }

func TestManager_GenerateAPIKey_PersistsToStore(t *testing.T) {
	store := newFakeStore()
	m := NewWithStore(fastCfg(), store)
	defer m.Close()

	apiKey, raw, err := m.GenerateAPIKey("svc-token", RoleReadWrite, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if raw == "" {
		t.Fatalf("raw key empty")
	}
	if apiKey.ID == "" {
		t.Fatalf("apiKey.ID empty")
	}

	if store.saveCalls != 1 {
		t.Errorf("saveCalls = %d, want 1", store.saveCalls)
	}
	persisted, err := store.GetAPIKey(context.Background(), apiKey.ID)
	if err != nil {
		t.Fatalf("GetAPIKey persisted: %v", err)
	}
	if persisted.Role != storedRoleReadWrite {
		t.Errorf("persisted Role = %q, want %q", persisted.Role, storedRoleReadWrite)
	}
	if persisted.Revoked {
		t.Errorf("persisted Revoked = true, want false")
	}
}

func TestManager_GenerateAPIKey_StoreFailure_RollsBack(t *testing.T) {
	store := newFakeStore()
	store.saveErr = stderrors.New("disk full")
	m := NewWithStore(fastCfg(), store)
	defer m.Close()

	_, _, err := m.GenerateAPIKey("svc", RoleReadOnly, nil)
	if err == nil {
		t.Fatalf("want error from store, got nil")
	}
	if got := len(m.ListAPIKeys()); got != 0 {
		t.Errorf("in-memory keys = %d, want 0 after rollback", got)
	}
}

func TestManager_RevokeAPIKey_PersistsRevocation(t *testing.T) {
	store := newFakeStore()
	m := NewWithStore(fastCfg(), store)
	defer m.Close()

	key, _, err := m.GenerateAPIKey("svc", RoleAdmin, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if revokeErr := m.RevokeAPIKey(key.ID); revokeErr != nil {
		t.Fatalf("Revoke: %v", revokeErr)
	}
	persisted, err := store.GetAPIKey(context.Background(), key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey after revoke: %v", err)
	}
	if !persisted.Revoked {
		t.Errorf("persisted Revoked = false, want true")
	}
	if got := len(m.ListAPIKeys()); got != 0 {
		t.Errorf("in-memory keys after revoke = %d, want 0", got)
	}
}

func TestManager_RevokeAPIKey_StoreFailure_KeepsInMemory(t *testing.T) {
	store := newFakeStore()
	m := NewWithStore(fastCfg(), store)
	defer m.Close()

	key, _, err := m.GenerateAPIKey("svc", RoleAdmin, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	store.saveErr = stderrors.New("DB exploded")
	if err := m.RevokeAPIKey(key.ID); err == nil {
		t.Fatalf("want error from Revoke, got nil")
	}
	if got := len(m.ListAPIKeys()); got != 1 {
		t.Errorf("in-memory keys = %d, want 1 (rollback)", got)
	}
}

func TestManager_Load_HydratesFromStore(t *testing.T) {
	store := newFakeStore()

	// Pre-populate the store directly.
	for _, tc := range []struct {
		id      string
		role    string
		revoked bool
	}{
		{"a", storedRoleAdmin, false},
		{"b", storedRoleReadOnly, false},
		{"c", storedRoleReadWrite, true}, // revoked: should be skipped
	} {
		_ = store.SaveAPIKey(context.Background(), &metadata.APIKey{
			ID: tc.id, KeyHash: "h", Role: tc.role, Revoked: tc.revoked, CreatedAt: time.Now(),
		})
	}

	m := NewWithStore(fastCfg(), store)
	defer m.Close()

	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys := m.ListAPIKeys()
	if len(keys) != 2 {
		t.Fatalf("loaded %d keys, want 2 (revoked excluded)", len(keys))
	}
	for _, k := range keys {
		if k.Role != RoleAdmin && k.Role != RoleReadOnly {
			t.Errorf("unexpected role %q", k.Role)
		}
		if len(k.Permissions) == 0 {
			t.Errorf("permissions empty for role %q (should be derived)", k.Role)
		}
	}
}

func TestManager_Load_NilStore_NoOp(t *testing.T) {
	m := NewWithStore(fastCfg(), nil)
	defer m.Close()
	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load with nil store: %v", err)
	}
}

func TestManager_Load_NotImplemented_NoOp(t *testing.T) {
	store := newFakeStore()
	store.disabled = true
	m := NewWithStore(fastCfg(), store)
	defer m.Close()
	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load with disabled store: %v", err)
	}
}

func TestManager_ValidateAPIKey_AsyncLastUsed(t *testing.T) {
	store := newFakeStore()
	m := NewWithStore(fastCfg(), store)
	defer m.Close()

	_, raw, err := m.GenerateAPIKey("svc", RoleReadOnly, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, err := m.ValidateAPIKey(context.Background(), raw); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Wait for the fire-and-forget goroutine.
	m.Close()

	if store.updateCalls < 1 {
		t.Errorf("UpdateAPIKeyLastUsed not called (calls=%d)", store.updateCalls)
	}
}

func TestManager_ValidateAPIKey_RejectsUnknown(t *testing.T) {
	m := NewWithStore(fastCfg(), nil)
	defer m.Close()
	if _, err := m.ValidateAPIKey(context.Background(), "no-such-key"); err == nil {
		t.Fatalf("Validate(unknown): want error")
	}
}

func TestManager_InMemoryMode_StillWorks(t *testing.T) {
	// Back-compat: the legacy New() constructor must continue working
	// without a store.
	m := New()
	defer m.Close()
	apiKey, raw, err := m.GenerateAPIKey("legacy", RoleReadOnly, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got, err := m.ValidateAPIKey(context.Background(), raw)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != apiKey.ID {
		t.Errorf("validated wrong key: got %q want %q", got.ID, apiKey.ID)
	}
}

func TestManager_RoleRoundTrip(t *testing.T) {
	cases := []struct {
		role   Role
		stored string
	}{
		{RoleReadOnly, storedRoleReadOnly},
		{RoleReadWrite, storedRoleReadWrite},
		{RoleAdmin, storedRoleAdmin},
	}
	for _, tc := range cases {
		t.Run(string(tc.role), func(t *testing.T) {
			if got := roleToStored(tc.role); got != tc.stored {
				t.Errorf("roleToStored(%q) = %q, want %q", tc.role, got, tc.stored)
			}
			if got := storedToRole(tc.stored); got != tc.role {
				t.Errorf("storedToRole(%q) = %q, want %q", tc.stored, got, tc.role)
			}
		})
	}

	if got := storedToRole("garbage"); got != RoleReadOnly {
		t.Errorf("storedToRole(garbage) = %q, want least-privilege RoleReadOnly", got)
	}
}
