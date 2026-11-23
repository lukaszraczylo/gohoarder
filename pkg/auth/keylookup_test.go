package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// countBcrypt wraps bcryptCompare and returns the call counter.
func countBcrypt(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	orig := bcryptCompare
	bcryptCompare = func(h, p []byte) error {
		n.Add(1)
		return orig(h, p)
	}
	t.Cleanup(func() { bcryptCompare = orig })
	return &n
}

func newTestManager() *Manager { return NewWithStore(Config{BcryptCost: bcrypt.MinCost}, nil) }

// addLegacyKey stores a key in the pre-key-id format: bcrypt of the whole raw key, no id in the key.
func addLegacyKey(t *testing.T, m *Manager) string {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	raw := base64.URLEncoding.EncodeToString(b)
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	k := &APIKey{ID: generateID(), Name: "legacy", HashedKey: string(h), Role: RoleReadOnly, CreatedAt: time.Now(), Permissions: getPermissionsForRole(RoleReadOnly)}
	m.mu.Lock()
	m.keys[k.ID] = k
	m.mu.Unlock()
	return raw
}

func TestValidateAPIKeyCostIndependentOfKeyCount(t *testing.T) {
	m := newTestManager()
	_, good, err := m.GenerateAPIKey("target", RoleReadWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, _, err := m.GenerateAPIKey("filler", RoleReadOnly, nil); err != nil {
			t.Fatal(err)
		}
	}
	n := countBcrypt(t)

	if _, err := m.ValidateAPIKey(context.Background(), good); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("valid key: %d bcrypt compares, want 1", got)
	}

	n.Store(0)
	idPart := strings.SplitN(good, keySeparator, 2)[0]
	cases := map[string]string{
		"known id, wrong secret": idPart + keySeparator + "AAAA",
		"unknown id":             keyPrefix + "nope" + keySeparator + "AAAA",
		"no secret":              idPart + keySeparator,
	}
	for name, raw := range cases {
		n.Store(0)
		if _, err := m.ValidateAPIKey(context.Background(), raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if got := n.Load(); got != 1 {
			t.Errorf("%s: %d bcrypt compares, want exactly 1", name, got)
		}
	}
}

func TestValidateAPIKeyRejectsSecretOfAnotherKey(t *testing.T) {
	m := newTestManager()
	a, _, _ := m.GenerateAPIKey("a", RoleAdmin, nil)
	_, rawB, _ := m.GenerateAPIKey("b", RoleReadOnly, nil)
	secretB := strings.SplitN(rawB, keySeparator, 2)[1]
	if _, err := m.ValidateAPIKey(context.Background(), a.ID+keySeparator+secretB); err == nil {
		t.Fatal("id of one key with the secret of another was accepted")
	}
}

func TestLegacyKeysStillValidate(t *testing.T) {
	m := newTestManager()
	raw := addLegacyKey(t, m)
	for i := 0; i < 3; i++ {
		addLegacyKey(t, m)
	}
	k, err := m.ValidateAPIKey(context.Background(), raw)
	if err != nil || k == nil || k.Name != "legacy" {
		t.Fatalf("legacy key rejected: %v", err)
	}
}

func TestNewFormatKeyNeverTouchesLegacyKeys(t *testing.T) {
	m := newTestManager()
	for i := 0; i < 20; i++ {
		addLegacyKey(t, m)
	}
	_, raw, _ := m.GenerateAPIKey("new", RoleReadOnly, nil)
	n := countBcrypt(t)
	if _, err := m.ValidateAPIKey(context.Background(), raw+"x"); err == nil {
		t.Fatal("bad key accepted")
	}
	if got := n.Load(); got != 1 {
		t.Errorf("%d bcrypt compares with 20 legacy keys stored, want 1", got)
	}
}

func TestLegacyComparesAreConcurrencyBounded(t *testing.T) {
	m := newTestManager()
	for i := 0; i < 5; i++ {
		addLegacyKey(t, m)
	}
	var cur, peak atomic.Int64
	orig := bcryptCompare
	bcryptCompare = func(h, p []byte) error {
		c := cur.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		cur.Add(-1)
		return orig(h, p)
	}
	t.Cleanup(func() { bcryptCompare = orig })

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.ValidateAPIKey(context.Background(), "bad-legacy-key-bad-legacy-key-bad-legacy-key-0000")
		}()
	}
	wg.Wait()
	if got := peak.Load(); got > maxLegacyCompares {
		t.Errorf("peak concurrent legacy compares %d, want <= %d", got, maxLegacyCompares)
	}
}
