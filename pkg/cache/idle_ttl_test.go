package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/metrics"
	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func evictions(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		panic(err)
	}
	return m.GetCounter().GetValue()
}

type fakeClock struct {
	now time.Time
	mu  sync.Mutex
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type memStorage struct {
	storage.StorageBackend
	objects map[string][]byte
	mu      sync.Mutex
}

func newMemStorage() *memStorage { return &memStorage{objects: map[string][]byte{}} }

func (s *memStorage) Get(_ context.Context, key string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (s *memStorage) Put(_ context.Context, key string, data io.Reader, _ *storage.PutOptions) error {
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = b
	return nil
}

func (s *memStorage) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, key)
	return nil
}

func (s *memStorage) GetQuota(context.Context) (*storage.QuotaInfo, error) {
	return &storage.QuotaInfo{}, nil
}

func (s *memStorage) Close() error { return nil }

func (s *memStorage) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.objects[key]
	return ok
}

// memMetadata mirrors the real store's contract: UpdateDownloadCount stamps
// last_accessed, and the list queries are ordered and bounded.
type memMetadata struct {
	metadata.MetadataStore
	clock     *fakeClock
	pkgs      map[string]*metadata.Package
	onList    func()
	maxLimit  int
	mu        sync.Mutex
	idleCalls int
}

func newMemMetadata(clock *fakeClock) *memMetadata {
	return &memMetadata{clock: clock, pkgs: map[string]*metadata.Package{}}
}

func pkgKey(registry, name, version string) string { return registry + "/" + name + "/" + version }

func (m *memMetadata) SavePackage(_ context.Context, pkg *metadata.Package) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *pkg
	m.pkgs[pkgKey(pkg.Registry, pkg.Name, pkg.Version)] = &cp
	return nil
}

func (m *memMetadata) GetPackage(_ context.Context, registry, name, version string) (*metadata.Package, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pkgs[pkgKey(registry, name, version)]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *p
	return &cp, nil
}

func (m *memMetadata) DeletePackage(_ context.Context, registry, name, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.pkgs, pkgKey(registry, name, version))
	return nil
}

func (m *memMetadata) UpdateDownloadCount(_ context.Context, registry, name, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pkgs[pkgKey(registry, name, version)]
	if !ok {
		return errors.New("not found")
	}
	p.DownloadCount++
	p.LastAccessed = m.clock.Now()
	return nil
}

func (m *memMetadata) list(limit int, match func(*metadata.Package) bool, less func(a, b *metadata.Package) bool) []*metadata.Package {
	m.mu.Lock()
	if limit > m.maxLimit {
		m.maxLimit = limit
	}
	var out []*metadata.Package
	for _, p := range m.pkgs {
		if match(p) {
			cp := *p
			out = append(out, &cp)
		}
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	if m.onList != nil {
		m.onList()
	}
	return out
}

func (m *memMetadata) ListIdlePackages(_ context.Context, idleBefore time.Time, limit int) ([]*metadata.Package, error) {
	m.mu.Lock()
	m.idleCalls++
	m.mu.Unlock()
	return m.list(limit,
		func(p *metadata.Package) bool { return p.LastAccessed.Before(idleBefore) },
		func(a, b *metadata.Package) bool { return a.LastAccessed.Before(b.LastAccessed) }), nil
}

func (m *memMetadata) ListExpiredPackages(_ context.Context, before time.Time, limit int) ([]*metadata.Package, error) {
	return m.list(limit,
		func(p *metadata.Package) bool { return p.ExpiresAt != nil && p.ExpiresAt.Before(before) },
		func(a, b *metadata.Package) bool { return a.ExpiresAt.Before(*b.ExpiresAt) }), nil
}

func (m *memMetadata) ClearArtifactExpiry(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, p := range m.pkgs {
		if p.ExpiresAt != nil && !metadata.IsMetadataEntry(p.Name, p.Version) {
			p.ExpiresAt = nil
			n++
		}
	}
	return n, nil
}

func (m *memMetadata) Close() error { return nil }

func (m *memMetadata) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pkgs)
}

type idleHarness struct {
	mgr     *Manager
	clock   *fakeClock
	meta    *memMetadata
	store   *memStorage
	fetches int
}

func newIdleHarness(t *testing.T, cfg Config) *idleHarness {
	t.Helper()
	h := &idleHarness{clock: newFakeClock(), store: newMemStorage()}
	h.meta = newMemMetadata(h.clock)
	cfg.Now = h.clock.Now
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 24 * time.Hour
	}
	return h.start(t, cfg)
}

func (h *idleHarness) start(t *testing.T, cfg Config) *idleHarness {
	t.Helper()
	mgr, err := New(h.store, h.meta, nil, nil, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	h.mgr = mgr
	return h
}

func (h *idleHarness) get(t *testing.T, name, version string) *CacheEntry {
	t.Helper()
	entry, err := h.mgr.Get(context.Background(), "npm", name, version, func(context.Context) (*FetchResult, error) {
		h.fetches++
		return &FetchResult{Data: io.NopCloser(strings.NewReader("payload-" + name)), UpstreamURL: "https://upstream/" + name}, nil
	})
	require.NoError(t, err)
	_ = entry.Data.Close()
	return entry
}

func (h *idleHarness) exists(name, version string) bool {
	_, err := h.meta.GetPackage(context.Background(), "npm", name, version)
	return err == nil && h.store.has(fmt.Sprintf("npm/%s/%s", name, version))
}

const (
	day         = 24 * time.Hour
	artifactVer = "4.17.21"
)

func TestIdleTTL_AccessedArtifactSurvivesDefaultTTL(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: 2 * day, IdleTTL: 3 * day})
	entry := h.get(t, "lodash", artifactVer)
	require.Nil(t, entry.Package.ExpiresAt, "an artifact is immutable: no age-based expiry")

	h.clock.Advance(2 * day)
	h.get(t, "lodash", artifactVer) // touches last_accessed
	h.clock.Advance(2 * day)        // 4 days after caching, past DefaultTTL; idle for only 2

	h.mgr.cleanup(context.Background())

	require.True(t, h.exists("lodash", artifactVer))
	h.get(t, "lodash", artifactVer)
	require.Equal(t, 1, h.fetches, "served from cache, not re-fetched")
}

func TestIdleTTL_IdleArtifactIsDeletedFromStorageAndMetadata(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: 2 * day, IdleTTL: 3 * day})
	h.get(t, "lodash", artifactVer)
	h.get(t, "left-pad", "1.3.0")
	h.clock.Advance(2 * day)
	h.get(t, "left-pad", "1.3.0") // keeps left-pad alive
	h.clock.Advance(2 * day)      // lodash idle for 4 days

	before := evictions(metrics.CacheEvictions.WithLabelValues("idle"))
	h.mgr.cleanup(context.Background())

	require.False(t, h.exists("lodash", artifactVer))
	require.False(t, h.store.has("npm/lodash/"+artifactVer), "storage object removed")
	_, err := h.meta.GetPackage(context.Background(), "npm", "lodash", artifactVer)
	require.Error(t, err, "metadata row removed")
	require.True(t, h.exists("left-pad", "1.3.0"))
	require.Equal(t, before+1, evictions(metrics.CacheEvictions.WithLabelValues("idle")))
}

func TestIdleTTL_IdleMetadataEntryIsDeleted(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: 30 * day, IdleTTL: 3 * day})
	h.get(t, "lodash", "metadata")
	h.clock.Advance(4 * day)

	h.mgr.cleanup(context.Background())

	require.False(t, h.exists("lodash", "metadata"))
}

func TestIdleTTL_MetadataEntryPastFreshnessTTLIsRefetched(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: time.Hour, IdleTTL: 7 * day})
	entry := h.get(t, "lodash", "metadata")
	require.NotNil(t, entry.Package.ExpiresAt)
	require.Equal(t, h.clock.Now().Add(time.Hour), *entry.Package.ExpiresAt)

	h.clock.Advance(30 * time.Minute)
	h.get(t, "lodash", "metadata")
	require.Equal(t, 1, h.fetches, "still fresh")

	h.clock.Advance(2 * time.Hour) // recently requested, but stale
	before := evictions(metrics.CacheEvictions.WithLabelValues("ttl"))
	h.get(t, "lodash", "metadata")
	require.Equal(t, 2, h.fetches, "stale metadata is re-fetched")
	require.Equal(t, before+1, evictions(metrics.CacheEvictions.WithLabelValues("ttl")))
}

func TestIdleTTL_CleanupRemovesExpiredMetadataOnly(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: time.Hour, IdleTTL: 30 * day})
	h.get(t, "lodash", "metadata")
	h.get(t, "lodash", artifactVer)
	h.clock.Advance(2 * time.Hour)

	h.mgr.cleanup(context.Background())

	require.False(t, h.exists("lodash", "metadata"), "past its freshness expiry")
	require.True(t, h.exists("lodash", artifactVer), "artifacts have no age-based expiry")
}

func TestIdleTTL_ZeroDisablesIdleEviction(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: 2 * day, IdleTTL: 0})
	h.get(t, "lodash", artifactVer)
	h.clock.Advance(365 * day)

	h.mgr.cleanup(context.Background())

	require.True(t, h.exists("lodash", artifactVer))
	require.Zero(t, h.meta.idleCalls, "no idle query when disabled")
}

func TestIdleTTL_CleanupReadsBoundedBatches(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: day, IdleTTL: day})
	const total = 1250
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("pkg-%d", i)
		h.get(t, name, "1.0.0")
	}
	h.clock.Advance(2 * day)

	h.mgr.cleanup(context.Background())

	require.Zero(t, h.meta.count(), "every idle item removed across batches")
	require.Positive(t, h.meta.maxLimit)
	require.LessOrEqual(t, h.meta.maxLimit, cleanupBatchSize, "never loads more than one batch")
	require.Zero(t, len(h.store.objects))
}

func TestIdleTTL_ItemRequestedDuringCleanupSurvives(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: 30 * day, IdleTTL: day})
	h.get(t, "lodash", artifactVer)
	h.clock.Advance(2 * day)
	h.meta.onList = func() {
		h.meta.onList = nil
		require.NoError(t, h.meta.UpdateDownloadCount(context.Background(), "npm", "lodash", artifactVer))
	}

	h.mgr.cleanup(context.Background())

	require.True(t, h.exists("lodash", artifactVer), "a request between listing and deleting wins")
}

func TestIdleTTL_StartupClearsLegacyArtifactExpiry(t *testing.T) {
	h := &idleHarness{clock: newFakeClock(), store: newMemStorage()}
	h.meta = newMemMetadata(h.clock)
	past := h.clock.Now().Add(-day)
	require.NoError(t, h.meta.SavePackage(context.Background(), &metadata.Package{
		Registry: "npm", Name: "lodash", Version: artifactVer, StorageKey: "npm/lodash/" + artifactVer,
		LastAccessed: h.clock.Now(), ExpiresAt: &past,
	}))
	require.NoError(t, h.store.Put(context.Background(), "npm/lodash/"+artifactVer, strings.NewReader("x"), nil))

	h.start(t, Config{DefaultTTL: 7 * day, IdleTTL: 7 * day, Now: h.clock.Now, CleanupInterval: 24 * time.Hour})

	h.get(t, "lodash", artifactVer)
	require.Zero(t, h.fetches, "the legacy 7-day expiry no longer evicts a popular artifact")
	p, err := h.meta.GetPackage(context.Background(), "npm", "lodash", artifactVer)
	require.NoError(t, err)
	require.Nil(t, p.ExpiresAt)
}
