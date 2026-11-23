package cache

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func (h *idleHarness) getFrom(t *testing.T, registry, name, version string) *CacheEntry {
	t.Helper()
	entry, err := h.mgr.Get(context.Background(), registry, name, version, func(context.Context) (*FetchResult, error) {
		return &FetchResult{Data: io.NopCloser(strings.NewReader("payload-" + name)), UpstreamURL: "https://upstream/" + name}, nil
	})
	require.NoError(t, err)
	_ = entry.Data.Close()
	return entry
}

func TestMetadataTTLOverridesApplyPerRegistry(t *testing.T) {
	h := newIdleHarness(t, Config{
		DefaultTTL:   6 * time.Hour,
		TTLOverrides: map[string]time.Duration{"npm": time.Hour, "go": 12 * time.Hour},
	})

	require.Equal(t, time.Hour, h.getFrom(t, "npm", "left-pad", "metadata").Package.ExpiresAt.Sub(h.clock.Now()))
	require.Equal(t, 12*time.Hour, h.getFrom(t, "go", "example.com/m/@v/list", "list").Package.ExpiresAt.Sub(h.clock.Now()))
	require.Equal(t, 6*time.Hour, h.getFrom(t, "pypi", "left-pad", "metadata").Package.ExpiresAt.Sub(h.clock.Now()), "registry without override keeps default_ttl")
}

func TestMetadataTTLOverridesSkipArtifacts(t *testing.T) {
	h := newIdleHarness(t, Config{TTLOverrides: map[string]time.Duration{"npm": time.Hour}})

	require.Nil(t, h.getFrom(t, "npm", "left-pad", artifactVer).Package.ExpiresAt, "artifacts have no age expiry")
}
