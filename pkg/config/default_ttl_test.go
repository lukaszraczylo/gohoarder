package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDefaultMetadataTTL(t *testing.T) {
	require.Equal(t, 24*time.Hour, Default().Cache.DefaultTTL)
	for registry, ttl := range Default().Cache.TTLOverrides {
		require.LessOrEqual(t, ttl, 72*time.Hour, "override %s outlives the 72h release-age gate", registry)
	}
}

// The shipped examples must not teach a metadata TTL longer than the release-age gate.
func TestShippedExamplesKeepMetadataTTLWithinGate(t *testing.T) {
	for file, key := range map[string]string{
		"../../config.yaml.example":        `default_ttl`,
		"../../helm/gohoarder/values.yaml": `defaultTTL`,
	} {
		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		m := regexp.MustCompile(`(?m)^\s*` + key + `:\s*"?(\d+h)"?`).FindSubmatch(raw)
		require.NotNil(t, m, "%s has no %s", file, key)
		ttl, err := time.ParseDuration(string(m[1]))
		require.NoError(t, err)
		require.Equal(t, 24*time.Hour, ttl, file)

		for _, o := range regexp.MustCompile(`(?m)^\s+(?:npm|pip|go):\s*"(\d+h)"`).FindAllSubmatch(raw, -1) {
			d, err := time.ParseDuration(string(o[1]))
			require.NoError(t, err)
			require.LessOrEqual(t, d, 72*time.Hour, "%s: override %s", file, o[0])
		}
	}
}

func TestTTLOverridesValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		overrides map[string]time.Duration
		wantErr   string
	}{
		"known registries": {map[string]time.Duration{"npm": time.Hour, "pypi": time.Hour, "go": time.Hour}, ""},
		"pip alias":        {map[string]time.Duration{"pip": time.Hour}, ""},
		"unknown registry": {map[string]time.Duration{"cargo": time.Hour}, "cache.ttl_overrides"},
		"zero":             {map[string]time.Duration{"npm": 0}, "cache.ttl_overrides"},
		"negative":         {map[string]time.Duration{"go": -time.Hour}, "cache.ttl_overrides"},
	} {
		t.Run(name, func(t *testing.T) {
			c := Default()
			c.Cache.TTLOverrides = tc.overrides
			err := c.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestMetadataTTLOverridesNormalisesPip(t *testing.T) {
	c := CacheConfig{TTLOverrides: map[string]time.Duration{"pip": time.Hour, "npm": 2 * time.Hour}}
	require.Equal(t, map[string]time.Duration{"pypi": time.Hour, "npm": 2 * time.Hour}, c.MetadataTTLOverrides())
}

func TestDefaultsKeepNoTTLOverrides(t *testing.T) {
	require.Empty(t, Default().Cache.TTLOverrides, "an unset override must not shadow default_ttl")
}

func TestLoadReadsTTLOverridesFromYAML(t *testing.T) {
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}

	cfg, err := Load(write("cache:\n  ttl_overrides:\n    npm: 2h\n    pip: 30m\n"))
	require.NoError(t, err)
	require.Equal(t, map[string]time.Duration{"npm": 2 * time.Hour, "pypi": 30 * time.Minute}, cfg.Cache.MetadataTTLOverrides())

	_, err = Load(write("cache:\n  ttl_overrides:\n    cargo: 2h\n"))
	require.ErrorContains(t, err, "cache.ttl_overrides")
}
