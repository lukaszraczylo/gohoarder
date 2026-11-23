package config

import (
	"os"
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
