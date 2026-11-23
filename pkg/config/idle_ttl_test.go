package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func loadCacheYAML(t *testing.T, cacheYAML string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cacheYAML), 0600))
	return Load(path)
}

func TestIdleTTLDefaultsToAWeek(t *testing.T) {
	require.Equal(t, 168*time.Hour, Default().Cache.IdleTTL)

	cfg, err := loadCacheYAML(t, "cache:\n  default_ttl: 24h\n")
	require.NoError(t, err)
	require.Equal(t, 168*time.Hour, cfg.Cache.IdleTTL, "an unset key keeps the default")
}

func TestIdleTTLParse(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    time.Duration
		wantErr bool
	}{
		{name: "duration string", yaml: "cache:\n  idle_ttl: 72h\n", want: 72 * time.Hour},
		{name: "zero disables", yaml: "cache:\n  idle_ttl: 0\n", want: 0},
		{name: "quoted zero disables", yaml: "cache:\n  idle_ttl: \"0\"\n", want: 0},
		{name: "quoted duration", yaml: "cache:\n  idle_ttl: \"168h\"\n", want: 168 * time.Hour},
		{name: "negative rejected", yaml: "cache:\n  idle_ttl: -1h\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadCacheYAML(t, tt.yaml)
			if tt.wantErr {
				require.ErrorContains(t, err, "cache.idle_ttl")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.Cache.IdleTTL)
		})
	}
}
