package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDeletedRetentionDefaultsToThirtyDays(t *testing.T) {
	require.Equal(t, 30*24*time.Hour, Default().Cache.DeletedRetention)

	cfg, err := loadCacheYAML(t, "cache:\n  default_ttl: 24h\n")
	require.NoError(t, err)
	require.Equal(t, 30*24*time.Hour, cfg.Cache.DeletedRetention, "an unset key keeps the default")
}

func TestDeletedRetentionParse(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    time.Duration
		wantErr bool
	}{
		{name: "duration string", yaml: "cache:\n  deleted_retention: 48h\n", want: 48 * time.Hour},
		{name: "zero keeps rows", yaml: "cache:\n  deleted_retention: 0\n", want: 0},
		{name: "quoted duration", yaml: "cache:\n  deleted_retention: \"720h\"\n", want: 720 * time.Hour},
		{name: "negative rejected", yaml: "cache:\n  deleted_retention: -1h\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadCacheYAML(t, tt.yaml)
			if tt.wantErr {
				require.ErrorContains(t, err, "cache.deleted_retention")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.Cache.DeletedRetention)
		})
	}
}
