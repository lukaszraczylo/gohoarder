package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

func TestStatsReportsIdleTTLSeconds(t *testing.T) {
	for name, tt := range map[string]struct {
		idle time.Duration
		want float64
	}{
		"a week":   {idle: 168 * time.Hour, want: 604800},
		"disabled": {idle: 0, want: 0},
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestApp(t, func(c *config.Config) { c.Cache.IdleTTL = tt.idle })

			code, _, body := doRequest(t, a, "/api/stats", nil)
			if code != http.StatusOK {
				t.Fatalf("status %d, body %q", code, body)
			}
			var resp struct {
				Stats map[string]any `json:"stats"`
			}
			if err := json.Unmarshal([]byte(body), &resp); err != nil {
				t.Fatalf("decode %q: %v", body, err)
			}
			got, ok := resp.Stats["idle_ttl"].(float64)
			if !ok || got != tt.want {
				t.Errorf("stats.idle_ttl = %v, want %v (body %s)", resp.Stats["idle_ttl"], tt.want, body)
			}
		})
	}
}
