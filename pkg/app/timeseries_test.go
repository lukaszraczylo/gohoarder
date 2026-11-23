package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

func TestTimeSeriesCountsCacheHitDownloads(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/left-pad/-/left-pad-1.3.0.tgz" {
			_, _ = w.Write([]byte("TARBALL"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(upstream.Close)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.NPM.UpstreamRegistry = upstream.URL })

	// The npm handler tracks every tarball request, the first miss included.
	const downloads = 4
	for i := 0; i < downloads; i++ {
		if code, _, body := doRequest(t, a, "/npm/left-pad/-/left-pad-1.3.0.tgz", nil); code != http.StatusOK {
			t.Fatalf("download %d: status %d, body %q", i, code, body)
		}
	}

	for _, period := range []string{"1h", "1day", "7day", "30day"} {
		code, _, body := doRequest(t, a, "/api/stats/timeseries?period="+period, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d, body %q", period, code, body)
		}
		var ts struct {
			DataPoints []struct {
				Value int64 `json:"value"`
			} `json:"data_points"`
		}
		if err := json.Unmarshal([]byte(body), &ts); err != nil {
			t.Fatalf("%s: decode %q: %v", period, body, err)
		}
		var total int64
		for _, p := range ts.DataPoints {
			total += p.Value
		}
		if total != downloads {
			t.Errorf("%s: timeseries total = %d, want %d (body %s)", period, total, downloads, body)
		}
	}
}
