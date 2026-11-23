package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

func TestPyPIRecordsOneRowPerArtifactAndNeverTheSidecar(t *testing.T) {
	const wheel = "six-1.17.0-py2.py3-none-any.whl"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/six/" + wheel:
			_, _ = w.Write([]byte("WHEEL"))
		case "/six/" + wheel + ".metadata":
			_, _ = w.Write([]byte("Metadata-Version: 2.1\nName: six\n"))
		case "/six/six-1.17.0.tar.gz":
			_, _ = w.Write([]byte("SDIST"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.PyPI.SimpleAPIURL = upstream.URL })

	for target, want := range map[string]string{
		"/pypi/six/" + wheel:               "WHEEL",
		"/pypi/six/" + wheel + ".metadata": "Metadata-Version: 2.1\nName: six\n",
		"/pypi/six/six-1.17.0.tar.gz":      "SDIST",
	} {
		// Twice: the second request is the cache hit.
		for i := 0; i < 2; i++ {
			code, _, body := doRequest(t, a, target, nil)
			if code != http.StatusOK || body != want {
				t.Fatalf("GET %s = %d %q, want 200 %q", target, code, body, want)
			}
		}
	}

	code, _, body := doRequest(t, a, "/api/packages?registry=pypi", nil)
	if code != http.StatusOK {
		t.Fatalf("/api/packages: %d %s", code, body)
	}
	var resp struct {
		Packages []struct {
			Name           string `json:"name"`
			Version        string `json:"version"`
			ReleaseVersion string `json:"release_version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	// One row per file, each reporting the release version; the sidecar has none.
	keys := map[string]string{}
	for _, p := range resp.Packages {
		if p.Name == "six" {
			keys[p.Version] = p.ReleaseVersion
		}
	}
	want := map[string]string{wheel: "1.17.0", "six-1.17.0.tar.gz": "1.17.0"}
	if len(keys) != len(want) {
		t.Fatalf("six rows = %v, want %v", keys, want)
	}
	for k, v := range want {
		if keys[k] != v {
			t.Errorf("six row %q release version = %q, want %q", k, keys[k], v)
		}
	}
}
