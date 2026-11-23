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
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	got := map[string]bool{}
	for _, p := range resp.Packages {
		if p.Name != "six" {
			continue
		}
		got[p.Version] = true
	}
	want := map[string]bool{"1.17.0": true, "1.17.0+py2.py3-none-any": true}
	if len(got) != len(want) {
		t.Fatalf("six versions = %v, want %v (body %s)", got, want, body)
	}
	for v := range want {
		if !got[v] {
			t.Errorf("missing six version %q in %v", v, got)
		}
	}
}
