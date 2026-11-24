package app

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

// analyticsDownloads maps "registry:name" to downloads as the analytics engine reports them.
func analyticsDownloads(a *App) map[string]int64 {
	out := map[string]int64{}
	for _, p := range a.analyticsEngine.GetTopPackages(0) {
		out[p.Registry+":"+p.Name] = p.Downloads
	}
	return out
}

// scrub sends requests whose paths differ from the proxied ones. The server reuses its request
// buffers, so a name kept from an earlier request changes under the analytics engine.
func scrub(t *testing.T, a *App) {
	t.Helper()
	for i := 0; i < 5; i++ {
		doRequest(t, a, "/api/analytics/top?limit="+strings.Repeat("9", 40+i), nil)
	}
}

func assertDownloads(t *testing.T, a *App, want map[string]int64) {
	t.Helper()
	scrub(t, a)
	got := analyticsDownloads(a)
	if len(got) != len(want) {
		t.Errorf("analytics keys = %v, want %v", got, want)
		return
	}
	for key, n := range want {
		if got[key] != n {
			t.Errorf("analytics keys = %v, want %v", got, want)
			return
		}
	}
}

func TestAnalyticsNameNpmPackagesAfterRegistryPaths(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			_, _ = w.Write([]byte("TARBALL"))
			return
		}
		_, _ = w.Write([]byte(`{"name":"x","versions":{}}`))
	}))
	t.Cleanup(upstream.Close)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.NPM.UpstreamRegistry = upstream.URL })

	for _, target := range []string{
		"/npm/lodash/-/lodash-4.17.21.tgz",
		"/npm/@types/node/-/node-18.0.0.tgz",
		"/npm/@types%2fnode/-/node-18.0.0.tgz",
		"/npm/lodash",
		"/npm/@types%2fnode",
	} {
		if code, _, body := doRequest(t, a, target, nil); code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", target, code, body)
		}
	}
	// Tarballs are downloads; the packument is metadata and does not count.
	assertDownloads(t, a, map[string]int64{"npm:lodash": 1, "npm:@types/node": 2})
}

func TestAnalyticsNameGoModuleCountsOnlyTheZip(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("BODY " + r.URL.Path)) // #nosec G705 -- test upstream, plain text body
	}))
	t.Cleanup(upstream.Close)
	a := newTestApp(t, func(c *config.Config) {
		c.Handlers.Go.UpstreamProxy = upstream.URL
		c.Handlers.Go.VerifyChecksums = false
	})

	const base = "/go/github.com/google/uuid/@v/"
	for _, target := range []string{base + "list", base + "v1.6.0.info", base + "v1.6.0.mod", base + "v1.6.0.zip", base + "v1.5.0.zip"} {
		if code, _, body := doRequest(t, a, target, nil); code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", target, code, body)
		}
	}
	// One key per module: both zips are downloads of the module, .info, .mod and list are not.
	assertDownloads(t, a, map[string]int64{"go:github.com/google/uuid": 2})
}

func TestAnalyticsNamePyPIFilesNotPages(t *testing.T) {
	upstream, _ := newPyPIUpstream(t)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.PyPI.SimpleAPIURL = upstream.URL + "/simple" })

	file := "/pypi/foo/" + pypiWheel + "?original_url=" + url.QueryEscape(upstream.URL+"/packages/"+pypiWheel)
	for _, target := range []string{"/pypi/simple/foo/", file} {
		if code, _, body := doRequest(t, a, target, nil); code != http.StatusOK {
			t.Fatalf("GET %s: %d %.80s", target, code, body)
		}
	}
	doRequest(t, a, "/pypi/simple/foo/", map[string]string{"Accept": pypiJSONType})
	assertDownloads(t, a, map[string]int64{"pypi:foo": 1})
}

// The proxy hands the cache names that alias the server's request buffer. Analytics keeps them
// after the request ends, so they must be copied or later requests rewrite them.
func TestAnalyticsKeepsNamesAfterTheRequestBufferIsReused(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("TARBALL"))
	}))
	t.Cleanup(upstream.Close)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.NPM.UpstreamRegistry = upstream.URL })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	base := "http://" + ln.Addr().String()

	get := func(path string) {
		resp, err := http.Get(base + path) // #nosec G107 -- loopback test server
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	names := []string{"lodash", "express", "@types/node", "left-pad"}
	for _, name := range names {
		bare := name[strings.Index(name, "/")+1:]
		get("/npm/" + name + "/-/" + bare + "-1.0.0.tgz")
	}
	for i := 0; i < 20; i++ {
		get("/api/analytics/top?limit=" + strings.Repeat("7", 30+i))
	}

	got := analyticsDownloads(a)
	for _, name := range names {
		if got["npm:"+name] != 1 {
			t.Fatalf("analytics keys = %v, want each of %v once", got, names)
		}
	}
}
