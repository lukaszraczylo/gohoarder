package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

// newTestApp builds a full App on temp storage with the given config tweaks.
func newTestApp(t *testing.T, mutate func(*config.Config)) *App {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.Backend = "filesystem"
	cfg.Storage.Path = t.TempDir()
	cfg.Metadata.Backend = "sqlite"
	cfg.Metadata.SQLite.Path = t.TempDir() + "/meta.db"
	cfg.Security.Enabled = false
	cfg.Prewarming.Enabled = false
	cfg.Auth.Enabled = false
	if mutate != nil {
		mutate(cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown() })
	return a
}

func doRequest(t *testing.T, a *App, target string, headers map[string]string) (int, http.Header, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.app.Test(req, fiber.TestConfig{Timeout: 40 * time.Second})
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

func TestNPMScopedNames(t *testing.T) {
	const tarball = "TARBALL-BYTES"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/@types/node":
			_, _ = w.Write([]byte(`{"name":"@types/node","versions":{"1.0.0":{"dist":{"tarball":"` + "http://" + r.Host + `/@types/node/-/node-1.0.0.tgz"}}}}`)) // #nosec G705 -- test upstream, JSON body
		case "/@types/node/-/node-1.0.0.tgz":
			_, _ = w.Write([]byte(tarball))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	a := newTestApp(t, func(c *config.Config) { c.Handlers.NPM.UpstreamRegistry = upstream.URL })

	packuments := []string{"/npm/@types%2fnode", "/npm/@types%2Fnode", "/npm/@types/node"}
	for _, target := range packuments {
		t.Run("packument "+target, func(t *testing.T) {
			code, _, body := doRequest(t, a, target, nil)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %q", code, body)
			}
			if !strings.Contains(body, `"name":"@types/node"`) {
				t.Errorf("unexpected packument body %q", body)
			}
		})
	}

	tarballs := []string{
		"/npm/@types%2fnode/-/node-1.0.0.tgz",
		"/npm/@types%2Fnode/-/node-1.0.0.tgz",
		"/npm/@types/node/-/node-1.0.0.tgz",
	}
	for _, target := range tarballs {
		t.Run("tarball "+target, func(t *testing.T) {
			code, _, body := doRequest(t, a, target, nil)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %q", code, body)
			}
			if body != tarball {
				t.Errorf("tarball body = %q, want %q", body, tarball)
			}
		})
	}
}

const (
	pypiJSONType = "application/vnd.pypi.simple.v1+json"
	pypiWheel    = "foo-1.0.0-py3-none-any.whl"
	pypiUploaded = "2020-01-02T03:04:05.678901Z"
)

// buildWheel returns a minimal valid wheel for distribution "foo" 1.0.0.
func buildWheel(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"foo/__init__.py":                   "",
		"foo-1.0.0.dist-info/METADATA":      "Metadata-Version: 2.1\nName: foo\nVersion: 1.0.0\n",
		"foo-1.0.0.dist-info/WHEEL":         "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		"foo-1.0.0.dist-info/RECORD":        "",
		"foo-1.0.0.dist-info/top_level.txt": "foo\n",
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newPyPIUpstream mimics pypi.org: JSON for PEP 691 clients, HTML otherwise.
func newPyPIUpstream(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	wheel := buildWheel(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/foo/":
			fileURL := srv.URL + "/packages/" + pypiWheel
			if strings.Contains(r.Header.Get("Accept"), pypiJSONType) {
				w.Header().Set("Content-Type", pypiJSONType)
				_, _ = w.Write([]byte(`{"meta":{"api-version":"1.1"},"name":"foo","versions":["1.0.0"],"files":[{"filename":"` + pypiWheel +
					`","url":"` + fileURL + `","hashes":{"sha256":"abc"},"requires-python":">=3.8","size":` + strconv.Itoa(len(wheel)) +
					`,"upload-time":"` + pypiUploaded + `","yanked":false,"core-metadata":true}]}`))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="` + fileURL + `#sha256=abc" data-requires-python="&gt;=3.8">` + pypiWheel + `</a></body></html>`))
		case "/packages/" + pypiWheel:
			_, _ = w.Write(wheel)
		case "/packages/" + pypiWheel + ".metadata":
			_, _ = w.Write([]byte("Metadata-Version: 2.1\nName: foo\nVersion: 1.0.0\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, wheel
}

func TestPyPISimpleJSON(t *testing.T) {
	upstream, _ := newPyPIUpstream(t)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.PyPI.SimpleAPIURL = upstream.URL + "/simple" })

	t.Run("json with upload-time passed through", func(t *testing.T) {
		code, hdr, body := doRequest(t, a, "/pypi/simple/foo/", map[string]string{"Accept": pypiJSONType + ", text/html;q=0.01"})
		if code != http.StatusOK {
			t.Fatalf("status = %d, body %q", code, body)
		}
		if ct := hdr.Get("Content-Type"); ct != pypiJSONType {
			t.Errorf("Content-Type = %q, want %q", ct, pypiJSONType)
		}
		var doc struct {
			Meta  map[string]string `json:"meta"`
			Name  string            `json:"name"`
			Files []map[string]any  `json:"files"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("invalid JSON %q: %v", body, err)
		}
		if doc.Meta["api-version"] != "1.1" || doc.Name != "foo" || len(doc.Files) != 1 {
			t.Fatalf("unexpected document: %+v", doc)
		}
		f := doc.Files[0]
		if f["upload-time"] != pypiUploaded {
			t.Errorf("upload-time = %v, want %s", f["upload-time"], pypiUploaded)
		}
		if f["requires-python"] != ">=3.8" || f["filename"] != pypiWheel {
			t.Errorf("file fields not passed through: %v", f)
		}
		fileURL, _ := f["url"].(string)
		if !strings.Contains(fileURL, "/pypi/foo/"+pypiWheel) || strings.HasPrefix(fileURL, upstream.URL) {
			t.Errorf("file url %q must point at the proxy", fileURL)
		}
	})

	t.Run("html kept for html clients", func(t *testing.T) {
		for _, accept := range []string{"", "text/html", "*/*"} {
			headers := map[string]string{}
			if accept != "" {
				headers["Accept"] = accept
			}
			code, hdr, body := doRequest(t, a, "/pypi/simple/foo/", headers)
			if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") || !strings.Contains(body, "<a href=") {
				t.Errorf("Accept %q: status %d type %q body %q", accept, code, hdr.Get("Content-Type"), body)
			}
		}
	})

	t.Run("unsupported accept is 406", func(t *testing.T) {
		code, _, _ := doRequest(t, a, "/pypi/simple/foo/", map[string]string{"Accept": "application/xml"})
		if code != http.StatusNotAcceptable {
			t.Errorf("status = %d, want 406", code)
		}
	})

	t.Run("core metadata sidecar fetches the metadata file", func(t *testing.T) {
		_, _, body := doRequest(t, a, "/pypi/simple/foo/", map[string]string{"Accept": pypiJSONType})
		var doc struct {
			Files []struct {
				URL string `json:"url"`
			} `json:"files"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(doc.Files[0].URL)
		if err != nil {
			t.Fatal(err)
		}
		u.Path += ".metadata"
		code, _, meta := doRequest(t, a, u.RequestURI(), nil)
		if code != http.StatusOK || !strings.HasPrefix(meta, "Metadata-Version:") {
			t.Errorf("metadata sidecar: status %d body %q", code, meta)
		}
	})
}

// uv with --exclude-newer drops files that carry no upload-time, so resolving
// through the proxy proves the PEP 700 field survives.
func TestPyPI_UVExcludeNewerResolvesThroughProxy(t *testing.T) {
	uvPath, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv not installed")
	}
	upstream, _ := newPyPIUpstream(t)
	a := newTestApp(t, func(c *config.Config) { c.Handlers.PyPI.SimpleAPIURL = upstream.URL + "/simple" })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	base := "http://" + ln.Addr().String()

	cutoff := "2021-01-01T00:00:00Z"
	run := func(exclude string) (string, error) {
		// #nosec G204 -- uvPath comes from LookPath; arguments are test constants
		cmd := exec.Command(uvPath, "pip", "compile", "-", "--no-header", "--no-annotate", "--no-config", "--no-cache",
			"--index-url", base+"/pypi/simple/", "--exclude-newer", exclude)
		cmd.Stdin = strings.NewReader("foo\n")
		cmd.Env = append(os.Environ(), "UV_CACHE_DIR="+t.TempDir())
		out, runErr := cmd.CombinedOutput()
		return string(out), runErr
	}

	out, err := run(cutoff)
	if err != nil || !strings.Contains(out, "foo==1.0.0") {
		t.Fatalf("uv --exclude-newer %s did not resolve foo: %v\n%s", cutoff, err, out)
	}

	out, err = run("2019-01-01T00:00:00Z")
	if err == nil {
		t.Fatalf("uv resolved foo although it was uploaded after the cutoff:\n%s", out)
	}
}

func TestNPMMetadataTTLOverrideReachesCache(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"left-pad","versions":{}}`))
	}))
	t.Cleanup(upstream.Close)

	a := newTestApp(t, func(c *config.Config) {
		c.Handlers.NPM.UpstreamRegistry = upstream.URL
		c.Cache.TTLOverrides = map[string]time.Duration{"npm": 90 * time.Minute}
	})
	if code, _, body := doRequest(t, a, "/npm/left-pad", nil); code != http.StatusOK {
		t.Fatalf("status = %d, body %q", code, body)
	}

	pkgs, err := a.metadata.ListPackages(context.Background(), &metadata.ListOptions{Registry: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.ExpiresAt == nil {
			continue
		}
		if got := p.ExpiresAt.Sub(p.CachedAt); got < 89*time.Minute || got > 91*time.Minute {
			t.Errorf("npm metadata freshness = %s, want 90m from cache.ttl_overrides", got)
		}
		return
	}
	t.Fatalf("no npm metadata entry with an expiry among %d packages", len(pkgs))
}

// The mount already strips the registry prefix, so a package named after the registry must keep its name.
func TestPackagesNamedAfterTheRegistryKeepTheirName(t *testing.T) {
	var npmSeen, pypiSeen []string
	npmUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		npmSeen = append(npmSeen, r.URL.Path)
		_, _ = w.Write([]byte(`{"name":"x","versions":{}}`))
	}))
	t.Cleanup(npmUp.Close)
	pypiUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pypiSeen = append(pypiSeen, r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body></body></html>`))
	}))
	t.Cleanup(pypiUp.Close)

	a := newTestApp(t, func(c *config.Config) {
		c.Handlers.NPM.UpstreamRegistry = npmUp.URL
		c.Handlers.PyPI.SimpleAPIURL = pypiUp.URL + "/simple"
	})
	for _, target := range []string{"/npm/npm-run-all", "/npm/npm", "/pypi/simple/pypi-a/", "/pypi/pypi-b/"} {
		if code, _, body := doRequest(t, a, target, nil); code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, body %q", target, code, body)
		}
	}
	if want := []string{"/npm-run-all", "/npm"}; !slices.Equal(npmSeen, want) {
		t.Errorf("npm upstream paths = %v, want %v", npmSeen, want)
	}
	if want := []string{"/simple/pypi-a/", "/simple/pypi-b/"}; !slices.Equal(pypiSeen, want) {
		t.Errorf("pypi upstream paths = %v, want %v", pypiSeen, want)
	}
}
