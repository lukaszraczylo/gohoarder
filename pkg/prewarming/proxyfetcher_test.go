package prewarming

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type routes struct {
	resp map[string]string
	hits []string
	mu   sync.Mutex
}

func (r *routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	key := req.URL.RequestURI()
	r.mu.Lock()
	r.hits = append(r.hits, key)
	r.mu.Unlock()
	body, ok := r.resp[key]
	if !ok {
		http.NotFound(w, req)
		return
	}
	_, _ = w.Write([]byte(body))
}

func fetcherFor(registry string, resp map[string]string) (*ProxyFetcher, *routes) {
	rt := &routes{resp: resp}
	f := NewProxyFetcher()
	f.Mount(registry, rt)
	return f, rt
}

func TestFetchNPMLatestDownloadsTheTarball(t *testing.T) {
	f, rt := fetcherFor("npm", map[string]string{
		"/npm/@scope/pkg":                 `{"dist-tags":{"latest":"2.1.0"}}`,
		"/npm/@scope/pkg/-/pkg-2.1.0.tgz": "tarball",
	})

	require.NoError(t, f.Fetch(context.Background(), PackageInfo{Registry: "npm", Name: "@scope/pkg", Version: LatestVersion}))

	assert.Equal(t, []string{"/npm/@scope/pkg", "/npm/@scope/pkg/-/pkg-2.1.0.tgz"}, rt.hits)
}

func TestFetchNPMExplicitVersionSkipsMetadata(t *testing.T) {
	f, rt := fetcherFor("npm", map[string]string{"/npm/lodash/-/lodash-4.17.21.tgz": "x"})

	require.NoError(t, f.Fetch(context.Background(), PackageInfo{Registry: "npm", Name: "lodash", Version: "4.17.21"}))

	assert.Equal(t, []string{"/npm/lodash/-/lodash-4.17.21.tgz"}, rt.hits)
}

func TestFetchGoLatestDownloadsTheZip(t *testing.T) {
	f, rt := fetcherFor("go", map[string]string{
		"/go/example.com/m/@latest":       `{"Version":"v1.2.3","Time":"2026-01-01T00:00:00Z"}`,
		"/go/example.com/m/@v/v1.2.3.zip": "zip",
	})

	require.NoError(t, f.Fetch(context.Background(), PackageInfo{Registry: "go", Name: "example.com/m", Version: LatestVersion}))

	assert.Equal(t, []string{"/go/example.com/m/@latest", "/go/example.com/m/@v/v1.2.3.zip"}, rt.hits)
}

const pypiPage = `<html><body>
<a href="http://h/pypi/req/req-2.9.0-py3-none-any.whl?original_url=https%3A%2F%2Ffiles%2Fa">a</a>
<a href="http://h/pypi/req/req-2.31.0.tar.gz?original_url=https%3A%2F%2Ffiles%2Fb">b</a>
<a href="http://h/pypi/req/req-2.31.0-py3-none-any.whl?original_url=https%3A%2F%2Ffiles%2Fc&amp;x=1">c</a>
<a href="http://h/pypi/req/req-3.0.0rc1-py3-none-any.whl?original_url=https%3A%2F%2Ffiles%2Fd">d</a>
<a href="http://h/pypi/req/req-2.31.0-py3-none-any.whl.metadata?original_url=m">m</a>
</body></html>`

func TestFetchPyPILatestPicksHighestPlainReleaseWheel(t *testing.T) {
	f, rt := fetcherFor("pypi", map[string]string{
		"/pypi/simple/req/": pypiPage,
		"/pypi/req/req-2.31.0-py3-none-any.whl?original_url=https%3A%2F%2Ffiles%2Fc&x=1": "whl",
	})

	require.NoError(t, f.Fetch(context.Background(), PackageInfo{Registry: "pypi", Name: "req", Version: LatestVersion}))

	require.Len(t, rt.hits, 2)
	assert.Equal(t, "/pypi/req/req-2.31.0-py3-none-any.whl?original_url=https%3A%2F%2Ffiles%2Fc&x=1", rt.hits[1])
}

func TestFetchPyPIExplicitVersionAndMissingVersion(t *testing.T) {
	f, rt := fetcherFor("pypi", map[string]string{
		"/pypi/simple/req/": pypiPage,
		"/pypi/req/req-2.9.0-py3-none-any.whl?original_url=https%3A%2F%2Ffiles%2Fa": "whl",
	})

	require.NoError(t, f.Fetch(context.Background(), PackageInfo{Registry: "pypi", Name: "req", Version: "2.9.0"}))
	assert.Contains(t, rt.hits[1], "req-2.9.0")
	require.ErrorContains(t, f.Fetch(context.Background(), PackageInfo{Registry: "pypi", Name: "req", Version: "9.9.9"}), "no file listed")
}

func TestFetchRejectsBadInput(t *testing.T) {
	f, rt := fetcherFor("npm", map[string]string{})
	ctx := context.Background()

	require.ErrorContains(t, f.Fetch(ctx, PackageInfo{Registry: "cargo", Name: "x"}), "not mounted")
	for _, name := range []string{"", "../etc", "a?b", "/abs", "a#b"} {
		assert.ErrorContains(t, f.Fetch(ctx, PackageInfo{Registry: "npm", Name: name}), "unsafe package name", name)
	}
	assert.Empty(t, rt.hits)
}

func TestFetchReportsUpstreamFailure(t *testing.T) {
	f, _ := fetcherFor("npm", map[string]string{})

	err := f.Fetch(context.Background(), PackageInfo{Registry: "npm", Name: "ghost", Version: LatestVersion})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestSinkDiscardsArtifactBytes(t *testing.T) {
	big := strings.Repeat("a", 1<<20)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(big)) })

	body, err := call(context.Background(), h, "/x", "", false)

	require.NoError(t, err)
	assert.Empty(t, body)
}
