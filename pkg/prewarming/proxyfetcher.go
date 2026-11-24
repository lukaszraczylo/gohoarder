package prewarming

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/lukaszraczylo/gohoarder/pkg/proxy/pypi"
)

const (
	registryNPM  = "npm"
	registryPyPI = "pypi"
	registryGo   = "go"

	// proxyHost is only a placeholder: the handlers are called in-process and never dial it.
	proxyHost        = "gohoarder.invalid"
	maxMetadataBytes = 64 << 20
)

var (
	hrefPattern   = regexp.MustCompile(`href="([^"]+)"`)
	numericSemVer = regexp.MustCompile(`^\d+(\.\d+)*$`)
	distSuffixes  = []string{".whl", ".tar.gz", ".zip", ".egg"}
)

// ProxyFetcher pre-warms through the registry handlers in-process, so artifacts are cached,
// scanned and policy-checked exactly like a client request.
type ProxyFetcher struct {
	handlers map[string]http.Handler
}

// NewProxyFetcher returns a fetcher with no registries mounted.
func NewProxyFetcher() *ProxyFetcher {
	return &ProxyFetcher{handlers: make(map[string]http.Handler)}
}

// Mount registers the handler serving a registry; it must already strip the "/<registry>" prefix
// the way the HTTP server mounts it. Mount before the worker starts.
func (f *ProxyFetcher) Mount(registry string, h http.Handler) {
	f.handlers[registry] = h
}

// Fetch resolves the version when it is empty or LatestVersion, then downloads the artifact.
func (f *ProxyFetcher) Fetch(ctx context.Context, pkg PackageInfo) error {
	h, ok := f.handlers[pkg.Registry]
	if !ok {
		return fmt.Errorf("registry %q is not mounted", pkg.Registry)
	}
	if !safeName(pkg.Name) {
		return fmt.Errorf("unsafe package name %q", pkg.Name)
	}
	latest := pkg.Version == "" || pkg.Version == LatestVersion
	switch pkg.Registry {
	case registryNPM:
		return f.fetchNPM(ctx, h, pkg.Name, pkg.Version, latest)
	case registryGo:
		return f.fetchGo(ctx, h, pkg.Name, pkg.Version, latest)
	case registryPyPI:
		return f.fetchPyPI(ctx, h, pkg.Name, pkg.Version, latest)
	default:
		return fmt.Errorf("unsupported registry %q", pkg.Registry)
	}
}

func safeName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "?#\\") && !strings.Contains(name, "..") && !strings.HasPrefix(name, "/")
}

func (f *ProxyFetcher) fetchNPM(ctx context.Context, h http.Handler, name, version string, latest bool) error {
	if latest {
		body, err := call(ctx, h, "/npm/"+name, "", true)
		if err != nil {
			return fmt.Errorf("npm metadata: %w", err)
		}
		var meta struct {
			DistTags map[string]string `json:"dist-tags"`
		}
		if err := json.Unmarshal(body, &meta); err != nil {
			return fmt.Errorf("npm metadata: %w", err)
		}
		if version = meta.DistTags["latest"]; version == "" {
			return fmt.Errorf("npm %s has no latest dist-tag", name)
		}
	}
	bare := name[strings.LastIndex(name, "/")+1:]
	_, err := call(ctx, h, "/npm/"+name+"/-/"+bare+"-"+version+".tgz", "", false)
	return err
}

func (f *ProxyFetcher) fetchGo(ctx context.Context, h http.Handler, name, version string, latest bool) error {
	if latest {
		body, err := call(ctx, h, "/go/"+name+"/@latest", "", true)
		if err != nil {
			return fmt.Errorf("go latest: %w", err)
		}
		var info struct{ Version string }
		if err := json.Unmarshal(body, &info); err != nil {
			return fmt.Errorf("go latest: %w", err)
		}
		if version = info.Version; version == "" {
			return fmt.Errorf("go %s has no latest version", name)
		}
	}
	_, err := call(ctx, h, "/go/"+name+"/@v/"+version+".zip", "", false)
	return err
}

func (f *ProxyFetcher) fetchPyPI(ctx context.Context, h http.Handler, name, version string, latest bool) error {
	page, err := call(ctx, h, "/pypi/simple/"+name+"/", "text/html", true)
	if err != nil {
		return fmt.Errorf("pypi package page: %w", err)
	}
	link, err := pickPyPIFile(page, version, latest)
	if err != nil {
		return fmt.Errorf("pypi %s: %w", name, err)
	}
	if !strings.HasPrefix(link.Path, "/pypi/") {
		return fmt.Errorf("pypi %s: link %q is not a proxy path", name, link.Path)
	}
	_, err = call(ctx, h, link.Path, "", false, link.RawQuery)
	return err
}

type distFile struct {
	link    *url.URL
	version string
}

// pickPyPIFile chooses one distribution: the wanted version or the highest plain release,
// preferring a wheel over an sdist.
func pickPyPIFile(page []byte, version string, latest bool) (*url.URL, error) {
	var wheel, sdist *distFile
	for _, m := range hrefPattern.FindAllSubmatch(page, -1) {
		u, err := url.Parse(html.UnescapeString(string(m[1])))
		if err != nil {
			continue
		}
		file := path.Base(u.Path)
		if !hasDistSuffix(file) {
			continue
		}
		cand := &distFile{link: u, version: pypi.ReleaseVersion(file)}
		if latest {
			if !numericSemVer.MatchString(cand.version) {
				continue
			}
		} else if cand.version != version {
			continue
		}
		if strings.HasSuffix(file, ".whl") {
			wheel = better(wheel, cand, latest)
		} else {
			sdist = better(sdist, cand, latest)
		}
	}
	for _, c := range []*distFile{wheel, sdist} {
		if c != nil {
			return c.link, nil
		}
	}
	if latest {
		return nil, fmt.Errorf("no plain release file listed")
	}
	return nil, fmt.Errorf("no file listed for version %q", version)
}

func better(cur, cand *distFile, latest bool) *distFile {
	if cur == nil || (latest && compareVersions(cand.version, cur.version) > 0) {
		return cand
	}
	return cur
}

func hasDistSuffix(file string) bool {
	for _, s := range distSuffixes {
		if strings.HasSuffix(file, s) {
			return true
		}
	}
	return false
}

func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

// call serves a GET through h. It keeps the body only when capture is set and fails on non-200.
func call(ctx context.Context, h http.Handler, p, accept string, capture bool, rawQuery ...string) ([]byte, error) {
	u := url.URL{Scheme: "http", Host: proxyHost, Path: p}
	if len(rawQuery) > 0 {
		u.RawQuery = rawQuery[0]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	w := &sink{header: make(http.Header), capture: capture}
	h.ServeHTTP(w, req)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.status != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", p, w.status)
	}
	if w.overflow {
		return nil, fmt.Errorf("GET %s: response over %d bytes", p, maxMetadataBytes)
	}
	return w.buf.Bytes(), nil
}

// sink is a ResponseWriter that discards artifact bytes so a pre-warm never holds one in memory.
type sink struct {
	header   http.Header
	buf      bytes.Buffer
	status   int
	capture  bool
	overflow bool
}

func (s *sink) Header() http.Header { return s.header }

func (s *sink) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
}

func (s *sink) Write(b []byte) (int, error) {
	s.WriteHeader(http.StatusOK)
	if s.capture {
		if s.buf.Len()+len(b) > maxMetadataBytes {
			s.overflow = true
		} else {
			s.buf.Write(b)
		}
	}
	return len(b), nil
}
