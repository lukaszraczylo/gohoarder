package network_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func redirectClient(allowPrivate bool) *network.Client {
	return network.NewClient(network.Config{
		Timeout:               5 * time.Second,
		MaxRetries:            1,
		AllowPrivateRedirects: allowPrivate,
	})
}

// hostPolicy allows only the listed hostnames (port ignored).
func hostPolicy(hosts ...string) func(*url.URL) error {
	return func(u *url.URL) error {
		for _, h := range hosts {
			if u.Hostname() == h {
				return nil
			}
		}
		return fmt.Errorf("host %q not allowed", u.Hostname())
	}
}

func okServer(hit *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte("secret"))
	}))
}

func TestRedirectToDisallowedHostRefused(t *testing.T) {
	var hit atomic.Int32
	target := okServer(&hit)
	defer target.Close()
	// Same loopback server under a different hostname: allowed host redirects to a disallowed one.
	redirectTo := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.RedirectHandler(redirectTo, http.StatusFound))
	defer origin.Close()

	_, _, err := redirectClient(true).GetWithRedirectCheck(context.Background(), origin.URL, nil, hostPolicy("127.0.0.1"))
	require.Error(t, err)
	assert.Zero(t, hit.Load(), "disallowed hop must not be fetched")
}

func TestRedirectToLoopbackRefused(t *testing.T) {
	var hit atomic.Int32
	target := okServer(&hit)
	defer target.Close()
	// Allowed by name, but resolves to loopback on a different host:port than the origin.
	origin := httptest.NewServer(http.RedirectHandler(strings.Replace(target.URL, "127.0.0.1", "localhost", 1), http.StatusFound))
	defer origin.Close()

	_, _, err := redirectClient(false).GetWithRedirectCheck(context.Background(), origin.URL, nil, hostPolicy("127.0.0.1", "localhost"))
	require.Error(t, err)
	assert.Zero(t, hit.Load(), "loopback hop must not be fetched")
}

func TestRedirectToPrivateLiteralRefused(t *testing.T) {
	for _, loc := range []string{"http://10.1.2.3/x", "http://169.254.169.254/latest/meta-data", "http://[::1]/x", "http://192.168.0.1/x"} {
		origin := httptest.NewServer(http.RedirectHandler(loc, http.StatusFound))
		_, _, err := redirectClient(false).Get(context.Background(), origin.URL, nil)
		origin.Close()
		require.Error(t, err, loc)
	}
}

func TestRedirectAllowedToAllowedWorks(t *testing.T) {
	var hit atomic.Int32
	target := okServer(&hit)
	defer target.Close()
	origin := httptest.NewServer(http.RedirectHandler(strings.Replace(target.URL, "127.0.0.1", "localhost", 1), http.StatusFound))
	defer origin.Close()

	body, status, err := redirectClient(true).GetWithRedirectCheck(context.Background(), origin.URL, nil, hostPolicy("127.0.0.1", "localhost"))
	require.NoError(t, err)
	defer func() { _ = body.Close() }()
	data, _ := io.ReadAll(body)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "secret", string(data))
}

func TestRedirectHopsCapped(t *testing.T) {
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
	}))
	defer srv.Close()

	_, _, err := redirectClient(true).Get(context.Background(), srv.URL, nil)
	require.Error(t, err)
	assert.LessOrEqual(t, int(hits.Load()), 11)
}

func TestRedirectToNonHTTPSchemeRefused(t *testing.T) {
	origin := httptest.NewServer(http.RedirectHandler("file:///etc/passwd", http.StatusFound))
	defer origin.Close()
	_, _, err := redirectClient(true).Get(context.Background(), origin.URL, nil)
	require.Error(t, err)
}

func TestRedirectDropsAuthorizationAcrossHosts(t *testing.T) {
	var got atomic.Value
	got.Store("unset")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
	}))
	defer target.Close()
	origin := httptest.NewServer(http.RedirectHandler(strings.Replace(target.URL, "127.0.0.1", "localhost", 1), http.StatusFound))
	defer origin.Close()

	body, _, err := redirectClient(true).Get(context.Background(), origin.URL, map[string]string{"Authorization": "Bearer x"})
	require.NoError(t, err)
	_ = body.Close()
	assert.Equal(t, "", got.Load())
}

func TestSameHostRedirectToLoopbackStillWorks(t *testing.T) {
	// A private index redirecting within itself is operator-trusted.
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, status, err := redirectClient(false).Get(context.Background(), srv.URL+"/a", nil)
	require.NoError(t, err)
	_ = body.Close()
	assert.Equal(t, http.StatusOK, status)
}
