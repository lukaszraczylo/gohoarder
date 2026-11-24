package app

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
)

// proxyHandler mounts a net/http proxy handler on fiber with a request that owns its strings.
// The adaptor builds URL, Host, Method and header strings over fasthttp's request buffer, which the
// next request on the connection overwrites; the proxies hand these strings to background scans,
// singleflight keys and analytics that outlive the request.
func proxyHandler(h http.Handler) fiber.Handler {
	return adaptor.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, detachRequest(r))
	}))
}

func detachRequest(r *http.Request) *http.Request {
	d := r.Clone(r.Context())
	d.Method = strings.Clone(r.Method)
	d.Proto = strings.Clone(r.Proto)
	d.Host = strings.Clone(r.Host)
	d.RequestURI = strings.Clone(r.RequestURI)
	u := *r.URL
	u.Scheme = strings.Clone(u.Scheme)
	u.Host = strings.Clone(u.Host)
	u.Path = strings.Clone(u.Path)
	u.RawPath = strings.Clone(u.RawPath)
	u.RawQuery = strings.Clone(u.RawQuery)
	u.Fragment = strings.Clone(u.Fragment)
	u.User = nil
	if r.URL.User != nil {
		if p, ok := r.URL.User.Password(); ok {
			u.User = url.UserPassword(strings.Clone(r.URL.User.Username()), strings.Clone(p))
		} else {
			u.User = url.User(strings.Clone(r.URL.User.Username()))
		}
	}
	d.URL = &u
	h := make(http.Header, len(r.Header))
	for k, vs := range r.Header {
		cp := make([]string, len(vs))
		for i, v := range vs {
			cp[i] = strings.Clone(v)
		}
		h[strings.Clone(k)] = cp
	}
	d.Header = h
	return d
}
