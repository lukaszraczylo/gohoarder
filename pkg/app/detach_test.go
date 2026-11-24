package app

import (
	"net/http"
	"net/url"
	"testing"
	"unsafe"
)

// The adaptor's strings point into a buffer fasthttp reuses; a detached request must not see later writes.
func TestDetachRequestSurvivesBufferReuse(t *testing.T) {
	buf := []byte("GET/npm/lodash/-/lodash-1.0.0.tgzq=1proxy.lanBearer secret")
	alias := func(from, to int) string { return unsafe.String(&buf[from], to-from) } // #nosec G103 -- reproduces the adaptor's aliasing
	r := &http.Request{
		Method: alias(0, 3),
		Host:   alias(36, 45),
		URL:    &url.URL{Path: alias(3, 33), RawQuery: alias(33, 36), User: url.UserPassword(alias(36, 41), alias(52, 58))},
		Header: http.Header{"Authorization": {alias(45, 58)}},
	}

	d := detachRequest(r)
	for i := range buf {
		buf[i] = 'x'
	}

	pw, _ := d.URL.User.Password()
	got := []string{d.Method, d.Host, d.URL.Path, d.URL.RawQuery, d.Header.Get("Authorization"), d.URL.User.Username(), pw}
	want := []string{"GET", "proxy.lan", "/npm/lodash/-/lodash-1.0.0.tgz", "q=1", "Bearer secret", "proxy", "secret"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d = %q after the buffer changed, want %q", i, got[i], want[i])
		}
	}
	if r.URL == d.URL {
		t.Fatal("detached request shares the URL with the original")
	}
}
