package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
)

// Handlers must not set CORS headers themselves: apiOriginGuard owns the decision.
func TestHandlersSetNoCORSHeaders(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "cors.go" {
			continue
		}
		parsed, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(v, "Access-Control-") {
				t.Errorf("%s: handler sets %q; apiOriginGuard owns CORS", fset.Position(lit.Pos()), v)
			}
			return true
		})
	}
}

func TestAPIResponsesNeverCarryWildcardOrigin(t *testing.T) {
	const dashboard = "https://dash.example.com"
	a := newTestApp(t, func(c *config.Config) { c.Server.AllowedOrigins = []string{dashboard} })
	targets := []string{
		"/api/stats", "/api/info", "/api/config", "/api/packages",
		"/api/analytics/top", "/api/analytics/trending", "/api/analytics/trends", "/api/analytics/total",
		"/api/analytics/search?q=x", "/api/stats/timeseries",
	}
	for _, origin := range []string{"", dashboard, "https://evil.example.net"} {
		for _, target := range targets {
			hdr := map[string]string{}
			if origin != "" {
				hdr["Origin"] = origin
			}
			code, h, _ := doRequest(t, a, target, hdr)
			if code == http.StatusNotFound {
				t.Errorf("GET %s = 404, route missing", target)
			}
			if got := h.Get("Access-Control-Allow-Origin"); got == "*" {
				t.Errorf("GET %s Origin=%q carries Access-Control-Allow-Origin: *", target, origin)
			}
		}
	}
}
