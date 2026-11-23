package app

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

func TestMigrateLegacyPyPIRecords(t *testing.T) {
	a := newTestApp(t, nil)
	ctx := context.Background()
	now := time.Now()
	save := func(registry, version string) {
		t.Helper()
		err := a.metadata.SavePackage(ctx, &metadata.Package{
			Registry: registry, Name: "six", Version: version,
			StorageKey: registry + "/six/" + version, Size: 1, CachedAt: now, LastAccessed: now,
		})
		if err != nil {
			t.Fatalf("save %s/%s: %v", registry, version, err)
		}
	}
	const wheel = "six-1.17.0-py2.py3-none-any.whl"
	save("pypi", wheel)
	save("pypi", wheel+".metadata")
	save("pypi", "page")
	save("npm", "1.0.0")

	a.migrateLegacyPyPIRecords(ctx)
	a.migrateLegacyPyPIRecords(ctx) // idempotent

	list := func(registry string) map[string]string {
		pkgs, err := a.metadata.ListPackages(ctx, &metadata.ListOptions{Registry: registry})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, p := range pkgs {
			out[p.Version] = p.ReleaseVersion
		}
		return out
	}
	got := list("pypi")
	if len(got) != 2 || got[wheel] != "1.17.0" || got["page"] != "" {
		t.Errorf("pypi rows = %v, want the wheel with release version 1.17.0 and the page, no sidecar", got)
	}
	if npm := list("npm"); len(npm) != 1 || npm["1.0.0"] != "" {
		t.Errorf("npm rows changed: %v", npm)
	}
}
