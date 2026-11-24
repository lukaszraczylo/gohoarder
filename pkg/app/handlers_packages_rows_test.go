package app

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

func rowNames(out map[string]any) []string {
	items, _ := out["packages"].([]any)
	names := make([]string, 0, len(items))
	for i := range items {
		name, _ := jsonAt(items, i, "name").(string)
		names = append(names, name)
	}
	return names
}

func TestRowsLayoutFiltersByVerdict(t *testing.T) {
	a := newVerdictApp(t)
	for verdict, want := range map[string][]string{
		"held":     {"held"},
		"bypassed": {"waved"},
		"cleared":  {"plain"},
		"pending":  {},
	} {
		out, _ := getJSON(t, a, "/api/packages?layout=rows&verdict="+verdict)
		if got := rowNames(out); !slices.Equal(got, want) {
			t.Errorf("verdict=%s names = %v, want %v", verdict, got, want)
		}
		if int(out["total"].(float64)) != len(want) {
			t.Errorf("verdict=%s total = %v, want %d", verdict, out["total"], len(want))
		}
	}
}

func TestRowsLayoutCountsIgnoreTheVerdictFilter(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?layout=rows&verdict=held")
	for verdict, want := range map[string]float64{"held": 1, "bypassed": 1, "cleared": 1, "pending": 0} {
		if got := jsonAt(out, "counts", "verdicts", verdict); got != want {
			t.Errorf("counts.verdicts.%s = %v, want %v", verdict, got, want)
		}
	}
	if got := jsonAt(out, "counts", "severity_packages", "critical"); got != float64(2) {
		t.Errorf("counts.severity_packages.critical = %v, want 2", got)
	}
	if got := jsonAt(out, "counts", "vulnerable_allowed"); got != float64(0) {
		t.Errorf("counts.vulnerable_allowed = %v, want 0", got)
	}
}

func TestRowsLayoutSeverityFilterNarrowsRows(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?layout=rows&severity=critical")
	if got := rowNames(out); !slices.Equal(got, []string{"held", "waved"}) {
		t.Errorf("names = %v, want held and waved", got)
	}
	out, _ = getJSON(t, a, "/api/packages?layout=rows&severity=high")
	if got := rowNames(out); len(got) != 0 {
		t.Errorf("high names = %v, want none", got)
	}
}

func TestRowsLayoutSearchesAndSorts(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?layout=rows&q=WAV")
	if got := rowNames(out); !slices.Equal(got, []string{"waved"}) {
		t.Errorf("q names = %v", got)
	}
	out, _ = getJSON(t, a, "/api/packages?layout=rows&sort=name&order=desc")
	if got := rowNames(out); !slices.Equal(got, []string{"waved", "plain", "held"}) {
		t.Errorf("desc names = %v", got)
	}
	out, _ = getJSON(t, a, "/api/packages?layout=rows&sort=last_scanned&order=asc")
	if len(rowNames(out)) != 3 {
		t.Errorf("last_scanned sort lost rows: %v", rowNames(out))
	}
}

func TestRowsLayoutPagesAndReportsTotals(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?layout=rows&page=2&page_size=2")
	if got := rowNames(out); !slices.Equal(got, []string{"waved"}) {
		t.Errorf("page 2 names = %v, want waved", got)
	}
	if out["total"] != float64(3) || out["page"] != float64(2) || out["page_size"] != float64(2) {
		t.Errorf("total/page/page_size = %v/%v/%v", out["total"], out["page"], out["page_size"])
	}
	out, _ = getJSON(t, a, "/api/packages?layout=rows&page=9&page_size=2")
	if len(rowNames(out)) != 0 || out["total"] != float64(3) {
		t.Errorf("past the end: names %v total %v", rowNames(out), out["total"])
	}
}

func TestRowsLayoutCapsPageSize(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?layout=rows&page_size=100000")
	if out["page_size"] != float64(maxPageSize) {
		t.Errorf("page_size = %v, want %d", out["page_size"], maxPageSize)
	}
}

func TestRowsLayoutRejectsBadParams(t *testing.T) {
	a := newVerdictApp(t)
	for _, q := range []string{"verdict=maybe", "sort=colour", "order=sideways", "severity=huge"} {
		code, _, body := doRequest(t, a, "/api/packages?layout=rows&"+q, nil)
		if code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", q, code, body)
		}
	}
}

func TestRowsLayoutKeepsPendingRows(t *testing.T) {
	a := newVerdictApp(t)
	now := time.Now()
	if err := a.metadata.SavePackage(context.Background(), &metadata.Package{
		Registry: "npm", Name: "unscanned", Version: "1.0.0", StorageKey: "npm/unscanned", Size: 1, CachedAt: now, LastAccessed: now,
	}); err != nil {
		t.Fatal(err)
	}
	out, _ := getJSON(t, a, "/api/packages?layout=rows&verdict=pending")
	if got := rowNames(out); !slices.Equal(got, []string{"unscanned"}) {
		t.Errorf("pending names = %v", got)
	}
}

func TestListWithoutLayoutIsUnchanged(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?verdict=held&sort=last_scanned")
	if got := rowNames(out); len(got) != 3 {
		t.Errorf("legacy list ignored nothing: %v", got)
	}
	if _, ok := out["counts"]; ok {
		t.Error("legacy response gained counts")
	}
}

func TestRowsLayoutSortsByRisk(t *testing.T) {
	a := newVerdictApp(t)
	out, _ := getJSON(t, a, "/api/packages?layout=rows&sort=risk&order=desc")
	got := rowNames(out)
	if len(got) != 3 || got[2] != "plain" {
		t.Errorf("risk desc names = %v, want the clean package last", got)
	}
}

func TestRowsLayoutExcludesGoMetadataFiles(t *testing.T) {
	a := newVerdictApp(t)
	before, _ := getJSON(t, a, "/api/packages?layout=rows")
	now := time.Now()
	for _, name := range []string{"example.com/m/@v/v1.0.0.mod", "example.com/m/@v/v1.0.0.info", "example.com/m/@v/v1.0.0.zip", "example.com/only/@v/v0.1.0.mod"} {
		if err := a.metadata.SavePackage(context.Background(), &metadata.Package{
			Registry: "go", Name: name, Version: "v1.0.0", StorageKey: "go/" + name, Size: 1, CachedAt: now, LastAccessed: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	out, _ := getJSON(t, a, "/api/packages?layout=rows&registry=go")
	if got := rowNames(out); !slices.Equal(got, []string{"example.com/m"}) {
		t.Errorf("go rows = %v, want only the .zip", got)
	}
	if out["total"].(float64) != 1 {
		t.Errorf("total = %v, want 1", out["total"])
	}
	if pending := out["counts"].(map[string]any)["verdicts"].(map[string]any)["pending"].(float64); pending != 1 {
		t.Errorf("pending count = %v, want 1", pending)
	}

	after, _ := getJSON(t, a, "/api/packages?layout=rows")
	if after["total"].(float64) != before["total"].(float64)+1 {
		t.Errorf("total = %v, want %v", after["total"], before["total"].(float64)+1)
	}
}
