package app

import (
	"net/http"
	"testing"
)

func TestSeverityFilterOnPackagesList(t *testing.T) {
	a, _ := newScanningApp(t)
	seedScanned(t, a, 0, 60) // every fifth package carries one critical finding

	cases := []struct {
		query string
		want  int
	}{
		{"", 60},
		{"?severity=", 60},
		{"?severity=critical", 12},
		{"?severity=Critical,high", 12},
		{"?severity=high", 0},
		{"?severity=high,moderate,low", 0},
		{"?severity=critical&q=pkg-005", 1},
		{"?severity=critical&q=pkg-006", 0},
	}
	for _, c := range cases {
		if got := getList(t, a, "/api/packages"+c.query); len(got.Packages) != c.want {
			t.Errorf("%q returned %d packages, want %d", c.query, len(got.Packages), c.want)
		}
	}

	paged := getList(t, a, "/api/packages?severity=critical&page=1&page_size=5")
	if paged.TotalGroups != 12 || len(paged.Packages) != 5 {
		t.Errorf("paged severity list = %d groups, %d rows; want 12 groups, 5 rows", paged.TotalGroups, len(paged.Packages))
	}
	for _, p := range getList(t, a, "/api/packages?severity=critical").Packages {
		if p.Vulnerabilities.Counts.Critical == 0 {
			t.Errorf("%s has no critical finding but passed the critical filter", p.Name)
		}
	}
}

func TestSeverityFilterRejectsUnknownValue(t *testing.T) {
	a, _ := newScanningApp(t)
	for _, q := range []string{"?severity=urgent", "?severity=critical,nope"} {
		if code, _, body := doRequest(t, a, "/api/packages"+q, nil); code != http.StatusBadRequest {
			t.Errorf("%q = %d %s, want 400", q, code, body)
		}
	}
}
