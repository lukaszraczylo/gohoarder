package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata/gormstore"
)

type trendResponse struct {
	VulnerabilityHistoryStart *string `json:"vulnerability_history_start"`
	Period                    string  `json:"period"`
	From                      string  `json:"from"`
	To                        string  `json:"to"`
	Points                    []struct {
		VulnerablePackages *int64 `json:"vulnerable_packages"`
		Blocked            *int64 `json:"blocked"`
		Date               string `json:"date"`
		TotalPackages      int64  `json:"total_packages"`
	} `json:"points"`
}

func trendDay(daysAgo int) string {
	return time.Now().UTC().AddDate(0, 0, -daysAgo).Format("2006-01-02")
}

func getTrend(t *testing.T, a *App, target string) trendResponse {
	t.Helper()
	code, _, body := doRequest(t, a, target, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", target, code, body)
	}
	var out trendResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

func TestSeverityAndTrendQueryCountIsConstant(t *testing.T) {
	a, counter := newScanningApp(t)
	targets := []string{
		"/api/packages?severity=critical,high",
		"/api/packages?severity=low&page=1&page_size=25",
		"/api/stats/trend?period=90day",
	}
	seedScanned(t, a, 0, 20)
	small := map[string]int{}
	for _, target := range targets {
		small[target] = queriesFor(t, a, counter, target)
	}
	seedScanned(t, a, 20, 100)
	for _, target := range targets {
		large := queriesFor(t, a, counter, target)
		t.Logf("%-50s 20 rows: %2d queries, 120 rows: %2d queries", target, small[target], large)
		if large != small[target] {
			t.Errorf("%s: %d queries for 20 rows but %d for 120 rows", target, small[target], large)
		}
	}
	if n := small["/api/stats/trend?period=90day"]; n != 1 {
		t.Errorf("trend costs %d statements, want 1", n)
	}
}

func TestStatsTrendEndpoint(t *testing.T) {
	a := newTestApp(t, nil)

	empty := getTrend(t, a, "/api/stats/trend")
	if empty.Period != "30day" || empty.Points == nil || len(empty.Points) != 0 || empty.VulnerabilityHistoryStart != nil {
		t.Fatalf("empty trend = %+v, want the default period, no points and no vulnerability start", empty)
	}

	store := a.metadata.(*gormstore.GORMStoreV2)
	one, two := int64(1), int64(2)
	for _, row := range []gormstore.StatsSnapshotModel{
		{Day: trendDay(100), TotalPackages: 5},
		{Day: trendDay(40), TotalPackages: 6},
		{Day: trendDay(2), TotalPackages: 7},
		{Day: trendDay(1), TotalPackages: 8, VulnerablePackages: &two, Blocked: &one},
	} {
		if err := store.DB().Create(&row).Error; err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}
	}

	cases := []struct {
		target string
		period string
		points int
	}{
		{"/api/stats/trend", "30day", 2},
		{"/api/stats/trend?period=30day", "30day", 2},
		{"/api/stats/trend?period=90day", "90day", 3},
		{"/api/stats/trend?period=1year", "1year", 4},
	}
	for _, c := range cases {
		got := getTrend(t, a, c.target)
		if got.Period != c.period || len(got.Points) != c.points {
			t.Errorf("%s = period %q, %d points; want %q, %d", c.target, got.Period, len(got.Points), c.period, c.points)
		}
	}

	got := getTrend(t, a, "/api/stats/trend")
	if got.To != trendDay(0) || got.From != trendDay(29) {
		t.Errorf("window = %s..%s, want %s..%s", got.From, got.To, trendDay(29), trendDay(0))
	}
	if got.Points[0].Date != trendDay(2) || got.Points[1].Date != trendDay(1) {
		t.Errorf("points not oldest first: %+v", got.Points)
	}
	if got.Points[0].VulnerablePackages != nil || got.Points[0].Blocked != nil {
		t.Errorf("a day without vulnerability data must carry null, got %+v", got.Points[0])
	}
	if v := got.Points[1].VulnerablePackages; v == nil || *v != 2 {
		t.Errorf("vulnerable_packages = %v, want 2", v)
	}
	if got.VulnerabilityHistoryStart == nil || *got.VulnerabilityHistoryStart != trendDay(1) {
		t.Errorf("vulnerability_history_start = %v, want %s", got.VulnerabilityHistoryStart, trendDay(1))
	}
}

func TestStatsTrendRejectsUnknownPeriod(t *testing.T) {
	a := newTestApp(t, nil)
	for _, p := range []string{"7day", "1day", "bogus", "1YEAR"} {
		if code, _, body := doRequest(t, a, "/api/stats/trend?period="+p, nil); code != http.StatusBadRequest {
			t.Errorf("period=%s = %d %s, want 400", p, code, body)
		}
	}
}
