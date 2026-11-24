package prewarming

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeFetcher struct {
	err   error
	got   map[string]PackageInfo
	calls chan PackageInfo
	mu    sync.Mutex
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{got: map[string]PackageInfo{}, calls: make(chan PackageInfo, 64)}
}

func (f *fakeFetcher) Fetch(_ context.Context, pkg PackageInfo) error {
	f.mu.Lock()
	f.got[pkg.Registry+":"+pkg.Name] = pkg
	f.mu.Unlock()
	f.calls <- pkg
	return f.err
}

type fakePopularity struct {
	top, trending []analytics.PopularPackage
	topLimit      int
}

func (p *fakePopularity) GetTopPackages(limit int) []analytics.PopularPackage {
	p.topLimit = limit
	return p.top
}

func (p *fakePopularity) GetTrendingPackages(int) []analytics.PopularPackage { return p.trending }

func samplePopularity() *fakePopularity {
	return &fakePopularity{
		top:      []analytics.PopularPackage{{Registry: "npm", Name: "lodash", Downloads: 9}, {Registry: "go", Name: "example.com/m", Downloads: 3}},
		trending: []analytics.PopularPackage{{Registry: "npm", Name: "lodash"}, {Registry: "pypi", Name: "requests"}},
	}
}

func TestCycleFetchesEachPopularPackageOnceAsLatest(t *testing.T) {
	f, pop := newFakeFetcher(), samplePopularity()
	w := NewWorker(Config{Enabled: true, Fetcher: f, Popularity: pop, MaxConcurrent: 2, TopPackages: 7})

	w.prewarmPopularPackages(context.Background())

	assert.Len(t, f.got, 3, "lodash appears in both lists and must be fetched once")
	for _, p := range f.got {
		assert.Equal(t, LatestVersion, p.Version)
	}
	assert.Equal(t, 7, pop.topLimit)
}

func TestFetchFailureDoesNotStopTheCycle(t *testing.T) {
	f := newFakeFetcher()
	f.err = errors.New("upstream down")
	w := NewWorker(Config{Enabled: true, Fetcher: f, Popularity: samplePopularity(), MaxConcurrent: 1})

	w.prewarmPopularPackages(context.Background())

	assert.Len(t, f.got, 3)
}

func TestStartRunsACycleAndStopEndsIt(t *testing.T) {
	f := newFakeFetcher()
	w := NewWorker(Config{Enabled: true, Fetcher: f, Popularity: samplePopularity(), Interval: time.Hour})

	w.Start(context.Background())
	w.Start(context.Background()) // second start must not spawn a second loop

	select {
	case <-f.calls:
	case <-time.After(5 * time.Second):
		t.Fatal("Start never ran a pre-warm cycle")
	}
	done := make(chan struct{})
	go func() { w.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
	w.Stop() // idempotent
}

func TestDisabledWorkerNeverFetches(t *testing.T) {
	f := newFakeFetcher()
	w := NewWorker(Config{Enabled: false, Fetcher: f, Popularity: samplePopularity()})

	w.Start(context.Background())
	w.TriggerPrewarm(context.Background())
	require.NoError(t, w.PrewarmPackage(context.Background(), "npm", "lodash", "4.17.21"))
	w.Stop()

	assert.Empty(t, f.calls)
}

func TestStopIsSafeWithoutStart(t *testing.T) {
	assert.NotPanics(t, func() {
		NewWorker(Config{Enabled: true, Fetcher: newFakeFetcher(), Popularity: samplePopularity()}).Stop()
		NewWorker(Config{}).Stop()
		(*Worker)(nil).Stop()
	})
}

func TestStartWithoutFetcherDoesNotRun(t *testing.T) {
	w := NewWorker(Config{Enabled: true, Popularity: samplePopularity()})
	w.Start(context.Background())
	w.Stop()
	assert.Nil(t, w.cancel)
}

func TestPrewarmPackagePassesExplicitVersionAndReturnsError(t *testing.T) {
	f := newFakeFetcher()
	f.err = errors.New("boom")
	w := NewWorker(Config{Enabled: true, Fetcher: f, Popularity: samplePopularity()})

	err := w.PrewarmPackage(context.Background(), "npm", "lodash", "4.17.21")

	require.ErrorContains(t, err, "boom")
	assert.Equal(t, "4.17.21", f.got["npm:lodash"].Version)
}
