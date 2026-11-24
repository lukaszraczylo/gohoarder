package app

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/analytics"
	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/prewarming"
)

// TestWorkersDrainTheBroadcastChannel pins that the app starts the websocket
// event loop: without it the 256-slot broadcast channel fills and every later
// event is dropped.
func TestWorkersDrainTheBroadcastChannel(t *testing.T) {
	a := newTestApp(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.startWorkers(ctx)

	// Bursts stay under the 256-slot channel and wait for the loop to drain between them, so the
	// result depends on the loop running, not on how fast the scheduler runs it.
	const (
		bursts   = 10
		burstLen = 100
	)
	for b := 0; b < bursts; b++ {
		for i := 0; i < burstLen; i++ {
			a.wsServer.BroadcastEvent("cache_hit", map[string]interface{}{"i": i})
		}
		deadline := time.Now().Add(10 * time.Second)
		for a.wsServer.Pending() > 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}

	if dropped := a.wsServer.Dropped(); dropped != 0 {
		t.Fatalf("dropped %d of %d events; the broadcast loop is not draining the channel", dropped, bursts*burstLen)
	}
}

type recordingFetcher struct{ got chan prewarming.PackageInfo }

func (f recordingFetcher) Fetch(_ context.Context, pkg prewarming.PackageInfo) error {
	f.got <- pkg
	return nil
}

type fixedPopularity struct{}

func (fixedPopularity) GetTopPackages(int) []analytics.PopularPackage {
	return []analytics.PopularPackage{{Registry: "npm", Name: "lodash"}}
}

func (fixedPopularity) GetTrendingPackages(int) []analytics.PopularPackage { return nil }

// TestEnabledPrewarmWorkerStartsWithTheApp pins that startWorkers starts the pre-warm loop.
func TestEnabledPrewarmWorkerStartsWithTheApp(t *testing.T) {
	a := newTestApp(t, nil)
	f := recordingFetcher{got: make(chan prewarming.PackageInfo, 4)}
	a.prewarmWorker = prewarming.NewWorker(prewarming.Config{Enabled: true, Fetcher: f, Popularity: fixedPopularity{}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.startWorkers(ctx)
	defer a.prewarmWorker.Stop()

	select {
	case pkg := <-f.got:
		if pkg.Name != "lodash" {
			t.Fatalf("pre-warmed %q, want lodash", pkg.Name)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pre-warm worker never ran after startWorkers")
	}
}

func TestPrewarmingStaysOffByDefault(t *testing.T) {
	if config.Default().Prewarming.Enabled {
		t.Fatal("prewarming.enabled must default to false")
	}
}
