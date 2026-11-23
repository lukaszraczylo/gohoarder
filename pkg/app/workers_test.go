package app

import (
	"context"
	"testing"
	"time"
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
