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

	const events = 1000
	for i := 0; i < events; i++ {
		a.wsServer.BroadcastEvent("cache_hit", map[string]interface{}{"i": i})
		if i%200 == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}

	if dropped := a.wsServer.Dropped(); dropped != 0 {
		t.Fatalf("dropped %d of %d events; the broadcast loop is not draining the channel", dropped, events)
	}
}
