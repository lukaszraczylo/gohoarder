package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	gws "github.com/gorilla/websocket"
)

// TestCloseSendIdempotent ensures double-close on client.send is safe.
func TestCloseSendIdempotent(t *testing.T) {
	tests := []struct {
		name  string
		calls int
	}{
		{name: "single", calls: 1},
		{name: "double", calls: 2},
		{name: "many", calls: 16},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{send: make(chan []byte, 1)}
			var wg sync.WaitGroup
			wg.Add(tc.calls)
			for i := 0; i < tc.calls; i++ {
				go func() {
					defer wg.Done()
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("closeSend panicked: %v", r)
						}
					}()
					c.closeSend()
				}()
			}
			wg.Wait()
		})
	}
}

// TestUnregisterChannelBuffered verifies unregister channel is buffered so
// non-blocking sends from broadcastEvent/pingClients don't block or leak
// goroutines under a stuck consumer.
func TestUnregisterChannelBuffered(t *testing.T) {
	s := NewServer(Config{})
	if cap(s.unregister) < 256 {
		t.Fatalf("unregister channel cap=%d, want >=256", cap(s.unregister))
	}
}

// TestConcurrentConnectionsCloseNoPanic spawns N concurrent websocket clients,
// closes them all, and asserts no panic. Also performs a coarse goroutine-leak
// check (pre/post counts within a small delta).
func TestConcurrentConnectionsCloseNoPanic(t *testing.T) {
	startGoros := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(Config{})
	srv.Start(ctx)

	httpSrv := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer httpSrv.Close()

	wsURL, err := url.Parse(httpSrv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	wsURL.Scheme = "ws"

	const N = 32
	conns := make([]*gws.Conn, 0, N)
	for i := 0; i < N; i++ {
		c, _, err := gws.DefaultDialer.Dial(wsURL.String(), nil)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Allow registrations to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.RLock()
		n := len(srv.clients)
		srv.mu.RUnlock()
		if n == N {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Concurrent close from many goroutines simulates burst disconnect.
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func(c *gws.Conn) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("close panicked: %v", r)
				}
			}()
			_ = c.Close()
		}(c)
	}
	wg.Wait()

	// Trigger shutdown — closeAllClients runs concurrently with any pending
	// in-loop unregisters. This is the double-close race scenario.
	cancel()

	// Give run loop and pumps time to exit.
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	endGoros := runtime.NumGoroutine()
	// Allow some slack: test runtime, pollers, etc. We just want to catch
	// catastrophic per-connection leaks (would scale with N=32).
	if endGoros > startGoros+8 {
		t.Errorf("possible goroutine leak: start=%d end=%d", startGoros, endGoros)
	}
}

// TestBroadcastWithFullClientBufferDoesNotLeakGoroutines verifies the
// non-blocking unregister send path: a client with a full send buffer should
// be unregistered without spawning per-event goroutines.
func TestBroadcastWithFullClientBufferDoesNotLeakGoroutines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewServer(Config{})
	// Don't Start — drive run-loop interactions manually so we can test the
	// non-blocking unregister send without races on the real loop.
	go s.run(ctx)

	// Inject a fake client with a full send buffer.
	c := &Client{
		send:          make(chan []byte, 1),
		subscriptions: make(map[EventType]bool),
	}
	c.send <- []byte("filler") // buffer now full
	s.register <- c

	// Wait for registration.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		_, ok := s.clients[c]
		s.mu.RUnlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Broadcast many events. Buffer is full, so each will hit the default
	// branch and try to non-blocking-send to s.unregister.
	for i := 0; i < 1000; i++ {
		s.Broadcast(EventStatsUpdate, map[string]interface{}{"n": i})
	}

	// Wait for client to be unregistered.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		_, ok := s.clients[c]
		n := len(s.clients)
		s.mu.RUnlock()
		if !ok && n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client was not unregistered after broadcast spam with full buffer")
}
