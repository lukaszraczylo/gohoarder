package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// blockingScanner holds the scan open until its context ends.
type blockingScanner struct {
	started chan struct{}
	done    chan error
}

func (s *blockingScanner) Enabled() bool { return true }
func (s *blockingScanner) ScanPackage(ctx context.Context, _, _, _, _ string) error {
	close(s.started)
	<-ctx.Done()
	s.done <- ctx.Err()
	return ctx.Err()
}
func (s *blockingScanner) CheckVulnerabilities(context.Context, string, string, string) (bool, string, error) {
	return false, "", nil
}

// Close must cancel an in-flight background scan instead of leaking it.
func TestClose_CancelsBackgroundScan(t *testing.T) {
	sc := &blockingScanner{started: make(chan struct{}), done: make(chan error, 1)}
	manager := newMissManager(t, sc, Config{ScanWaitTimeout: 50 * time.Millisecond})

	_, err := manager.Get(context.Background(), "npm", "lodash", "4.17.21", fetchLodash)
	require.NoError(t, err)
	select {
	case <-sc.started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}

	require.NoError(t, manager.Close())
	select {
	case err := <-sc.done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("background scan still running after Close")
	}
}
