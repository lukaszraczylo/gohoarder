package scanner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
)

type healthProbe struct {
	err   error
	calls atomic.Int32
}

func (s *healthProbe) Name() string { return "counting" }

func (s *healthProbe) Scan(context.Context, string, string, string, string) (*metadata.ScanResult, error) {
	return nil, nil
}

func (s *healthProbe) Health(context.Context) error {
	s.calls.Add(1)
	return s.err
}

// Health runs each scanner's version command; under scan load that took over a second, so
// repeated probes must reuse a recent result.
func TestHealthReusesRecentResult(t *testing.T) {
	tests := []struct {
		err  error
		name string
	}{
		{name: "healthy", err: nil},
		{name: "unhealthy", err: errors.New("grype missing")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &healthProbe{err: tt.err}
			m := &Manager{enabled: true, scanners: []Scanner{s}}
			for range 3 {
				if err := m.Health(context.Background()); (err != nil) != (tt.err != nil) {
					t.Fatalf("Health() error = %v, want error %v", err, tt.err != nil)
				}
			}
			if got := s.calls.Load(); got != 1 {
				t.Fatalf("scanner health ran %d times, want 1", got)
			}
		})
	}
}

// A probe whose context was cancelled must not pin its failure for the cache period.
func TestHealthDoesNotCacheCancelledProbe(t *testing.T) {
	s := &healthProbe{err: context.Canceled}
	m := &Manager{enabled: true, scanners: []Scanner{s}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = m.Health(ctx)
	s.err = nil
	if err := m.Health(context.Background()); err != nil {
		t.Fatalf("Health() after cancelled probe = %v, want nil", err)
	}
	if got := s.calls.Load(); got != 2 {
		t.Fatalf("scanner health ran %d times, want 2", got)
	}
}
