package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Clients gate on a 72h release age; a metadata page that stays fresh longer would hide the gate's inputs.
func TestMetadataEntryDefaultTTLIsBelowReleaseAgeGate(t *testing.T) {
	h := newIdleHarness(t, Config{})
	entry := h.get(t, "left-pad", "metadata")

	require.NotNil(t, entry.Package.ExpiresAt)
	require.Equal(t, 24*time.Hour, entry.Package.ExpiresAt.Sub(h.clock.Now()))
}

func TestMetadataEntryExplicitTTLWins(t *testing.T) {
	h := newIdleHarness(t, Config{DefaultTTL: 6 * time.Hour})
	entry := h.get(t, "left-pad", "metadata")

	require.Equal(t, 6*time.Hour, entry.Package.ExpiresAt.Sub(h.clock.Now()))
}
