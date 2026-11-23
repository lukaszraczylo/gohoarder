package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/stretchr/testify/require"
)

// A vulnerability covered by an active bypass must not block under any block_on_severity.
func TestCheckVulnerabilities_BypassedCVENeverBlocks(t *testing.T) {
	policies := []string{"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "none", ""}
	severities := []string{"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "UNKNOWN"}

	for _, policy := range policies {
		for _, severity := range severities {
			t.Run(policy+"/"+severity, func(t *testing.T) {
				store := &stubBypassStore{
					stubMetadataStore: &stubMetadataStore{},
					bypasses: []*metadata.CVEBypass{
						{ID: "b1", Type: metadata.BypassTypeCVE, Target: "CVE-1", Active: true, ExpiresAt: time.Now().Add(time.Hour)},
					},
					scan: &metadata.ScanResult{
						ID: "r", Scanner: "stub", ScannedAt: time.Now(), Status: metadata.ScanStatusVulnerable,
						Vulnerabilities: []metadata.Vulnerability{{ID: "CVE-1", Severity: severity}},
					},
				}
				mgr, err := New(config.SecurityConfig{
					Enabled:         true,
					BlockOnSeverity: policy,
					BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1},
				}, store)
				require.NoError(t, err)

				blocked, reason, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
				require.NoError(t, err)
				require.False(t, blocked, "bypassed CVE blocked: %s", reason)
			})
		}
	}
}

// An unbypassed vulnerability at or above the policy severity still blocks.
func TestCheckVulnerabilities_UnbypassedCVEBlocksAtPolicy(t *testing.T) {
	store := &stubBypassStore{
		stubMetadataStore: &stubMetadataStore{},
		bypasses: []*metadata.CVEBypass{
			{ID: "b1", Type: metadata.BypassTypeCVE, Target: "CVE-1", Active: true, ExpiresAt: time.Now().Add(time.Hour)},
		},
		scan: &metadata.ScanResult{
			ID: "r", Scanner: "stub", ScannedAt: time.Now(), Status: metadata.ScanStatusVulnerable,
			Vulnerabilities: []metadata.Vulnerability{
				{ID: "CVE-1", Severity: "LOW"},
				{ID: "CVE-2", Severity: "LOW"},
			},
		},
	}
	mgr, err := New(config.SecurityConfig{
		Enabled:         true,
		BlockOnSeverity: "LOW",
		BlockThresholds: config.VulnerabilityThresholds{Critical: -1, High: -1, Medium: -1, Low: -1},
	}, store)
	require.NoError(t, err)

	blocked, _, err := mgr.CheckVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	require.NoError(t, err)
	require.True(t, blocked)
}
