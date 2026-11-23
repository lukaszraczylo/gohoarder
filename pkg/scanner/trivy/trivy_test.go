package trivy

import (
	"context"
	"testing"
	"time"

	"github.com/lukaszraczylo/gohoarder/pkg/config"
	"github.com/lukaszraczylo/gohoarder/pkg/metadata"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scanerr"
	"github.com/lukaszraczylo/gohoarder/pkg/scanner/scannertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanTimeoutIsAnInfrastructureErrorResult(t *testing.T) {
	scannertest.Script(t, "trivy", "exec sleep 5")

	res, err := New(config.TrivyConfig{Timeout: 100 * time.Millisecond}).Scan(context.Background(), "npm", "p", "1", "/x")

	require.NoError(t, err)
	assert.Equal(t, metadata.ScanStatusError, res.Status)
	assert.Equal(t, true, res.Details[scanerr.DetailInfrastructure])
}
