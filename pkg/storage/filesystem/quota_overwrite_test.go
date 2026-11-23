package filesystem

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Used bytes must equal the bytes on disk after a key is overwritten.
func TestPutOverwriteKeepsUsageExact(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir(), 1000)
	require.NoError(t, err)

	require.NoError(t, fs.Put(ctx, "npm/a/metadata", strings.NewReader(strings.Repeat("x", 400)), nil))
	require.NoError(t, fs.Put(ctx, "npm/a/metadata", strings.NewReader(strings.Repeat("y", 300)), nil))

	quota, err := fs.GetQuota(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 300, quota.Used)

	require.NoError(t, fs.Delete(ctx, "npm/a/metadata"))
	quota, err = fs.GetQuota(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 0, quota.Used)
}

// An overwrite that fits once the old bytes are released must not hit the quota.
func TestPutOverwriteWithinQuota(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir(), 500)
	require.NoError(t, err)

	require.NoError(t, fs.Put(ctx, "npm/a/metadata", strings.NewReader(strings.Repeat("x", 400)), nil))
	require.NoError(t, fs.Put(ctx, "npm/a/metadata", strings.NewReader(strings.Repeat("y", 450)), nil))
}
