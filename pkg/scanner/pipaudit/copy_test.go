package pipaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCopyInto(t *testing.T) {
	s := &Scanner{}
	src := filepath.Join(t.TempDir(), "pkg.whl")
	require.NoError(t, os.WriteFile(src, []byte("wheel"), 0600))

	t.Run("copies inside dir", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, s.copyInto(src, dir, "pkg.whl"))
		got, err := os.ReadFile(filepath.Join(dir, "pkg.whl"))
		require.NoError(t, err)
		require.Equal(t, "wheel", string(got))
	})

	t.Run("refuses name escaping dir", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "sub")
		require.NoError(t, os.Mkdir(dir, 0750))
		require.Error(t, s.copyInto(src, dir, "../escape.whl"))
		require.NoFileExists(t, filepath.Join(parent, "escape.whl"))
	})

	t.Run("missing source", func(t *testing.T) {
		require.Error(t, s.copyInto(filepath.Join(t.TempDir(), "none"), t.TempDir(), "x"))
	})
}
