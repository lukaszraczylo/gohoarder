package nfs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lukaszraczylo/gohoarder/pkg/storage"
	"github.com/rs/zerolog"
)

// newTestStorage builds an NFS Storage rooted at t.TempDir(). It also returns
// a buffer capturing the logger output so detection-related tests can assert
// on log lines without requiring a real NFS mount.
func newTestStorage(t *testing.T, syncWrites bool) (*Storage, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	logBuf := &bytes.Buffer{}
	logger := zerolog.New(logBuf)
	s, err := New(Config{
		Path:       dir,
		MaxSize:    1 << 20, // 1 MiB
		SyncWrites: syncWrites,
	}, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, logBuf
}

func TestNew_RejectsMissingPath(t *testing.T) {
	logger := zerolog.New(io.Discard)
	if _, err := New(Config{Path: ""}, logger); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestNew_RejectsNonDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	logger := zerolog.New(io.Discard)
	if _, err := New(Config{Path: file}, logger); err == nil {
		t.Fatal("expected error when path is a file")
	}
}

func TestNew_RejectsNonexistentPath(t *testing.T) {
	logger := zerolog.New(io.Discard)
	if _, err := New(Config{Path: "/nonexistent/path/does/not/exist"}, logger); err == nil {
		t.Fatal("expected error for missing path")
	}
}

// TestNew_LogsWarnOnNonNFSMount: on Linux the temp dir lives on a non-NFS fs,
// so detection should fire and log a warn. On other OSes detection is skipped
// and we just assert New succeeds.
func TestNew_LogsWarnOnNonNFSMount(t *testing.T) {
	s, logBuf := newTestStorage(t, true)
	if s == nil {
		t.Fatal("expected storage")
	}

	if runtime.GOOS != "linux" {
		t.Skipf("mount detection only runs on linux; got %s", runtime.GOOS)
	}

	out := logBuf.String()
	// Either a warn ("not on an NFS mount") or, if /proc/mounts is unreadable
	// inside the sandbox, a debug "detection skipped". Both are acceptable;
	// what we never want is a hard error.
	if !strings.Contains(out, "not on an NFS mount") &&
		!strings.Contains(out, "detection skipped") &&
		!strings.Contains(out, "detected NFS mount") {
		t.Fatalf("expected mount-detection log line, got: %q", out)
	}
}

func TestRoundTrip_PutGetStatDelete(t *testing.T) {
	s, _ := newTestStorage(t, true)
	ctx := context.Background()

	const key = "pkgs/example/1.0.0/data.bin"
	payload := []byte("hello-nfs-roundtrip")

	if err := s.Put(ctx, key, bytes.NewReader(payload), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	exists, err := s.Exists(ctx, key)
	if err != nil || !exists {
		t.Fatalf("Exists: got (%v, %v), want (true, nil)", exists, err)
	}

	rc, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}

	info, err := s.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size != int64(len(payload)) {
		t.Fatalf("Stat size: got %d want %d", info.Size, len(payload))
	}

	if delErr := s.Delete(ctx, key); delErr != nil {
		t.Fatalf("Delete: %v", delErr)
	}
	exists, err = s.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists after delete: %v", err)
	}
	if exists {
		t.Fatal("expected key to be gone after delete")
	}
}

func TestPut_NoSyncPath(t *testing.T) {
	// Same flow as round-trip, but with SyncWrites=false to exercise the
	// non-fsync branch.
	s, _ := newTestStorage(t, false)
	ctx := context.Background()
	if err := s.Put(ctx, "no-sync.txt", strings.NewReader("data"), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func TestList(t *testing.T) {
	s, _ := newTestStorage(t, true)
	ctx := context.Background()
	keys := []string{"a/one.txt", "a/two.txt", "b/three.txt"}
	for _, k := range keys {
		if err := s.Put(ctx, k, strings.NewReader(k), nil); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}

	objs, err := s.List(ctx, "a", &storage.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("List(a): got %d objs want 2 (%v)", len(objs), objsKeys(objs))
	}
}

func TestGetQuota(t *testing.T) {
	s, _ := newTestStorage(t, true)
	ctx := context.Background()

	q, err := s.GetQuota(ctx)
	if err != nil {
		t.Fatalf("GetQuota: %v", err)
	}
	if q.Limit != 1<<20 {
		t.Fatalf("Limit: got %d want %d", q.Limit, 1<<20)
	}
}

func TestHealth_OK(t *testing.T) {
	s, _ := newTestStorage(t, true)
	if err := s.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestHealth_LeavesNoProbeFile(t *testing.T) {
	s, _ := newTestStorage(t, true)
	if err := s.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	probe := filepath.Join(s.path, ".nfs_health_probe")
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatalf("expected probe file removed; stat err=%v", err)
	}
}

func TestHealth_FailsWhenPathRemoved(t *testing.T) {
	s, _ := newTestStorage(t, true)
	// Remove the entire base dir under the backend's feet to simulate a
	// missing/stale mount. Health must surface that as an error.
	if err := os.RemoveAll(s.path); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := s.Health(context.Background()); err == nil {
		t.Fatal("expected Health to fail after path removed")
	}
}

func TestGetLocalPath(t *testing.T) {
	s, _ := newTestStorage(t, true)
	ctx := context.Background()
	const key = "local/path/test.txt"
	if err := s.Put(ctx, key, strings.NewReader("data"), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	p, err := s.GetLocalPath(ctx, key)
	if err != nil {
		t.Fatalf("GetLocalPath: %v", err)
	}
	if !strings.HasPrefix(p, s.path) {
		t.Fatalf("expected path under base; got %s (base %s)", p, s.path)
	}
}

func TestStorageBackend_InterfaceConformance(t *testing.T) {
	// Compile-time check the wrapper satisfies the public interface.
	var _ storage.StorageBackend = (*Storage)(nil)
	var _ storage.LocalPathProvider = (*Storage)(nil)
}

// objsKeys is a small helper used in failure messages.
func objsKeys(objs []storage.StorageObject) string {
	keys := make([]string, 0, len(objs))
	for _, o := range objs {
		keys = append(keys, o.Key)
	}
	b, _ := json.Marshal(keys)
	return string(b)
}
