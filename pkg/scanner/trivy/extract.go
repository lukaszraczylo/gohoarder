package trivy

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// maxExtractBytes caps the unpacked size so a compressed bomb cannot fill the disk.
const maxExtractBytes int64 = 512 << 20

var errTooLarge = errors.New("archive exceeds the extraction size limit")

// unpackNPM extracts an npm tarball into root/node_modules/<name>, the layout trivy's node-pkg
// analyzer reads. It returns root, which the caller must remove.
func unpackNPM(archive, name string) (root string, err error) {
	if !validPackageName(name) {
		return "", fmt.Errorf("unsafe package name %q", name)
	}
	root, err = os.MkdirTemp("", "trivy-npm-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(root)
			root = ""
		}
	}()
	dest := filepath.Join(root, "node_modules", filepath.FromSlash(name))
	if err = os.MkdirAll(dest, 0o750); err != nil {
		return root, err
	}
	err = extractTarball(archive, dest)
	return root, err
}

func validPackageName(name string) bool {
	if name == "" || strings.Contains(name, "\\") || !filepath.IsLocal(name) {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return false
		}
	}
	return true
}

// extractTarball unpacks a .tgz into dest, dropping the top-level directory. Links are never
// created; escaping ones are rejected outright.
func extractTarball(archive, dest string) error {
	f, err := os.Open(archive) // #nosec G304 -- path from the cache, not user input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		rel, err := entryPath(hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if rel == "" {
				continue
			}
			if err := os.MkdirAll(filepath.Join(dest, rel), 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if rel == "" {
				continue
			}
			n, err := writeEntry(filepath.Join(dest, rel), tr, maxExtractBytes-total)
			if err != nil {
				return err
			}
			total += n
		case tar.TypeSymlink, tar.TypeLink:
			if err := checkLink(hdr); err != nil {
				return err
			}
		}
	}
}

// entryPath validates a tar entry name and strips its first segment.
func entryPath(name string) (string, error) {
	clean := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("absolute path in archive: %q", name)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal in archive: %q", name)
		}
	}
	segs := strings.Split(path.Clean(clean), "/")
	if len(segs) < 2 {
		return "", nil
	}
	rel := filepath.FromSlash(strings.Join(segs[1:], "/"))
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("unsafe path in archive: %q", name)
	}
	return rel, nil
}

func checkLink(hdr *tar.Header) error {
	target := strings.ReplaceAll(hdr.Linkname, "\\", "/")
	if strings.HasPrefix(target, "/") {
		return fmt.Errorf("absolute link target in archive: %q -> %q", hdr.Name, hdr.Linkname)
	}
	base := path.Dir(hdr.Name)
	if hdr.Typeflag == tar.TypeLink {
		base = "."
	}
	joined := path.Join(base, target)
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return fmt.Errorf("link escapes the archive: %q -> %q", hdr.Name, hdr.Linkname)
	}
	return nil
}

// writeEntry copies at most limit bytes and fails when the entry is larger.
func writeEntry(dst string, r io.Reader, limit int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- dst validated by entryPath
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(r, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = errTooLarge
	}
	return n, err
}
