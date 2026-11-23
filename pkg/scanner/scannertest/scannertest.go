// Package scannertest supplies fake scanner binaries for tests of the CLI wrappers.
package scannertest

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Fake puts an executable called name first on PATH. It records its arguments, one per line, in
// the returned file, writes stdoutFile to stdout and stderr to stderr, and exits with code.
func Fake(t *testing.T, name, stdoutFile, stderr string, code int) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> '" + argsFile + "'; done\n" +
		"pwd > '" + filepath.Join(dir, "cwd") + "'\n"
	if stdoutFile != "" {
		abs, err := filepath.Abs(stdoutFile)
		if err != nil {
			t.Fatal(err)
		}
		script += "cat '" + abs + "'\n"
	}
	if stderr != "" {
		script += "printf '%s' '" + stderr + "' >&2\n"
	}
	script += "exit " + strconv.Itoa(code) + "\n"
	install(t, dir, name, script)
	return argsFile
}

// Script puts a shell executable called name, with the given body, first on PATH.
func Script(t *testing.T, name, body string) {
	t.Helper()
	install(t, t.TempDir(), name, "#!/bin/sh\n"+body+"\n")
}

func install(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Args returns the arguments the fake was called with.
func Args(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, string(data[start:i]))
			start = i + 1
		}
	}
	return out
}
