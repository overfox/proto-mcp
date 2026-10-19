package main

import (
	"os"
	"path/filepath"
	"testing"
)

// launchd creates daemon.log 0644 (and the dir may predate the 0700
// MkdirAll); startup tightens both.
func TestTightenLogPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "protonmcp")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(log, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(log, 0o644); err != nil {
		t.Fatal(err)
	}
	tightenLogPerms(dir, log)
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(log); fi.Mode().Perm() != 0o600 {
		t.Errorf("log mode = %v, want 0600", fi.Mode().Perm())
	}
}
