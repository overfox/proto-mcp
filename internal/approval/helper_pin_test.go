package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withExecutable(t *testing.T, p string) {
	t.Helper()
	prev := executablePath
	executablePath = func() (string, error) { return p, nil }
	t.Cleanup(func() { executablePath = prev })
}

func writeScript(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func sameFile(a, b string) bool {
	ra, _ := filepath.EvalSymlinks(a)
	rb, _ := filepath.EvalSymlinks(b)
	return ra != "" && ra == rb
}

// SECURITY M4 — the helper is resolved relative to os.Executable(), not
// argv[0]. A caller that launches us with an argv[0] sitting next to an
// attacker-controlled "helper" must not get that helper picked.
func TestResolveHelperPath_IgnoresArgv0(t *testing.T) {
	t.Setenv("PROTONMCP_TOUCHID", "")

	real := t.TempDir()
	writeScript(t, filepath.Join(real, "protonmcpd"), "")
	good := filepath.Join(real, "protonmcp-touchid")
	writeScript(t, good, "exit 1")

	evil := t.TempDir()
	writeScript(t, filepath.Join(evil, "protonmcp-touchid"), "exit 0")

	withExecutable(t, filepath.Join(real, "protonmcpd"))
	got, err := ResolveHelperPath(filepath.Join(evil, "protonmcpd"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !sameFile(got, good) {
		t.Fatalf("resolved %q, want the helper beside os.Executable (%q)", got, good)
	}
}

// A symlink to the daemon placed in an attacker directory (next to an
// attacker helper) resolves to the real binary's directory; the
// symlink's own directory is not a candidate.
func TestResolveHelperPath_SymlinkDirNotACandidate(t *testing.T) {
	t.Setenv("PROTONMCP_TOUCHID", "")
	real := t.TempDir()
	daemon := filepath.Join(real, "protonmcpd")
	writeScript(t, daemon, "")
	good := filepath.Join(real, "protonmcp-touchid")
	writeScript(t, good, "exit 1")

	evil := t.TempDir()
	writeScript(t, filepath.Join(evil, "protonmcp-touchid"), "exit 0")
	link := filepath.Join(evil, "protonmcpd")
	if err := os.Symlink(daemon, link); err != nil {
		t.Fatal(err)
	}
	withExecutable(t, link)
	got, err := resolveHelperPath("")
	if err != nil {
		t.Fatal(err)
	}
	if !sameFile(got, good) {
		t.Fatalf("resolved %q, want %q (the symlink's directory must not be searched)", got, good)
	}
}

// SECURITY M4 — PromptDirect (startup gate / CLI gate / policy
// weakening) verifies the pinned hash before exec: a helper that would
// approve but doesn't match the pin is refused without running.
func TestPromptDirect_RefusesWrongHash(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	helper := filepath.Join(dir, "helper")
	writeScript(t, helper, "cat >/dev/null\ntouch "+marker+"\nexit 0")

	restore := SetTouchIDHashForTesting(strings.Repeat("ab", 32))
	err := PromptDirect(context.Background(), helper, DirectPrompt{Title: "t", Body: "b"}, nil)
	restore()
	if !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("err = %v, want ErrHelperUntrusted", err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("helper was executed despite the hash mismatch")
	}

	// Matching pin → runs and approves.
	data, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	restore = SetTouchIDHashForTesting(hex.EncodeToString(sum[:]))
	defer restore()
	if err := PromptDirect(context.Background(), helper, DirectPrompt{Title: "t", Body: "b"}, nil); err != nil {
		t.Fatalf("pinned helper: err = %v", err)
	}
	if _, serr := os.Stat(marker); serr != nil {
		t.Fatal("pinned helper did not run")
	}
}

func TestPromptDirect_Declined(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "helper")
	writeScript(t, helper, "cat >/dev/null\nexit 1")
	if err := PromptDirect(context.Background(), helper, DirectPrompt{}, nil); !errors.Is(err, ErrPromptDeclined) {
		t.Fatalf("err = %v, want ErrPromptDeclined", err)
	}
}
