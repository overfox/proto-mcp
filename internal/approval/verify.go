package approval

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Helper pinning.
//
// The Touch ID helper is the verdict oracle for every gated tool call:
// exit 0 means "approved". resolveHelperPath already refuses helpers
// that group/other can write (PROTO-127), but anything running as the
// user could still replace the helper with `#!/bin/sh\nexit 0` and
// auto-approve every gate. To close that, the build embeds the
// expected SHA-256 of each helper via
//
//	go build -ldflags "-X github.com/just-an-oldsalt/proto-mcp/internal/approval.touchIDHelperSHA256=<hex> \
//	                   -X github.com/just-an-oldsalt/proto-mcp/internal/approval.lockwatchHelperSHA256=<hex>"
//
// (the Makefile computes these with `shasum -a 256` after building the
// Swift helpers) and the broker re-hashes the helper before EVERY exec.
// Mismatch fails closed.
//
// A binary built without the ldflags (plain `go build`, `go test`)
// has empty hashes: it falls back to the owner/permission checks only
// and logs a loud warning on each exec.
//
// Residual risk: verify-then-exec by path leaves a small TOCTOU window,
// and a same-uid attacker can also replace the daemon binary itself.
// Pinning raises the bar from "drop a shell script" to "rebuild and
// replace the signed daemon"; Developer ID signing + a code-signing
// requirement check is the stronger long-term control.
var (
	touchIDHelperSHA256   string
	lockwatchHelperSHA256 string
)

// ErrHelperUntrusted is returned when a helper fails verification.
var ErrHelperUntrusted = errors.New("approval helper failed integrity verification")

// verifyHelper checks the file at path:
//
//  1. resolves symlinks (the cask layout symlinks into the Caskroom),
//  2. is a regular file owned by the current uid (or root, which the
//     user can't write either),
//  3. if expectedHex is non-empty, its SHA-256 matches.
//
// The hash is computed over the same open file descriptor whose owner
// was checked, so the checks agree with each other.
func verifyHelper(path, expectedHex string, logger *slog.Logger, uid int) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%w: resolve %s: %v", ErrHelperUntrusted, path, err)
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%w: open %s: %v", ErrHelperUntrusted, resolved, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat %s: %v", ErrHelperUntrusted, resolved, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrHelperUntrusted, resolved)
	}
	if !ownerOK(st, uid) {
		return fmt.Errorf("%w: %s is not owned by the current user (uid %d) or root",
			ErrHelperUntrusted, resolved, uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is group/world-writable", ErrHelperUntrusted, resolved)
	}

	expectedHex = strings.ToLower(strings.TrimSpace(expectedHex))
	if expectedHex == "" {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("SECURITY: approval helper hash NOT pinned — this binary was built "+
			"without -ldflags helper hashes (use `make`), so a swapped helper would not be "+
			"detected", "helper", resolved)
		return nil
	}
	want, err := hex.DecodeString(expectedHex)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("%w: embedded hash for %s is malformed", ErrHelperUntrusted, resolved)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("%w: hash %s: %v", ErrHelperUntrusted, resolved, err)
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return fmt.Errorf("%w: %s SHA-256 %x does not match the hash embedded at build time (%s); "+
			"refusing to exec it. Rebuild with `make` if you rebuilt the helper, otherwise "+
			"treat this as tampering", ErrHelperUntrusted, resolved, h.Sum(nil), expectedHex)
	}
	return nil
}

// ownerOK reports whether the file is owned by uid or by root.
func ownerOK(st os.FileInfo, uid int) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(sys.Uid) == uid || sys.Uid == 0
}

// VerifyLockwatchHelper verifies the screen-lock watcher helper against
// the hash embedded at build time (see verifyHelper). Called by
// internal/serve before every lockwatch exec. A swapped lockwatch can't
// approve anything, but it can silently disable auto-lock.
func VerifyLockwatchHelper(path string) error {
	return verifyHelper(path, lockwatchHelperSHA256, nil, os.Getuid())
}

// SetLockwatchHashForTesting pins the lockwatch hash from another
// package's tests and returns a restore func. It refuses to do anything
// outside `go test`, so a production binary can't be re-pinned at runtime.
func SetLockwatchHashForTesting(hash string) (restore func()) {
	if !testing.Testing() {
		return func() {}
	}
	prev := lockwatchHelperSHA256
	lockwatchHelperSHA256 = hash
	return func() { lockwatchHelperSHA256 = prev }
}
