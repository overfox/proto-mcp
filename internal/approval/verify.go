package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// VerifyTouchIDHelper verifies the Touch ID helper at path against the
// hash embedded at build time (see verifyHelper). Every direct helper
// exec outside the broker — the daemon's startup gate, the CLI's
// Keychain gate, the policy-weakening prompt — goes through
// PromptDirect, which calls this first. Same unpinned-dev handling as
// the broker: an empty embedded hash logs a loud warning and falls back
// to the owner/permission checks.
func VerifyTouchIDHelper(path string, logger *slog.Logger) error {
	return verifyHelper(path, touchIDHelperSHA256, logger, os.Getuid())
}

// SetTouchIDHashForTesting pins the Touch ID helper hash from another
// package's tests and returns a restore func. No-op outside `go test`.
func SetTouchIDHashForTesting(hash string) (restore func()) {
	if !testing.Testing() {
		return func() {}
	}
	prev := touchIDHelperSHA256
	touchIDHelperSHA256 = hash
	return func() { touchIDHelperSHA256 = prev }
}

// ErrPromptDeclined is returned by PromptDirect when the user cancels
// the dialog or the biometric fails (helper exit 1).
var ErrPromptDeclined = errors.New("user canceled approval")

// DirectPrompt is one Touch ID dialog run by PromptDirect.
type DirectPrompt struct {
	Title   string
	Body    string
	Caller  string        // shown by the helper as the requester
	Timeout time.Duration // 0 → 60s
}

// PromptDirect runs the Touch ID helper once, outside the broker: no
// policy, no approval cache, never routed to Remote mode. Used where a
// broker doesn't exist yet or must not be consulted (the daemon's
// startup gate, CLI Keychain loads, policy-weakening approval).
//
// SECURITY M4: the helper's pinned SHA-256 is verified before EVERY
// exec, exactly like the broker. A mismatch fails closed with
// ErrHelperUntrusted. Returns nil only on helper exit 0.
func PromptDirect(ctx context.Context, helperPath string, p DirectPrompt, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if err := VerifyTouchIDHelper(helperPath, logger); err != nil {
		logger.Error("touch-id helper failed verification; refusing to prompt", "err", err.Error())
		return err
	}
	payload, err := json.Marshal(struct {
		Title   string `json:"title"`
		Body    string `json:"body"`
		Caller  string `json:"caller"`
		Confirm bool   `json:"confirm"`
	}{Title: p.Title, Body: p.Body, Caller: p.Caller})
	if err != nil {
		return fmt.Errorf("approval: marshal prompt: %w", err)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(subCtx, helperPath)
	cmd.Stdin = bytes.NewReader(payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &bytes.Buffer{} // never inherit (serve-stdio would corrupt MCP framing)

	err = cmd.Run()
	if err == nil {
		return nil
	}
	// Context first: CommandContext kills the helper on timeout /
	// cancel, which surfaces as an ExitError with code -1.
	if subCtx.Err() != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("approval aborted: %w", ctx.Err())
		}
		return fmt.Errorf("approval timed out after %s", timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case 1:
			return ErrPromptDeclined
		case 2:
			return fmt.Errorf("helper rejected request: %s", stderr.String())
		default:
			return fmt.Errorf("helper exit %d: %s", exitErr.ExitCode(), stderr.String())
		}
	}
	return fmt.Errorf("helper invocation failed: %v", err)
}
