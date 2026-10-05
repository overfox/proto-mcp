package serve

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
)

// A lockwatch helper that fails its pinned-hash check must trigger the
// unconditional lock, not just be skipped (which would silently disable
// screen-lock auto-lock).
func TestLockwatchTamperLocks(t *testing.T) {
	restore := approval.SetLockwatchHashForTesting(strings.Repeat("0", 64))
	defer restore()

	helper := filepath.Join(t.TempDir(), "protonmcp-lockwatch")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var autoLocked, tamperLocked []string
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := runLockwatchOnce(context.Background(), helper,
		func(r string) { autoLocked = append(autoLocked, r) },
		func(r string) { tamperLocked = append(tamperLocked, r) },
		logger)
	if err == nil {
		t.Fatal("tampered helper ran; want verification error")
	}
	if len(tamperLocked) != 1 || tamperLocked[0] != "lockwatch_helper_untrusted" {
		t.Fatalf("tamper lock = %v, want [lockwatch_helper_untrusted]", tamperLocked)
	}
	if len(autoLocked) != 0 {
		t.Fatalf("auto-lock path used for tamper: %v", autoLocked)
	}
}
