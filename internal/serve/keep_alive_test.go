package serve

import (
	"io"
	"log/slog"
	"testing"
)

func TestKeepAliveGuard(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	keepAlive := true
	var locked []string
	guard := keepAliveGuard(func() bool { return keepAlive }, func(r string) { locked = append(locked, r) }, logger)

	for _, reason := range []string{"screen_locked", "sleep", "idle"} {
		guard(reason)
	}
	if len(locked) != 0 {
		t.Fatalf("keep alive on: auto-lock fired for %v, want none", locked)
	}

	// Toggling off takes effect on the very next trigger.
	keepAlive = false
	guard("screen_locked")
	if len(locked) != 1 || locked[0] != "screen_locked" {
		t.Fatalf("keep alive off: locked = %v, want [screen_locked]", locked)
	}
}
