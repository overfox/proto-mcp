package serve

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The idle-lock message is logged once per idle episode, not on every
// 30s tick (13k repeated lines in the live daemon.log), and re-arms
// after activity.
func TestIdleTrackerLogsOncePerEpisode(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	tr := newIdleTracker()
	tr.lastActivity.Store(time.Now().Add(-time.Hour).UnixNano())

	calls := 0
	lock := func(string) { calls++ }
	for i := 0; i < 5; i++ {
		tr.check(func() int { return 5 }, nil, lock, logger)
	}
	if calls != 5 {
		t.Fatalf("lockFn calls = %d, want 5 (locking still attempted each tick)", calls)
	}
	if n := strings.Count(buf.String(), "idle threshold exceeded"); n != 1 {
		t.Fatalf("logged %d times, want 1:\n%s", n, buf.String())
	}

	tr.bumpActivity()
	tr.lastActivity.Store(time.Now().Add(-time.Hour).UnixNano())
	tr.check(func() int { return 5 }, nil, lock, logger)
	if n := strings.Count(buf.String(), "idle threshold exceeded"); n != 2 {
		t.Fatalf("after activity: logged %d times, want 2", n)
	}
}

// Lockwatch-missing warning lands in state.json's reason (locked /
// unlocked only) and its own field.
func TestStatePublisher_WarningInReason(t *testing.T) {
	p := NewStatePublisher(t.TempDir()+"/state.json", discardLogger())
	p.SetState(StateUnlocked, "", "a@b.c")
	p.SetWarning(LockwatchMissingWarning)
	doc := readState(t, p.path)
	reason, _ := doc["reason"].(string)
	if doc["warning"] != LockwatchMissingWarning || !strings.Contains(reason, "lockwatch helper missing") {
		t.Fatalf("unlocked: reason=%q warning=%v", reason, doc["warning"])
	}
	p.SetState(StateConnecting, "waiting for network", "")
	doc = readState(t, p.path)
	if reason, _ := doc["reason"].(string); strings.Contains(reason, "lockwatch") {
		t.Fatalf("connecting reason must not carry the warning (menu bar parses it): %q", reason)
	}
}
