package serve

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readState(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode state %q: %v", b, err)
	}
	return m
}

func TestStatePublisher_SchemaAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	p := NewStatePublisher(path, discardLogger())
	p.SetKeepAlive(func() bool { return true })

	p.ToolCalled("mail_list") // before any state: nothing on disk
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file written before first SetState (err=%v)", err)
	}

	p.SetState(StateUnlocked, "", "a@example.com")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
	m := readState(t, path)
	want := []string{"state", "reason", "email", "pid", "keep_alive", "remote", "last_tool", "last_tool_at", "updated_at"}
	if len(m) != len(want) {
		t.Errorf("keys = %v, want exactly %v", m, want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if m["state"] != "unlocked" || m["email"] != "a@example.com" || m["keep_alive"] != true {
		t.Errorf("unexpected doc: %v", m)
	}
	if pid, ok := m["pid"].(float64); !ok || int(pid) != os.Getpid() {
		t.Errorf("pid = %v, want %d as a number", m["pid"], os.Getpid())
	}
	if m["last_tool"] != "mail_list" {
		t.Errorf("last_tool = %v", m["last_tool"])
	}
	if _, err := time.Parse(time.RFC3339, m["last_tool_at"].(string)); err != nil {
		t.Errorf("last_tool_at not RFC3339: %v", m["last_tool_at"])
	}
	if _, err := time.Parse(time.RFC3339, m["updated_at"].(string)); err != nil {
		t.Errorf("updated_at not RFC3339: %v", m["updated_at"])
	}

	// Locking keeps the last known email.
	p.SetState(StateLocked, LockReasonTouchIDRequired, "")
	m = readState(t, path)
	if m["state"] != "locked" || m["reason"] != LockReasonTouchIDRequired || m["email"] != "a@example.com" {
		t.Errorf("locked doc: %v", m)
	}

	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want just state.json", len(entries))
	}

	p.Remove()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state file survived Remove")
	}
	p.SetState(StateUnlocked, "", "") // after Remove: no-op
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("write after Remove resurrected the file")
	}
}

// Tool calls reach the disk via the Run goroutine (never on the call
// path itself).
func TestStatePublisher_RunFlushesToolCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	p := NewStatePublisher(path, discardLogger())
	p.SetState(StateLocked, "x", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	p.ToolCalled("proton_connect")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			var m map[string]any
			if json.Unmarshal(b, &m) == nil && m["last_tool"] == "proton_connect" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("tool call never flushed to the state file")
}

func TestStatePublisher_NilSafe(t *testing.T) {
	var p *StatePublisher
	p.SetState(StateLocked, "", "")
	p.ToolCalled("x")
	p.SetKeepAlive(nil)
	p.Remove()
	p.Run(context.Background())
}

// Runtime transitions publish: Lock → locked/reason, Unlock → unlocked.
func TestRuntimePublishesTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	pub := NewStatePublisher(path, discardLogger())
	rt := &Runtime{locked: true, lockReason: LockReasonTouchIDRequired, state: pub}
	rt.acquireSession = func(context.Context) (SessionBundle, error) {
		return fakeBundle{sess: newTestSession("z@example.com")}, nil
	}
	rt.publishState()
	if m := readState(t, path); m["state"] != "locked" || m["reason"] != LockReasonTouchIDRequired {
		t.Fatalf("initial: %v", m)
	}
	if err := rt.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := readState(t, path); m["state"] != "unlocked" || m["email"] != "z@example.com" {
		t.Fatalf("after unlock: %v", m)
	}
	rt.Lock("SIGUSR1")
	if m := readState(t, path); m["state"] != "locked" || m["reason"] != "SIGUSR1" {
		t.Fatalf("after lock: %v", m)
	}
}
