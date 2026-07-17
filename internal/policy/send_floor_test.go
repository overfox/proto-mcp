package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// writeOverride drops a policy.yaml into a temp dir and returns its path.
func writeOverride(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The floor: no override may set a send-family tool to allow. The
// override is rejected wholesale and the embedded defaults stay in
// force, so mail_send still prompts.
func TestSendFloorRejectsAllow(t *testing.T) {
	path := writeOverride(t, `
tools:
  mail_send:
    decision: allow
`)
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, _ := e.Decide("mail_send", nil, caller.Caller{})
	if d != DecisionPrompt {
		t.Errorf("mail_send after allow-override: decision = %s, want prompt (floor)", d)
	}
}

// A nonzero approval-cache TTL on a send tool is a floor violation:
// every send must re-prompt.
func TestSendFloorRejectsNonzeroTTL(t *testing.T) {
	path := writeOverride(t, `
tools:
  mail_reply:
    decision: prompt
    confirm: true
    ttl: 5m
`)
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, p := e.Decide("mail_reply", nil, caller.Caller{})
	if p.TTLDuration() != 0 {
		t.Errorf("mail_reply after ttl-override: ttl = %v, want 0 (floor)", p.TTLDuration())
	}
}

// Stricter than the floor is fine: deny is accepted.
func TestSendFloorAcceptsDeny(t *testing.T) {
	path := writeOverride(t, `
tools:
  mail_forward:
    decision: deny
`)
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d, _ := e.Decide("mail_forward", nil, caller.Caller{})
	if d != DecisionDeny {
		t.Errorf("mail_forward deny-override: decision = %s, want deny", d)
	}
}

// Reload with a floor-violating override must keep the previous
// policy in place and return an error naming the floor.
func TestSendFloorReloadKeepsPrevious(t *testing.T) {
	path := writeOverride(t, `
tools:
  mail_trash:
    decision: allow
`)
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Sanity: non-send override applied.
	if d, _ := e.Decide("mail_trash", nil, caller.Caller{}); d != DecisionAllow {
		t.Fatalf("precondition: mail_trash = %s, want allow", d)
	}
	if err := os.WriteFile(path, []byte(`
tools:
  mail_send_draft:
    decision: allow
`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = e.Reload()
	if err == nil || !strings.Contains(err.Error(), "policy floor") {
		t.Fatalf("Reload: err = %v, want policy-floor rejection", err)
	}
	if d, _ := e.Decide("mail_send_draft", nil, caller.Caller{}); d != DecisionPrompt {
		t.Errorf("mail_send_draft after rejected reload: decision = %s, want prompt", d)
	}
	if d, _ := e.Decide("mail_trash", nil, caller.Caller{}); d != DecisionAllow {
		t.Errorf("mail_trash after rejected reload: decision = %s, want allow (previous policy retained)", d)
	}
}

// idle_lock_minutes in the override must actually take effect — it
// was documented but never merged (silently ignored).
func TestIdleLockMinutesMergesFromOverride(t *testing.T) {
	path := writeOverride(t, "idle_lock_minutes: 15\n")
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := e.IdleLockMinutes(); got != 15 {
		t.Errorf("IdleLockMinutes = %d, want 15", got)
	}
}
