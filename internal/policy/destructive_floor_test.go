package policy

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// No override may set a destructive tool to allow; the whole override
// is rejected and the embedded defaults stay in force.
func TestDestructiveFloorRejectsAllow(t *testing.T) {
	for _, tool := range destructiveFloorTools {
		t.Run(tool, func(t *testing.T) {
			path := writeOverride(t, "tools:\n  "+tool+":\n    decision: allow\n  mail_list:\n    decision: deny\n")
			e, err := New(context.Background(), path, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if d, _ := e.Decide(tool, nil, caller.Caller{}); d == DecisionAllow {
				t.Errorf("%s after allow-override: decision = allow, want floor to hold", tool)
			}
			// Wholesale rejection: the sibling entry didn't apply either.
			if d, _ := e.Decide("mail_list", nil, caller.Caller{}); d != DecisionAllow {
				t.Errorf("mail_list = %s, want allow (override must be rejected wholesale)", d)
			}
		})
	}
}

// prompt with a nonzero ttl and deny are both fine for destructive tools.
func TestDestructiveFloorAcceptsPromptTTLAndDeny(t *testing.T) {
	path := writeOverride(t, `
tools:
  mail_trash:
    decision: prompt
    ttl: 30m
  mail_move:
    decision: deny
  mail_delete_permanent:
    decision: prompt
`)
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d, p := e.Decide("mail_trash", nil, caller.Caller{}); d != DecisionPrompt || p.TTL != "30m" {
		t.Errorf("mail_trash = %s ttl=%q, want prompt/30m", d, p.TTL)
	}
	if d, _ := e.Decide("mail_move", nil, caller.Caller{}); d != DecisionDeny {
		t.Errorf("mail_move = %s, want deny", d)
	}
	if d, _ := e.Decide("mail_delete_permanent", nil, caller.Caller{}); d != DecisionPrompt {
		t.Errorf("mail_delete_permanent = %s, want prompt (opt-in)", d)
	}
}

// Reload with a destructive-allow override keeps the previous policy.
func TestDestructiveFloorReloadKeepsPrevious(t *testing.T) {
	path := writeOverride(t, "tools:\n  mail_trash:\n    decision: prompt\n    ttl: 1m\n")
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.WriteFile(path, []byte("tools:\n  folders_delete:\n    decision: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = e.Reload()
	if err == nil || !strings.Contains(err.Error(), "policy floor") {
		t.Fatalf("Reload: err = %v, want policy-floor rejection", err)
	}
	if d, _ := e.Decide("folders_delete", nil, caller.Caller{}); d != DecisionPrompt {
		t.Errorf("folders_delete after rejected reload = %s, want prompt", d)
	}
	if _, p := e.Decide("mail_trash", nil, caller.Caller{}); p.TTL != "1m" {
		t.Errorf("mail_trash ttl after rejected reload = %q, want 1m (previous policy retained)", p.TTL)
	}
}

// The embedded defaults must themselves satisfy both floors.
func TestEmbeddedDefaultsSatisfyFloors(t *testing.T) {
	doc, err := parseDocument(defaultYAML)
	if err != nil {
		t.Fatal(err)
	}
	if err := enforceSendFloor(&doc); err != nil {
		t.Error(err)
	}
	if err := enforceDestructiveFloor(&doc); err != nil {
		t.Error(err)
	}
}
