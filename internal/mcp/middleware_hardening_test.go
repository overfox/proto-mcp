package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// Lows: a call refused because the daemon is locked is audited as
// outcome denied with reason "locked: …" (it used to leave no row).
func TestMiddlewareLockedRefusalAudited(t *testing.T) {
	w, st := newTestAudit(t)
	srv := New(nil, WithAudit(w), WithLockState(func() (bool, string) { return true, "screen_locked" }))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			t.Fatal("handler ran while locked")
			return nil, nil
		},
	})
	roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"q":"x"}}}`,
	)
	var outcome, errMsg string
	if err := st.DB.QueryRow(`SELECT outcome, error_msg FROM audit_log WHERE tool = 'echo'`).Scan(&outcome, &errMsg); err != nil {
		t.Fatalf("no audit row for the locked refusal: %v", err)
	}
	if outcome != "denied" || !strings.HasPrefix(errMsg, "locked") || !strings.Contains(errMsg, "screen_locked") {
		t.Fatalf("row outcome=%q err=%q, want denied / locked: screen_locked", outcome, errMsg)
	}
}

// Lows: the rate-limit key is per caller binary, so a reconnecting
// client (new PID, same binary) doesn't get a fresh budget.
func TestRateLimitKeyPerBinary(t *testing.T) {
	a := rateLimitKey("mail_send", caller.Caller{PID: 100, Binary: "/Applications/Claude.app/x"})
	b := rateLimitKey("mail_send", caller.Caller{PID: 200, Binary: "/Applications/Claude.app/x"})
	if a != b {
		t.Fatalf("keys differ across PIDs of the same binary: %q vs %q", a, b)
	}
	if rateLimitKey("mail_send", caller.Caller{PID: 1}) == rateLimitKey("mail_send", caller.Caller{PID: 2}) {
		t.Fatal("unresolved-binary callers should fall back to per-PID keys")
	}
}

// M5: the approval-cache binding includes the prompt text, so a prompt
// that describes different content (an edited rule) can't reuse a
// cached approval.
func TestApprovalBindingIncludesPrompt(t *testing.T) {
	args := json.RawMessage(`{"name":"r1"}`)
	x := approvalBinding(args, "Approve rules_run?", "APPLY rule r1\nrule content: aaaa")
	y := approvalBinding(args, "Approve rules_run?", "APPLY rule r1\nrule content: bbbb")
	if string(x) == string(y) {
		t.Fatal("binding ignores the prompt body")
	}
	if !json.Valid(x) || !json.Valid(approvalBinding(nil, "t", "b")) {
		t.Fatal("binding is not valid JSON")
	}
}
