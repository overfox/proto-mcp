package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// Pins the default policy for the archival / triage / rules tools so a
// later edit to default.yaml can't silently loosen them.
func TestNewToolPolicyDefaults(t *testing.T) {
	eng, err := policy.New(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		tool     string
		decision policy.Decision
		confirm  bool
		ttl      string
	}{
		{"mail_export_eml", policy.DecisionPrompt, true, "0"},
		{"mail_attachment_text", policy.DecisionPrompt, false, "5m"},
		{"mail_report_spam", policy.DecisionPrompt, false, "5m"},
		{"rules_set", policy.DecisionPrompt, true, "0"},
		{"rules_delete", policy.DecisionPrompt, true, "0"},
		{"rules_run", policy.DecisionPrompt, false, "5m"},
		{"mail_star", policy.DecisionAllow, false, ""},
		{"mail_unstar", policy.DecisionAllow, false, ""},
		{"contacts_search", policy.DecisionAllow, false, ""},
		{"mail_digest", policy.DecisionAllow, false, ""},
		{"mail_awaiting_reply", policy.DecisionAllow, false, ""},
		{"rules_list", policy.DecisionAllow, false, ""},
	}
	for _, c := range cases {
		d, p := eng.Decide(c.tool, nil, caller.Caller{})
		if d != c.decision {
			t.Errorf("%s: decision %s, want %s", c.tool, d, c.decision)
			continue
		}
		if p == nil {
			t.Errorf("%s: no policy entry", c.tool)
			continue
		}
		if p.Confirm != c.confirm || (c.ttl != "" && p.TTL != c.ttl) {
			t.Errorf("%s: confirm=%v ttl=%q, want confirm=%v ttl=%q", c.tool, p.Confirm, p.TTL, c.confirm, c.ttl)
		}
	}
}

// keep_alive removes the prompt only for the read-and-save attachment
// family; rules, spam and the rest stay gated.
func TestKeepAliveCoversOnlyAttachmentStyleNewTools(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte("keep_alive: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.New(context.Background(), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"mail_export_eml", "mail_attachment_text"} {
		if d, _ := eng.Decide(tool, nil, caller.Caller{}); d != policy.DecisionAllow {
			t.Errorf("keep_alive: %s = %s, want allow", tool, d)
		}
	}
	for _, tool := range []string{"mail_report_spam", "rules_set", "rules_delete", "rules_run"} {
		if d, _ := eng.Decide(tool, nil, caller.Caller{}); d != policy.DecisionPrompt {
			t.Errorf("keep_alive: %s = %s, want prompt", tool, d)
		}
	}
}
