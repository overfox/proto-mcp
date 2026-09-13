package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

func keepAliveEngine(t *testing.T, yaml string) *Engine {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// With keep_alive on, the two read-only attachment tools downgrade
// prompt → allow; every mutating tool keeps its prompt.
func TestKeepAliveSuppressesAttachmentPromptsOnly(t *testing.T) {
	e := keepAliveEngine(t, "keep_alive: true\n")

	for _, tool := range []string{"mail_download_attachment", "mail_save_attachment"} {
		if d, _ := e.Decide(tool, nil, caller.Caller{}); d != DecisionAllow {
			t.Errorf("keep_alive on: %s = %s, want allow", tool, d)
		}
	}
	// Mutating / send / delete tools must still prompt.
	for _, tool := range []string{
		"mail_send", "mail_reply", "mail_forward", "mail_send_draft",
		"mail_move", "mail_label", "mail_trash", "mail_draft_delete",
		"labels_delete", "folders_delete",
	} {
		if d, _ := e.Decide(tool, nil, caller.Caller{}); d != DecisionPrompt {
			t.Errorf("keep_alive on: %s = %s, want prompt (must stay gated)", tool, d)
		}
	}
}

// With keep_alive off (default), the attachment tools prompt as normal.
func TestKeepAliveOffKeepsAttachmentPrompts(t *testing.T) {
	e := keepAliveEngine(t, "keep_alive: false\n")
	for _, tool := range []string{"mail_download_attachment", "mail_save_attachment"} {
		if d, _ := e.Decide(tool, nil, caller.Caller{}); d != DecisionPrompt {
			t.Errorf("keep_alive off: %s = %s, want prompt", tool, d)
		}
	}
}

// Absent keep_alive key is treated as off (secure default).
func TestKeepAliveDefaultsOff(t *testing.T) {
	e, err := New(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Decide("mail_download_attachment", nil, caller.Caller{}); d != DecisionPrompt {
		t.Errorf("no config: mail_download_attachment = %s, want prompt", d)
	}
}

// keep_alive cannot un-gate a mutating tool even if a policy file
// tries to combine it with a downgrade the send floor would catch —
// and, for a tool NOT on the send floor, the hardcoded suppressible
// set still excludes it, so keep_alive has no effect on mail_move.
func TestKeepAliveCannotWidenToMutations(t *testing.T) {
	e := keepAliveEngine(t, "keep_alive: true\n")
	if d, _ := e.Decide("mail_move", nil, caller.Caller{}); d != DecisionPrompt {
		t.Errorf("keep_alive on: mail_move = %s, want prompt (not in suppressible set)", d)
	}
}
