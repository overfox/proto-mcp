package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// saveFixture returns a store with one cached attachment named fname.
func saveFixture(t *testing.T, fname string) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES (?, ?, ?, ?, ?, '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "test", "x@y", "X",
	); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
		MessageID: "msg-1", AttachmentID: "att-A",
		Filename: fname, MIMEType: "application/octet-stream",
		SizeBytes: 5, Content: []byte("hello"),
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func runSave(t *testing.T, deps Deps, args string) *mcp.ToolResult {
	t.Helper()
	res, err := mailSaveAttachment(deps).Handler(mcp.Context{Std: context.Background()}, json.RawMessage(args))
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	return res
}

// Saved files carry com.apple.quarantine.
func TestMailSaveAttachment_SetsQuarantine(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	st := saveFixture(t, "report.pdf")

	res := runSave(t, Deps{Store: st}, `{"message_id":"msg-1","attachment_id":"att-A"}`)
	if res == nil || res.IsError {
		t.Fatalf("save failed: %+v", res)
	}
	p := filepath.Join(tmp, "Downloads", "report.pdf")
	buf := make([]byte, 256)
	n, err := unix.Getxattr(p, "com.apple.quarantine", buf)
	if err != nil {
		t.Fatalf("quarantine xattr missing on %s: %v", p, err)
	}
	if !strings.Contains(string(buf[:n]), "protonmcp") {
		t.Errorf("quarantine value = %q, want protonmcp agent", buf[:n])
	}
}

// Agent/IDE config names and run-on-open extensions are refused, both
// from the cached name and from a caller-supplied override.
func TestMailSaveAttachment_RefusesDangerousNames(t *testing.T) {
	for _, tc := range []struct{ cached, override string }{
		{"CLAUDE.md", ""},
		{"report.pdf", "AGENTS.md"},
		{"report.pdf", "run.command"},
		{"setup.webloc", ""},
	} {
		t.Run(tc.cached+"/"+tc.override, func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("HOME", tmp)
			st := saveFixture(t, tc.cached)
			args := `{"message_id":"msg-1","attachment_id":"att-A"}`
			if tc.override != "" {
				args = `{"message_id":"msg-1","attachment_id":"att-A","filename":"` + tc.override + `"}`
			}
			res := runSave(t, Deps{Store: st}, args)
			if res == nil || !res.IsError {
				t.Fatalf("expected refusal, got %+v", res)
			}
			entries, _ := os.ReadDir(filepath.Join(tmp, "Downloads"))
			if len(entries) != 0 {
				t.Errorf("nothing should be written, found %d entries", len(entries))
			}
		})
	}
}

// A target directory under a hidden component is refused even when it
// is inside attachment_path_allowlist.
func TestMailSaveAttachment_RefusesHiddenDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	hidden := filepath.Join(tmp, "proj", ".claude")
	if err := os.MkdirAll(hidden, 0o700); err != nil {
		t.Fatal(err)
	}
	st := saveFixture(t, "notes.txt")
	deps := Deps{Store: st, Policy: engineWithAllowlist(t, filepath.Join(tmp, "proj"))}
	res := runSave(t, deps, `{"message_id":"msg-1","attachment_id":"att-A","directory":"`+hidden+`"}`)
	if res == nil || !res.IsError || !strings.Contains(resultText(res), "hidden directory") {
		t.Fatalf("expected hidden-dir refusal, got %+v", res)
	}
	if _, err := os.Stat(filepath.Join(hidden, "notes.txt")); err == nil {
		t.Error("file was written into a hidden directory")
	}
}
