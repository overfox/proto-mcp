package mcptools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"golang.org/x/sys/unix"
)

func TestMailExportEML_RoundTripWithAttachments(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := newFakeProton(t)
	csv := []byte("isin,qty\nCH0012345678,100\n")
	id, _ := f.createMessageWithAttachments(t, "Re: Arbitration/Hearing", "Hearing moved to Friday.",
		fakeAttachment{Name: "positions.csv", MIME: "text/csv", Body: csv})

	tl := mailExportEML(f.deps())
	var out struct {
		SavedPath       string `json:"saved_path"`
		Filename        string `json:"filename"`
		SizeBytes       int64  `json:"size_bytes"`
		AttachmentCount int    `json:"attachment_count"`
	}
	res := callTool(t, tl, fmt.Sprintf(`{"message_id":%q}`, id), &out)
	if res.IsError {
		t.Fatalf("export failed: %s", res.Content[0].Text)
	}
	if filepath.Dir(out.SavedPath) != filepath.Join(home, "Downloads") {
		t.Errorf("saved to %q, want ~/Downloads", out.SavedPath)
	}
	wantName := time.Now().Local().Format("2006-01-02") + " Re - Arbitration_Hearing.eml"
	if out.Filename != wantName {
		t.Errorf("filename = %q, want %q", out.Filename, wantName)
	}
	if out.AttachmentCount != 1 {
		t.Errorf("attachment_count = %d", out.AttachmentCount)
	}

	raw, err := os.ReadFile(out.SavedPath)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) != out.SizeBytes {
		t.Errorf("size mismatch %d vs %d", len(raw), out.SizeBytes)
	}
	hdr, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a parseable RFC 822 message: %v", err)
	}
	if got := hdr.Header.Get("Subject"); got != "Re: Arbitration/Hearing" {
		t.Errorf("Subject header = %q", got)
	}

	// Walk the MIME tree: the decrypted body and the attachment bytes
	// must both be present.
	ent, err := message.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var sawBody, sawAtt bool
	_ = ent.Walk(func(_ []int, e *message.Entity, _ error) error {
		if mr := e.MultipartReader(); mr != nil {
			return nil
		}
		b, _ := io.ReadAll(e.Body)
		if strings.Contains(string(b), "Hearing moved to Friday.") {
			sawBody = true
		}
		if bytes.Equal(b, csv) {
			sawAtt = true
		}
		return nil
	})
	if !sawBody || !sawAtt {
		t.Errorf("decoded parts: body=%v attachment=%v", sawBody, sawAtt)
	}

	// Quarantine xattr set.
	buf := make([]byte, 256)
	if n, err := unix.Getxattr(out.SavedPath, "com.apple.quarantine", buf); err != nil || n == 0 {
		t.Errorf("quarantine xattr missing: %v", err)
	}

	// Second export never overwrites.
	var out2 struct {
		SavedPath string `json:"saved_path"`
	}
	callTool(t, tl, fmt.Sprintf(`{"message_id":%q}`, id), &out2)
	if !strings.HasSuffix(out2.SavedPath, " (2).eml") {
		t.Errorf("second export path = %q, want (2) suffix", out2.SavedPath)
	}
}

func TestMailExportEML_FilenameAndDirectoryRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := newFakeProton(t)
	id, _ := f.createMessageWithAttachments(t, "Plain", "x")

	allowed := t.TempDir()
	allowed, _ = filepath.EvalSymlinks(allowed)
	deps := f.deps()
	deps.Policy = engineWithAllowlist(t, allowed)
	tl := mailExportEML(deps)

	// Caller filename gets .eml forced (no executable extension).
	var out struct {
		SavedPath string `json:"saved_path"`
	}
	res := callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"directory":%q,"filename":"run.command"}`, id, allowed), &out)
	if res.IsError {
		t.Fatalf("export failed: %s", res.Content[0].Text)
	}
	if out.SavedPath != filepath.Join(allowed, "run.command.eml") {
		t.Errorf("saved_path = %q", out.SavedPath)
	}

	// Path separators are neutralized, not followed.
	res = callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"directory":%q,"filename":"../../escape"}`, id, allowed), &out)
	if res.IsError || filepath.Dir(out.SavedPath) != allowed {
		t.Errorf("traversal filename escaped: %+v %v", out, res.Content[0].Text)
	}

	// Outside the allowlist → refused.
	other := t.TempDir()
	res = callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"directory":%q}`, id, other), nil)
	if !res.IsError {
		t.Error("directory outside allowlist must be refused")
	}

	// Hidden directory inside the allowlist → refused.
	hidden := filepath.Join(allowed, ".claude")
	if err := os.Mkdir(hidden, 0o700); err != nil {
		t.Fatal(err)
	}
	res = callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"directory":%q}`, id, hidden), nil)
	if !res.IsError {
		t.Error("hidden directory must be refused")
	}
}

func TestMailExportEML_Validation(t *testing.T) {
	f := newFakeProton(t)
	tl := mailExportEML(f.deps())
	_, err := tl.Handler(mcpCtx(), json.RawMessage(`{}`))
	if err == nil {
		t.Error("missing message_id must be invalid params")
	}
	if tl.PromptBody == nil {
		t.Error("PromptBody required — policy is confirm:true")
	}
}

func TestDefaultEMLName(t *testing.T) {
	d := time.Date(2026, 3, 4, 12, 0, 0, 0, time.Local)
	cases := map[string]string{
		"":                      "2026-03-04 message.eml",
		"Re: Hello":             "2026-03-04 Re - Hello.eml",
		"  many   spaces\there": "2026-03-04 many spaces here.eml",
	}
	for in, want := range cases {
		if got := emlFilename(defaultEMLName(in, d)); got != want {
			t.Errorf("defaultEMLName(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("x", 300)
	if got := defaultEMLName(long, d); len([]rune(got)) > 11+emlSubjectMaxRunes+4 {
		t.Errorf("long subject not truncated: %d runes", len([]rune(got)))
	}
}
