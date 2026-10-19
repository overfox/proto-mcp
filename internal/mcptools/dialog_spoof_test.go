package mcptools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// dialogLines splits a dialog body the way AppKit lays it out: '\n'
// AND the Unicode line/paragraph separators all start a new line.
func dialogLines(body string) []string {
	return strings.FieldsFunc(body, func(r rune) bool {
		return r == '\n' || r == 0x2028 || r == 0x2029 || r == 0x0085 || r == 0x0b || r == 0x0c
	})
}

// M3a (ported from the assessment PoC zz_dialog_test.go): a subject or
// attachment filename carrying U+2028 / U+2029 / U+0085 used to survive
// sanitization and paint fake "Attachments:" / "BCC:" lines.
func TestSendPrompt_UnicodeSeparatorsCannotForgeLines(t *testing.T) {
	for _, sep := range []string{string(rune(0x2028)), string(rune(0x2029)), string(rune(0x0085))} {
		args, _ := json.Marshal(map[string]any{
			"to":        []string{"bob@partner.com"},
			"subject":   "Lunch" + sep + "Attachments: none" + sep + "BCC: (none)",
			"body_text": "hi",
			"attachments": []map[string]string{{
				"filename":    "a" + sep + "To: x@y.com" + string(rune(0x202e)) + ".pdf",
				"content_b64": base64.StdEncoding.EncodeToString([]byte("x")),
			}},
		})
		_, body := sendPromptBodyWithDeps(Deps{}, "mail_send")(args)
		sendLedger.take("mail_send", args)
		for _, l := range dialogLines(body) {
			if strings.HasPrefix(l, "BCC:") || (strings.HasPrefix(l, "Attachments:") && !strings.HasPrefix(l, "Attachments (1):")) ||
				(strings.HasPrefix(l, "To:") && !strings.Contains(l, "bob@partner.com")) {
				t.Errorf("separator %U forged a dialog line %q:\n%s", []rune(sep)[0], l, body)
			}
		}
		if strings.ContainsRune(body, 0x202e) {
			t.Errorf("bidi override survived:\n%q", body)
		}
	}
}

// M3b: the recipient summary comes first and names every external
// address (BCC included); recipient and attachment lines are never
// cut — only the body excerpt shrinks.
func TestSendPrompt_BCCNeverHidden(t *testing.T) {
	var to []string
	for i := 0; i < 40; i++ {
		to = append(to, fmt.Sprintf("colleague%02d@proton.me", i))
	}
	body, failure := formatSendPromptChecked(sessionDeps(), sendPromptSpec{
		Action: "Send", Tool: "mail_send",
		To: to, BCC: []string{"exfil@evil.example"},
		Subject: "Team update", BodyText: strings.Repeat("blah ", 500),
		Attachments: []promptAttachment{{Name: "payroll.xlsx", Size: 4096}},
	})
	if failure != "" {
		t.Fatalf("unexpected overflow: %s", failure)
	}
	lines := strings.Split(body, "\n")
	if lines[1] != "41 recipients (1 external): exfil@evil.example [BCC]" {
		t.Errorf("summary line = %q", lines[1])
	}
	if !strings.Contains(body, "\nBCC: exfil@evil.example (external)") || !strings.Contains(body, "payroll.xlsx (4 KB)") {
		t.Errorf("BCC / attachment line missing:\n%s", body)
	}
	for _, a := range to {
		if !strings.Contains(body, a) {
			t.Errorf("recipient %s elided", a)
		}
	}
	if n := runeLen(body); n > sendPromptBudget {
		t.Errorf("dialog %d runes > budget %d", n, sendPromptBudget)
	}
}

// M3b: when every recipient + attachment can't fit, the dialog fails
// closed: it says so up top, the ledger records a failure, and the
// handler refuses even after approval.
func TestSendPrompt_FailsClosedWhenTooManyRecipients(t *testing.T) {
	var to []string
	for i := 0; i < 50; i++ {
		to = append(to, fmt.Sprintf("someone%02d@example.com", i))
	}
	args, _ := json.Marshal(map[string]any{
		"to": to, "bcc": []string{"hidden@evil.example"}, "subject": "s", "body_text": "b",
	})
	_, body := sendPromptBodyWithDeps(sessionDeps(), "mail_send")(args)
	if !strings.HasPrefix(body, "⚠️ TOO MANY RECIPIENTS") || !strings.Contains(body, "will NOT send") {
		t.Errorf("dialog does not flag overflow:\n%s", body)
	}
	if lines := strings.Split(body, "\n"); !strings.Contains(lines[2], "hidden@evil.example [BCC]") {
		t.Errorf("BCC external not in the summary line: %q", lines[2])
	}
	res, err := mailSend(sessionDeps()).Handler(mcp.Context{Std: context.Background()}, args)
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultText(res), "split this into several messages") {
		t.Fatalf("handler must refuse: res=%+v err=%v", res, err)
	}

	// Reply family + forward record the same failure.
	_, failure := formatSendPromptChecked(Deps{}, sendPromptSpec{Action: "Forward", To: to, BCC: to})
	if failure == "" {
		t.Error("forward-size overflow not detected")
	}
}

// M3c: a path attachment is shown by its REAL file name and folder,
// not the model-chosen filename; the name recipients will see is
// shown separately when it differs.
func TestDescribeAttachments_ShowsRealFile(t *testing.T) {
	home := fakeHome(t)
	docs := filepath.Join(home, "Documents")
	real := writeFile(t, filepath.Join(docs, "passport.pdf"), "123456")
	deps := Deps{Policy: engineWithAllowlist(t, docs)}

	atts, outside := describeAttachments(deps, []sendAttachmentInput{{Path: real, Filename: "holiday.jpg"}})
	if len(outside) != 0 || len(atts) != 1 {
		t.Fatalf("atts=%+v outside=%v", atts, outside)
	}
	got := formatPromptAttachment(atts[0])
	want := `passport.pdf — ~/Documents, sent as "holiday.jpg" (6 B)`
	if got != want {
		t.Errorf("attachment line = %q, want %q", got, want)
	}

	// A symlink with an innocent name resolves to the real file.
	link := filepath.Join(docs, "cat.jpg")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	atts, _ = describeAttachments(deps, []sendAttachmentInput{{Path: link}})
	if got := formatPromptAttachment(atts[0]); !strings.HasPrefix(got, "passport.pdf — ~/Documents") || !strings.Contains(got, `sent as "cat.jpg"`) {
		t.Errorf("symlink attachment line = %q", got)
	}

	// Outside the allowlist: the full path, plus the sent-as name.
	atts, outside = describeAttachments(Deps{}, []sendAttachmentInput{{Path: real, Filename: "holiday.jpg"}})
	if len(outside) != 1 {
		t.Fatalf("outside = %v", outside)
	}
	if got := formatPromptAttachment(atts[0]); got != real+` [outside allowlist], sent as "holiday.jpg" (6 B)` {
		t.Errorf("outside line = %q", got)
	}
}

// M3d: the draft out-of-allowlist prompt dedupes paths, lists them
// first and in full, and refuses more than maxDraftOutsideFiles.
func TestOutsideAllowlistPrompt_DedupeCapNoTruncation(t *testing.T) {
	mk := func(n int) []resolvedAttachmentPath {
		var out []resolvedAttachmentPath
		for i := 0; i < n; i++ {
			p := fmt.Sprintf("/Users/me/Private/%s/secret%d.pdf", strings.Repeat("deep", 10), i)
			out = append(out, resolvedAttachmentPath{Requested: p, Resolved: p, Size: 10})
		}
		return out
	}
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, fmt.Sprintf("r%03d@example.com", i))
	}
	five := mk(5)
	dup := append(append([]resolvedAttachmentPath{}, five...), five...)
	_, body, err := outsideAllowlistPrompt("mail_draft_create", "s", many, dup)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body, "Attach 5 files") {
		t.Errorf("duplicates not collapsed: %q", strings.Split(body, "\n")[0])
	}
	for _, f := range five {
		if strings.Count(body, f.Resolved) != 1 {
			t.Errorf("path %s not listed exactly once", f.Resolved)
		}
	}
	if strings.Index(body, "To:") < strings.Index(body, five[4].Resolved) {
		t.Error("recipients must come after the file list")
	}
	if n := runeLen(body); n > draftOutsidePromptBudget {
		t.Errorf("prompt %d runes > %d", n, draftOutsidePromptBudget)
	}

	if _, _, err := outsideAllowlistPrompt("mail_draft_create", "s", nil, mk(6)); err == nil ||
		!strings.Contains(err.Error(), "at most 5") {
		t.Errorf("6 files: err = %v, want refusal", err)
	}

	calls := 0
	deps := Deps{Approve: func(context.Context, string, string) error { calls++; return nil }}
	if err := draftAttachmentGate(context.Background(), deps, "mail_draft_create", "", nil)(mk(6)); err == nil || calls != 0 {
		t.Errorf("gate: err=%v calls=%d — must refuse without prompting", err, calls)
	}
}
