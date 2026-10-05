package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

func sessionDeps() Deps {
	return Deps{Session: &protonclient.Session{Addresses: []gpa.Address{
		{Email: "me@proton.me"}, {Email: "me@mydomain.org"},
	}}}
}

func lineIndex(t *testing.T, body, prefix string) int {
	t.Helper()
	for i, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	t.Fatalf("no line starting %q in:\n%s", prefix, body)
	return -1
}

// Item 1: recipients first, then subject, body excerpt, attachments;
// external domains flagged; body clipped at ~300 with "…"; every
// attachment listed; whole dialog within budget.
func TestFormatSendPrompt_OrderAndContent(t *testing.T) {
	long := strings.Repeat("word   \n\t ", 200) // collapses to "word word ..."
	var atts []promptAttachment
	for i := 0; i < 6; i++ {
		atts = append(atts, promptAttachment{Name: fmt.Sprintf("file%d.pdf", i), Size: 2048})
	}
	body := formatSendPrompt(sessionDeps(), sendPromptSpec{
		Action: "Send", Tool: "mail_send",
		To:          []string{"Alice <alice@proton.me>", "bob@gmail.com"},
		CC:          []string{"carol@mydomain.org"},
		BCC:         []string{"dave@evil.example"},
		Subject:     "Quarterly numbers",
		BodyText:    long,
		Attachments: atts,
	})

	to, cc, bcc := lineIndex(t, body, "To:"), lineIndex(t, body, "CC:"), lineIndex(t, body, "BCC:")
	subj, bod, att := lineIndex(t, body, "Subject:"), lineIndex(t, body, "Body:"), lineIndex(t, body, "Attachments (6):")
	if !(to < cc && cc < bcc && bcc < subj && subj < bod && bod < att) {
		t.Errorf("wrong order:\n%s", body)
	}
	toLine := strings.Split(body, "\n")[to]
	if strings.Contains(toLine, "alice@proton.me (external)") || !strings.Contains(toLine, "bob@gmail.com (external)") {
		t.Errorf("external flagging wrong: %q", toLine)
	}
	if strings.Contains(strings.Split(body, "\n")[cc], "(external)") {
		t.Errorf("own secondary domain flagged external")
	}
	if !strings.Contains(strings.Split(body, "\n")[bcc], "dave@evil.example (external)") {
		t.Errorf("BCC external not flagged")
	}
	bodyLine := strings.Split(body, "\n")[bod]
	if !strings.Contains(bodyLine, "word word") || !(strings.Contains(bodyLine, "…") || strings.Contains(bodyLine, "...")) {
		t.Errorf("body excerpt not collapsed/clipped: %q", bodyLine)
	}
	if n := len([]rune(bodyLine)); n > bodyExcerptMax+20 {
		t.Errorf("body line %d runes, want <= ~%d", n, bodyExcerptMax)
	}
	for i := 0; i < 6; i++ {
		if !strings.Contains(body, fmt.Sprintf("file%d.pdf (2 KB)", i)) {
			t.Errorf("attachment %d missing:\n%s", i, body)
		}
	}
	if n := len([]rune(body)); n > 700 {
		t.Errorf("dialog is %d runes, want <= 700:\n%s", n, body)
	}
}

// Long recipient/attachment lists squeeze the body excerpt, never the
// recipients.
func TestFormatSendPrompt_BudgetShrinksBodyFirst(t *testing.T) {
	var to []string
	for i := 0; i < 20; i++ {
		to = append(to, fmt.Sprintf("person%02d@example.com", i))
	}
	body := formatSendPrompt(Deps{}, sendPromptSpec{
		Action: "Send", To: to, Subject: "s", BodyText: strings.Repeat("x", 1000),
	})
	for _, a := range to {
		if !strings.Contains(body, a) {
			t.Errorf("recipient %s elided", a)
		}
	}
	bodyLine := strings.Split(body, "\n")[lineIndex(t, body, "Body:")]
	if n := len([]rune(bodyLine)); n >= bodyExcerptMax {
		t.Errorf("body excerpt should shrink under pressure; got %d runes", n)
	}
}

func TestBodyExcerptHTMLAndSanitize(t *testing.T) {
	got := bodyExcerpt("", "<p>Hello <b>there</b></p><script>evil()</script>\u202eabc", 300)
	if strings.Contains(got, "<") || strings.Contains(got, "evil") || strings.ContainsRune(got, '\u202e') {
		t.Errorf("html/bidi not stripped: %q", got)
	}
}

// Item 8b for sends: an out-of-allowlist path is listed with its full
// path in the send dialog, and only listed paths pass the handler gate.
func TestSendPrompt_OutsidePathListedAndGated(t *testing.T) {
	home := fakeHome(t)
	f := writeFile(t, filepath.Join(home, "Desktop", "tax return.pdf"), "123456")
	other := writeFile(t, filepath.Join(home, "Desktop", "other.pdf"), "x")
	args := json.RawMessage(`{"subject":"s","to":["a@b.c"],"attachments":[{"path":"` + f + `"}]}`)

	_, body := sendPromptBodyWithDeps(Deps{}, "mail_send")(args)
	if !strings.Contains(body, f+" [outside allowlist] (6 B)") {
		t.Fatalf("full path not shown:\n%s", body)
	}
	entry, have := sendLedger.take("mail_send", args)
	if !have || !entry.outsidePaths[f] {
		t.Fatalf("ledger entry = %+v have=%v", entry, have)
	}
	gate := ledgerGate(entry, have)
	if _, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: f}}, gate); err != nil {
		t.Errorf("listed path refused: %v", err)
	}
	if _, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: other}}, gate); err == nil {
		t.Error("unlisted out-of-allowlist path must be refused")
	}
	if _, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: f}}, ledgerGate(sendApproval{}, false)); err == nil {
		t.Error("no ledger entry: out-of-allowlist path must be refused")
	}
}

// Denylisted files show as REFUSED in the dialog.
func TestDescribeAttachments_ShowsRefusal(t *testing.T) {
	home := fakeHome(t)
	k := writeFile(t, filepath.Join(home, "Documents", "server.pem"), "x")
	atts, outside := describeAttachments(Deps{}, []sendAttachmentInput{{Path: k}, {Filename: "a.txt", ContentB64: "aGk="}})
	if len(outside) != 0 || atts[0].Err == "" || atts[1].Size != 2 {
		t.Errorf("atts=%+v outside=%v", atts, outside)
	}
	if s := formatPromptAttachment(atts[0]); !strings.Contains(s, "REFUSED") {
		t.Errorf("refusal not shown: %q", s)
	}
}

// Item 1/2: mail_send_draft with an unloadable draft says so in the
// dialog AND the handler refuses; with no dialog at all it refuses too.
func TestSendDraft_LookupFailureRefuses(t *testing.T) {
	tl := mailSendDraft(Deps{})
	args := json.RawMessage(`{"draft_id":"draft-lookup-fails"}`)
	_, body := tl.PromptBody(args)
	if !strings.Contains(body, "COULD NOT LOAD THE DRAFT") || !strings.Contains(body, "will NOT send") {
		t.Fatalf("dialog doesn't flag the failed lookup:\n%s", body)
	}
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, args)
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultText(res), "could not show the draft") {
		t.Fatalf("handler should refuse: res=%+v err=%v", res, err)
	}

	res, err = tl.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(`{"draft_id":"never-prompted"}`))
	if err != nil || res == nil || !res.IsError || !strings.Contains(resultText(res), "no record") {
		t.Fatalf("handler without dialog should refuse: res=%+v err=%v", res, err)
	}
}

// Item 2: the digest covers recipients, subject, body, MIME type and
// attachment IDs.
func TestDraftDigest(t *testing.T) {
	base := gpa.Message{}
	base.Subject = "Hello"
	base.MIMEType = "text/plain"
	base.ToList = []*mail.Address{{Address: "a@x.com"}}
	base.Attachments = []gpa.Attachment{{ID: "att1", Name: "a.pdf", Size: 10}}
	d0 := draftDigest(base, "body")
	if d0 != draftDigest(base, "body") {
		t.Fatal("digest not deterministic")
	}
	mut := func(f func(m *gpa.Message)) gpa.Message {
		m := base
		m.ToList = append([]*mail.Address{}, base.ToList...)
		m.Attachments = append([]gpa.Attachment{}, base.Attachments...)
		f(&m)
		return m
	}
	cases := map[string]string{
		"to":   draftDigest(mut(func(m *gpa.Message) { m.ToList = []*mail.Address{{Address: "evil@x.com"}} }), "body"),
		"bcc":  draftDigest(mut(func(m *gpa.Message) { m.BCCList = []*mail.Address{{Address: "spy@x.com"}} }), "body"),
		"subj": draftDigest(mut(func(m *gpa.Message) { m.Subject = "Hello!" }), "body"),
		"att":  draftDigest(mut(func(m *gpa.Message) { m.Attachments = append(m.Attachments, gpa.Attachment{ID: "att2"}) }), "body"),
		"mime": draftDigest(mut(func(m *gpa.Message) { m.MIMEType = "text/html" }), "body"),
		"body": draftDigest(base, "body changed"),
	}
	for name, d := range cases {
		if d == d0 {
			t.Errorf("digest unchanged after %s change", name)
		}
	}
}

// The draft dialog lists the draft's own attachments.
func TestDraftPromptSpecListsDraftAttachments(t *testing.T) {
	d := gpa.Message{}
	d.Subject = "Report"
	d.ToList = []*mail.Address{{Address: "boss@example.com"}}
	d.Attachments = []gpa.Attachment{{ID: "1", Name: "q3.xlsx", Size: 3 << 20}, {ID: "2", Name: "notes.txt", Size: 12}}
	body := formatSendPrompt(Deps{}, draftPromptSpec(d, "Please see attached."))
	for _, want := range []string{"boss@example.com", "Report", "Please see attached.", "q3.xlsx (3.0 MB) [on draft]", "notes.txt (12 B) [on draft]"} {
		if !strings.Contains(body, want) {
			t.Errorf("draft dialog missing %q:\n%s", want, body)
		}
	}
}

// Item 7: reply extra recipients are exposed to the middleware and
// validated; reply handlers refuse without a dialog record or when the
// dialog couldn't resolve recipients.
func TestReplyExtrasAndRefusals(t *testing.T) {
	got := extractReplyRecipients(json.RawMessage(`{"in_reply_to":"m","extra_to":["Boss <boss@y.com>"],"cc":["c@z.com"]}`))
	if strings.Join(got, ",") != "boss@y.com,c@z.com" {
		t.Errorf("extractReplyRecipients = %v", got)
	}

	tl := mailReplyAll(Deps{})
	ctx := mcp.Context{Std: context.Background()}
	_, err := tl.Handler(ctx, json.RawMessage(`{"in_reply_to":"m","cc":["not an address"]}`))
	var pe *mcp.Error
	if !errors.As(err, &pe) || pe.Code != mcp.CodeInvalidParams {
		t.Errorf("invalid cc: err = %v, want InvalidParams", err)
	}

	res, err := tl.Handler(ctx, json.RawMessage(`{"in_reply_to":"never-prompted"}`))
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "no record") {
		t.Errorf("no dialog: res=%+v err=%v", res, err)
	}

	args := json.RawMessage(`{"in_reply_to":"unknown-parent","extra_to":["x@y.com"]}`)
	_, body := tl.PromptBody(args)
	if !strings.Contains(body, "COULD NOT RESOLVE") || !strings.Contains(body, "x@y.com") {
		t.Errorf("dialog should flag unresolved parent and still show extras:\n%s", body)
	}
	res, err = tl.Handler(ctx, args)
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "could not show the recipients") {
		t.Errorf("unresolved parent: res=%+v err=%v", res, err)
	}
}

// Reply dialog shows parent-derived + extra recipients (mirror path).
func TestReplyPromptShowsAllRecipients(t *testing.T) {
	st := saveFixture(t, "x.pdf") // msg-1 from x@y, subject "test"
	tl := mailReply(Deps{Store: st})
	args := json.RawMessage(`{"in_reply_to":"msg-1","extra_to":["boss@y.com"],"cc":["c@z.com"],"body_text":"Thanks!"}`)
	_, body := tl.PromptBody(args)
	for _, want := range []string{"To: x@y, boss@y.com", "CC: c@z.com", "Subject: Re: test", `Body: "Thanks!"`} {
		if !strings.Contains(body, want) {
			t.Errorf("reply dialog missing %q:\n%s", want, body)
		}
	}
	entry, have := sendLedger.take("mail_reply", args)
	if !have || strings.Join(entry.recipients, ",") != "boss@y.com,c@z.com,x@y" {
		t.Errorf("recorded recipients = %v have=%v", entry.recipients, have)
	}
}

// Forward with include_parent_attachments: an unlisted original is a
// refusal; include_original is announced in the dialog.
func TestForwardDialog(t *testing.T) {
	tl := mailForward(Deps{})
	args := json.RawMessage(`{"forward_of":"p","to":["a@b.c"],"include_parent_attachments":true,"include_original":true}`)
	_, body := tl.PromptBody(args)
	if !strings.Contains(body, "COULD NOT LIST") || !strings.Contains(body, "+ quoted original message") {
		t.Errorf("forward dialog:\n%s", body)
	}
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, args)
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "could not show") {
		t.Errorf("forward handler should refuse: res=%+v err=%v", res, err)
	}
}

func TestFormatQuotedOriginal(t *testing.T) {
	p := gpa.Message{}
	p.Subject = "Plans"
	p.Sender = &mail.Address{Name: "Ann", Address: "ann@x.com"}
	p.ToList = []*mail.Address{{Address: "me@proton.me"}}
	p.CCList = []*mail.Address{{Address: "bo@x.com"}}
	p.Time = 1700000000
	p.MIMEType = "text/plain"
	got := formatQuotedOriginal(p, "line one\r\nline two\x1b[31m\n")
	for _, want := range []string{"---------- Forwarded message ----------", "From: Ann <ann@x.com>", "Subject: Plans",
		"To: me@proton.me", "Cc: bo@x.com", "Date: ", "line one\nline two[31m"} {
		if !strings.Contains(got, want) {
			t.Errorf("quote missing %q:\n%s", want, got)
		}
	}
	p.MIMEType = "text/html"
	got = formatQuotedOriginal(p, "<style>x{}</style><p>Hi&amp;bye</p><div>second<br>third</div>")
	if !strings.Contains(got, "Hi&bye\nsecond\nthird") || strings.Contains(got, "x{}") {
		t.Errorf("html quote:\n%s", got)
	}
}

// One approval → one send; entries expire.
func TestSendLedgerTakeOnceAndExpiry(t *testing.T) {
	l := &approvalLedger{entries: map[string]sendApproval{}, now: time.Now}
	l.record("t", []byte("a"), sendApproval{draftDigest: "d"})
	if e, ok := l.take("t", []byte("a")); !ok || e.draftDigest != "d" {
		t.Fatal("first take failed")
	}
	if _, ok := l.take("t", []byte("a")); ok {
		t.Error("second take must miss")
	}
	now := time.Now()
	l.now = func() time.Time { return now }
	l.record("t", []byte("b"), sendApproval{})
	now = now.Add(sendLedgerTTL + time.Second)
	if _, ok := l.take("t", []byte("b")); ok {
		t.Error("expired entry must miss")
	}
	if _, ok := l.take("u", []byte("a")); ok {
		t.Error("different tool must miss")
	}
}
