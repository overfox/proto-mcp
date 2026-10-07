package mcptools

import (
	"context"
	"encoding/json"
	"net/mail"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

func TestReplyPrimaryRecipients(t *testing.T) {
	self := []string{"me@proton.me"}
	cases := []struct {
		name string
		p    replyParent
		want string
	}{
		{"sender", replyParent{Sender: "ann@x.com"}, "ann@x.com"},
		{"reply-to wins", replyParent{Sender: "noreply@list.org", ReplyTo: []string{"list@list.org"}}, "list@list.org"},
		{"own sent message → its recipients", replyParent{Sender: "Me@Proton.me", To: []string{"bo@x.com", "cy@x.com"}}, "bo@x.com,cy@x.com"},
	}
	for _, c := range cases {
		to, _ := replyRecipients(c.p, self, false, nil, nil)
		if got := strings.Join(to, ","); got != c.want {
			t.Errorf("%s: to = %s, want %s", c.name, got, c.want)
		}
	}
	// Reply-all to own sent message: no duplicate of To in CC, self dropped.
	to, cc := replyRecipients(replyParent{Sender: "me@proton.me", To: []string{"bo@x.com"}, CC: []string{"me@proton.me", "dd@x.com"}},
		self, true, nil, nil)
	if strings.Join(to, ",") != "bo@x.com" || strings.Join(cc, ",") != "dd@x.com" {
		t.Errorf("reply-all own message: to=%v cc=%v", to, cc)
	}
}

func TestReplySubject(t *testing.T) {
	for in, want := range map[string]string{
		"Plans":         "Re: Plans",
		"Re: Plans":     "Re: Plans",
		"RE: Plans":     "RE: Plans",
		"Re[2]: Plans":  "Re[2]: Plans",
		"AW: Termin":    "AW: Termin",
		"Fwd: Plans":    "Re: Fwd: Plans",
		"Rebuild plans": "Re: Rebuild plans",
	} {
		if got := replySubject(in); got != want {
			t.Errorf("replySubject(%q) = %q, want %q", in, got, want)
		}
	}
	if replyAction(true) != gpa.ReplyAllAction || replyAction(false) != gpa.ReplyAction {
		t.Error("replyAction mapping")
	}
}

const threadOriginal = "From: Ann <ann@example.com>\r\n" +
	"Reply-To: team@example.com\r\n" +
	"To: alice@proton.local, bo@example.com\r\n" +
	"Cc: cy@example.com\r\n" +
	"Subject: Q3 plan\r\n" +
	"Message-ID: <orig-123@example.com>\r\n" +
	"Date: Mon, 5 Oct 2026 09:00:00 +0000\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"Can we meet Thursday?\r\n\r\nAnn\r\n"

// mail_draft_reply creates a draft linked to the original: reply-all
// recipients, Re: subject, quoted body, In-Reply-To on the server, and
// mirrored into the original's local thread.
func TestDraftReplyKeepsThread(t *testing.T) {
	f := newFakeProton(t)
	self := "alice@" + f.srv.GetDomain()
	origID := f.importMessage(t, strings.ReplaceAll(threadOriginal, "alice@proton.local", self))

	var out draftReplyResult
	res := callTool(t, mailDraftReply(f.deps()),
		`{"in_reply_to":"`+origID+`","reply_all":true,"body_text":"Thursday works."}`, &out)
	if res.IsError {
		t.Fatalf("mail_draft_reply: %s", resultText(res))
	}
	if out.Subject != "Re: Q3 plan" {
		t.Errorf("subject = %q", out.Subject)
	}
	if strings.Join(out.To, ",") != "team@example.com" {
		t.Errorf("to = %v, want Reply-To address", out.To)
	}
	if strings.Join(out.CC, ",") != "bo@example.com,cy@example.com" {
		t.Errorf("cc = %v (self must be dropped)", out.CC)
	}

	ctx := context.Background()
	draft, err := f.sess.Client.GetMessage(ctx, out.DraftID)
	if err != nil {
		t.Fatal(err)
	}
	// The fake server doesn't keep an imported message's Message-ID, so
	// the header value is "<>" there; its presence proves the server
	// resolved the parent link (it's only written when it does).
	if !strings.Contains(draft.Header, "In-Reply-To: <") {
		t.Errorf("draft not linked to the original; headers:\n%s", draft.Header)
	}
	_, kr, _ := senderKeyring(f.deps())
	body, err := decryptDraftBody(kr, draft.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Thursday works.\n\n", "Ann <ann@example.com> wrote:", "> Can we meet Thursday?", "\n>\n> Ann"} {
		if !strings.Contains(body, want) {
			t.Errorf("draft body missing %q:\n%s", want, body)
		}
	}

	orig, err := f.st.GetMessage(ctx, origID)
	if err != nil {
		t.Fatal(err)
	}
	mirrored, err := f.st.GetMessage(ctx, out.DraftID)
	if err != nil {
		t.Fatal(err)
	}
	if mirrored.ThreadID != orig.ThreadID || out.ThreadID != orig.ThreadID {
		t.Errorf("draft thread %q / %q, want original's %q", mirrored.ThreadID, out.ThreadID, orig.ThreadID)
	}
}

// include_quote:false leaves the body alone; HTML replies quote in a
// blockquote.
func TestDraftReplyQuoteOptions(t *testing.T) {
	f := newFakeProton(t)
	origID := f.importMessage(t, threadOriginal)
	_, kr, _ := senderKeyring(f.deps())

	var plain draftReplyResult
	callTool(t, mailDraftReply(f.deps()), `{"in_reply_to":"`+origID+`","body_text":"ok","include_quote":false}`, &plain)
	d, _ := f.sess.Client.GetMessage(context.Background(), plain.DraftID)
	if body, _ := decryptDraftBody(kr, d.Body); body != "ok" || plain.Quoted {
		t.Errorf("include_quote:false body = %q quoted=%v", body, plain.Quoted)
	}

	var rich draftReplyResult
	callTool(t, mailDraftReply(f.deps()), `{"in_reply_to":"`+origID+`","body_html":"<p>ok</p>"}`, &rich)
	d, _ = f.sess.Client.GetMessage(context.Background(), rich.DraftID)
	body, _ := decryptDraftBody(kr, d.Body)
	if !strings.Contains(body, "<blockquote") || !strings.Contains(body, "Can we meet Thursday?") || !strings.Contains(body, "Ann &lt;ann@example.com&gt; wrote:") {
		t.Errorf("html quote:\n%s", body)
	}
}

// mail_reply_all end to end: the dialog shows the Reply-To-derived
// recipients and the quote, the sent reply is linked to the original
// and the original is marked replied-all.
func TestReplyAllSendKeepsThread(t *testing.T) {
	f := newFakeProton(t)
	origID := f.importMessage(t, threadOriginal)
	tl := mailReplyAll(f.deps())
	args := json.RawMessage(`{"in_reply_to":"` + origID + `","body_text":"Thursday works."}`)
	_, dialog := tl.PromptBody(args)
	for _, want := range []string{"To: team@example.com", "Subject: Re: Q3 plan", "+ quoted original"} {
		if !strings.Contains(dialog, want) {
			t.Errorf("dialog missing %q:\n%s", want, dialog)
		}
	}
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, args)
	if err != nil || res.IsError {
		t.Fatalf("mail_reply_all: err=%v res=%s", err, resultText(res))
	}
	var sent sendResult
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &sent)

	ctx := context.Background()
	m, err := f.sess.Client.GetMessage(ctx, sent.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Header, "In-Reply-To: <") {
		t.Errorf("sent reply not linked; headers:\n%s", m.Header)
	}
	orig, _ := f.sess.Client.GetMessage(ctx, origID)
	if !orig.Flags.Has(gpa.MessageFlagRepliedAll) {
		t.Errorf("original flags %v, want RepliedAll", orig.Flags)
	}
}

func TestReplyQuoteAttribution(t *testing.T) {
	p := gpa.Message{}
	p.Sender = &mail.Address{Name: "Ann", Address: "ann@x.com"}
	p.Time = 1791190800 // Mon, 5 Oct 2026 09:00 UTC
	p.MIMEType = "text/plain"
	header, text := replyQuoteParts(p, "hi\r\n\x1b[31mthere\n")
	if !strings.HasPrefix(header, "On ") || !strings.Contains(header, " 2026 at ") || !strings.HasSuffix(header, ", Ann <ann@x.com> wrote:") {
		t.Errorf("header = %q", header)
	}
	if text != "hi\n[31mthere" {
		t.Errorf("text = %q", text)
	}
}
