package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func TestSanitizeField_CollapsesLineBreaks(t *testing.T) {
	got := sanitizeField("real@y.com\nBCC: evil@x.com\r\tx")
	if strings.ContainsAny(got, "\r\n\t") {
		t.Errorf("sanitizeField left a line break / tab in %q", got)
	}
}

func TestAddressesFromJSON(t *testing.T) {
	got := addressesFromJSON(`[{"name":"A","address":"a@x.com"},{"name":"","address":"b@x.com"}]`)
	if len(got) != 2 || got[0] != "a@x.com" || got[1] != "b@x.com" {
		t.Errorf("addressesFromJSON = %v, want [a@x.com b@x.com]", got)
	}
	if addressesFromJSON("") != nil || addressesFromJSON("not json") != nil {
		t.Errorf("addressesFromJSON should return nil for empty/garbage")
	}
}

// PROTO-126 — a recipient value carrying an embedded newline must NOT be
// able to inject a second framework line (e.g. a fake "BCC:") into the
// approval dialog. SanitizePromptText keeps newlines, so the defense is
// per-field sanitization before assembly.
func TestSendPromptBody_NoNewlineInjection(t *testing.T) {
	pb := sendPromptBodyWithDeps(Deps{}, "mail_send")
	_, body := pb(json.RawMessage(`{"to":["real@y.com\nBCC: evil@x.com"],"subject":"hi\nTo: x@y","body_text":"a\nBCC: z@z"}`))

	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "BCC:") {
			t.Errorf("newline injection produced a fake BCC line:\n%s", body)
		}
		if strings.HasPrefix(line, "To:") && !strings.Contains(line, "real@y.com") {
			t.Errorf("injected a second To line:\n%s", body)
		}
	}
	// The evil address still appears — inline on the To line, as data.
	if !strings.Contains(body, "evil@x.com") {
		t.Errorf("expected the smuggled address to show inline as data:\n%s", body)
	}
}

// The reply dialog resolves the parent from the local mirror when there
// is no session, and computes reply-all recipients (+ extras).
func TestLookupReplyParentMirror(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	_, err = st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 'inbox', 0, '{}')`,
		"msg-1", "msg-1", "hi", "sender@proton.me", "Sender",
		`[{"name":"Me","address":"me@x.com"},{"name":"","address":"team@x.com"}]`,
		`[{"name":"","address":"cc@x.com"}]`,
	)
	if err != nil {
		t.Fatal(err)
	}

	deps := Deps{Store: st}
	p, ok := lookupReplyParent(deps, "msg-1")
	if !ok || p.Sender != "sender@proton.me" || p.Subject != "hi" {
		t.Fatalf("lookupReplyParent = %+v ok=%v", p, ok)
	}
	to, cc := replyRecipients(p, nil, false, nil, nil)
	if len(to) != 1 || to[0] != "sender@proton.me" || len(cc) != 0 {
		t.Errorf("reply: to=%v cc=%v", to, cc)
	}
	to, cc = replyRecipients(p, []string{"me@x.com"}, true, []string{"boss@y.com", "SENDER@proton.me"}, []string{"extra@z.com"})
	if strings.Join(to, ",") != "sender@proton.me,boss@y.com" {
		t.Errorf("reply-all to = %v", to)
	}
	if strings.Join(cc, ",") != "team@x.com,cc@x.com,extra@z.com" {
		t.Errorf("reply-all cc = %v (self must be dropped, extras appended)", cc)
	}
	if _, ok := lookupReplyParent(deps, "nope"); ok {
		t.Errorf("unknown message should not resolve")
	}
}
