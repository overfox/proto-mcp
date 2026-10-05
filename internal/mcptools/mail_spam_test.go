package mcptools

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestMailReportSpam(t *testing.T) {
	f := newFakeProton(t)
	ctx := context.Background()
	a := f.importMessage(t, fakeMsgWithAttachment)
	b := f.importMessage(t, strings.Replace(fakeMsgWithAttachment, "stmt-1", "stmt-2", 1))

	tl := mailReportSpam(f.deps())
	title, body := tl.PromptBody([]byte(fmt.Sprintf(`{"message_ids":[%q,%q]}`, a, b)))
	if !strings.Contains(title, "mail_report_spam") || !strings.Contains(body, "2 messages") {
		t.Errorf("prompt = %q / %q", title, body)
	}

	var res stateActionResult
	callTool(t, tl, fmt.Sprintf(`{"message_ids":[%q,%q]}`, a, b), &res)
	if res.Count != 2 || res.Action != "reported_spam" || res.Warning != "" {
		t.Errorf("result = %+v", res)
	}
	for _, id := range []string{a, b} {
		m, err := f.sess.Client.GetMessage(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(m.LabelIDs, gpa.SpamLabel) || slices.Contains(m.LabelIDs, gpa.InboxLabel) {
			t.Errorf("%s labels = %v, want in spam, out of inbox", id, m.LabelIDs)
		}
		if row, _ := f.st.GetMessage(ctx, id); row.Folder != "spam" {
			t.Errorf("%s mirror folder = %q", id, row.Folder)
		}
	}
}
