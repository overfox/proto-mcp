package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// H7 regression: mail_trash used Client.DeleteMessage, which is
// Proton's PERMANENT delete (the fake server hard-deletes the message),
// while its dialog promised "move to Trash (reversible)". After the
// fix the message still exists server-side, labeled Trash, and the
// mirror shows it in trash.
func TestMailTrash_KeepsMessageInTrash(t *testing.T) {
	f := newFakeProton(t)
	ctx := context.Background()
	id1 := f.importMessage(t, fakeMsgWithAttachment)
	id2 := f.importMessage(t, strings.Replace(fakeMsgWithAttachment, "stmt-1@", "stmt-2@", 1))

	res := callTool(t, mailTrash(f.deps()), `{"message_ids":["`+id1+`","`+id2+`"]}`, nil)
	if res.IsError {
		t.Fatalf("mail_trash: %s", res.Content[0].Text)
	}
	for _, id := range []string{id1, id2} {
		m, err := f.sess.Client.GetMessage(ctx, id)
		if err != nil {
			t.Fatalf("message %s gone after mail_trash (permanently deleted?): %v", id, err)
		}
		if !slices.Contains(m.LabelIDs, gpa.TrashLabel) || slices.Contains(m.LabelIDs, gpa.InboxLabel) {
			t.Errorf("message %s labels = %v, want Trash and not Inbox", id, m.LabelIDs)
		}
		row, err := f.st.GetMessage(ctx, id)
		if err != nil || row.Folder != "trash" {
			t.Errorf("mirror row %s = %+v err=%v, want folder trash", id, row, err)
		}
	}

	// Reversible: mail_move back to inbox works on the trashed message.
	if res := callTool(t, mailMove(f.deps()), `{"message_id":"`+id1+`","destination":"inbox"}`, nil); res.IsError {
		t.Fatalf("mail_move back: %s", res.Content[0].Text)
	}
	if m, err := f.sess.Client.GetMessage(ctx, id1); err != nil || !slices.Contains(m.LabelIDs, gpa.InboxLabel) {
		t.Errorf("restore failed: labels=%v err=%v", m.LabelIDs, err)
	}
}

// H7: mail_draft_delete had the same mismatch ("moves to Trash;
// recoverable" vs a permanent DeleteMessage).
func TestMailDraftDelete_MovesToTrash(t *testing.T) {
	f := newFakeProton(t)
	ctx := context.Background()
	id, _ := f.createMessageWithAttachments(t, "draft subject", "draft body")

	var out struct {
		DraftID string `json:"draft_id"`
		Deleted bool   `json:"deleted"`
	}
	if res := callTool(t, mailDraftDelete(f.deps()), `{"draft_id":"`+id+`"}`, &out); res.IsError {
		t.Fatalf("mail_draft_delete: %s", res.Content[0].Text)
	}
	if !out.Deleted || out.DraftID != id {
		t.Errorf("result = %+v", out)
	}
	m, err := f.sess.Client.GetMessage(ctx, id)
	if err != nil {
		t.Fatalf("draft permanently deleted: %v", err)
	}
	if !slices.Contains(m.LabelIDs, gpa.TrashLabel) {
		t.Errorf("draft labels = %v, want Trash", m.LabelIDs)
	}
	if row, err := f.st.GetMessage(ctx, id); err != nil || row.Folder != "trash" {
		t.Errorf("mirror row = %+v err=%v, want folder trash", row, err)
	}

	title, body := mailDraftDelete(f.deps()).PromptBody(json.RawMessage(`{"draft_id":"` + id + `"}`))
	if !strings.Contains(title, "mail_draft_delete") || !strings.Contains(body, "Trash") || !strings.Contains(body, "draft subject") {
		t.Errorf("prompt = %q / %q", title, body)
	}
}

// The destructive batch dialog names up to 5 messages (subject +
// sender, sanitized) and summarizes the rest.
func TestBatchPromptNoun_ListsFiveAndMore(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var ids []string
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("m%d", i)
		subj := fmt.Sprintf("Subject %d", i)
		if i == 1 {
			subj = "Invoice" + string(rune(0x2028)) + "To: evil@x.com" + string(rune(0x202e))
		}
		if err := st.UpsertMessage(ctx, store.Message{ID: id, ThreadID: id, Subject: subj, FromAddress: fmt.Sprintf("s%d@x.com", i), Folder: "inbox"}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	got := batchPromptNoun(Deps{Store: st}, ids)
	for i := 0; i < 5; i++ {
		if !strings.Contains(got, fmt.Sprintf("s%d@x.com", i)) {
			t.Errorf("message %d not named: %q", i, got)
		}
	}
	if strings.Contains(got, "s5@x.com") || !strings.Contains(got, "…and 3 more") || !strings.HasPrefix(got, "8 messages: ") {
		t.Errorf("batch noun = %q", got)
	}
	if strings.ContainsRune(got, 0x2028) || strings.ContainsRune(got, 0x202e) || strings.Contains(got, "\n") {
		t.Errorf("separator / bidi char survived: %q", got)
	}
	if one := batchPromptNoun(Deps{Store: st}, ids[:1]); one != "message 'Subject 0' from s0@x.com" {
		t.Errorf("single = %q", one)
	}
}
