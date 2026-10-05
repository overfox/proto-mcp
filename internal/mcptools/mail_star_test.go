package mcptools

import (
	"context"
	"fmt"
	"slices"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestMailStarUnstar_BatchServerAndMirror(t *testing.T) {
	f := newFakeProton(t)
	ctx := context.Background()
	a, _ := f.createMessageWithAttachments(t, "one", "x")
	b, _ := f.createMessageWithAttachments(t, "two", "y")

	var res stateActionResult
	callTool(t, mailStar(f.deps()), fmt.Sprintf(`{"message_ids":[%q,%q]}`, a, b), &res)
	if res.Count != 2 || res.Action != "starred" {
		t.Errorf("result = %+v", res)
	}
	for _, id := range []string{a, b} {
		m, err := f.sess.Client.GetMessage(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(m.LabelIDs, gpa.StarredLabel) {
			t.Errorf("%s not starred server-side: %v", id, m.LabelIDs)
		}
		row, _ := f.st.GetMessage(ctx, id)
		if !row.Starred {
			t.Errorf("%s mirror not starred", id)
		}
	}

	// mail_search is:starred and the list summaries see it.
	var list listResult
	callTool(t, mailSearch(f.deps()), `{"query":"is:starred"}`, &list)
	if len(list.Messages) != 2 || !list.Messages[0].Starred {
		t.Errorf("is:starred search = %+v", list.Messages)
	}

	callTool(t, mailUnstar(f.deps()), fmt.Sprintf(`{"message_id":%q}`, a), &res)
	if res.MessageID != a || res.Action != "unstarred" {
		t.Errorf("unstar result = %+v", res)
	}
	m, _ := f.sess.Client.GetMessage(ctx, a)
	if slices.Contains(m.LabelIDs, gpa.StarredLabel) {
		t.Error("still starred server-side")
	}
	if row, _ := f.st.GetMessage(ctx, a); row.Starred {
		t.Error("mirror still starred")
	}
}

func TestMailStar_Validation(t *testing.T) {
	f := newFakeProton(t)
	for _, raw := range []string{`{}`, `{"message_id":"a","message_ids":["b"]}`} {
		if _, err := mailStar(f.deps()).Handler(mcpCtx(), []byte(raw)); err == nil {
			t.Errorf("%s: expected invalid params", raw)
		}
	}
}
