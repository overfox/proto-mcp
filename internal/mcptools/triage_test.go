package mcptools

import (
	"context"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func triageStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	day := 24 * time.Hour
	rows := []struct {
		m      store.Message
		labels []string
	}{
		{store.Message{ID: "i1", Subject: "Statement", Folder: "inbox", Date: now.Add(-2 * time.Hour),
			FromAddress: "noreply@juliusbaer.com", FromName: "Julius Baer", Unread: true}, []string{"0", "L-bank"}},
		{store.Message{ID: "i2", Subject: "Trade confirm", Folder: "inbox", Date: now.Add(-1 * time.Hour),
			FromAddress: "noreply@juliusbaer.com", FromName: "Julius Baer"}, []string{"0", "L-bank"}},
		{store.Message{ID: "i3", Subject: "Newsletter", Folder: "inbox", Date: now.Add(-3 * time.Hour),
			FromAddress: "news@example.com", Unread: true}, []string{"0"}},
		{store.Message{ID: "old", Subject: "Old", Folder: "inbox", Date: now.Add(-5 * day),
			FromAddress: "news@example.com"}, []string{"0"}},
		{store.Message{ID: "s1", ThreadID: "t1", Subject: "Fee note", Folder: "sent", Date: now.Add(-5 * day),
			ToJSON: `[{"address":"clerk@lawfirm.ch"}]`}, []string{"2", "7"}},
		{store.Message{ID: "s2", ThreadID: "t2", Subject: "Self note", Folder: "sent", Date: now.Add(-5 * day),
			ToJSON: `[{"address":"alice@proton.local"}]`}, []string{"2", "7"}},
	}
	for _, r := range rows {
		if r.m.ThreadID == "" {
			r.m.ThreadID = r.m.ID
		}
		if err := st.UpsertMessage(ctx, r.m); err != nil {
			t.Fatal(err)
		}
		if err := st.SetMessageLabels(ctx, r.m.ID, r.labels); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertLabel(ctx, store.Label{ID: "L-bank", Name: "Bank", Type: 1}); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestMailDigest(t *testing.T) {
	st := triageStore(t)
	var out struct {
		Total    int           `json:"total"`
		Unread   int           `json:"unread"`
		BySender []digestGroup `json:"by_sender"`
		ByLabel  []digestGroup `json:"by_label"`
	}
	res := callTool(t, mailDigest(Deps{Store: st}), `{"since":"24h","max_per_group":1}`, &out)
	if res.IsError {
		t.Fatal(res.Content[0].Text)
	}
	if out.Total != 3 || out.Unread != 2 {
		t.Errorf("totals = %d/%d, want 3/2", out.Total, out.Unread)
	}
	if len(out.BySender) != 2 || out.BySender[0].Key != "noreply@juliusbaer.com" || out.BySender[0].Count != 2 ||
		len(out.BySender[0].Messages) != 1 || out.BySender[0].Messages[0].MessageID != "i2" {
		t.Errorf("by_sender = %+v", out.BySender)
	}
	if len(out.ByLabel) != 2 || out.ByLabel[0].Name != "Bank" || out.ByLabel[1].Name != "(no label)" {
		t.Errorf("by_label = %+v", out.ByLabel)
	}

	// Day-count and date forms; bad input is invalid params.
	callTool(t, mailDigest(Deps{Store: st}), `{"since":"7d"}`, &out)
	if out.Total != 4 {
		t.Errorf("7d total = %d, want 4", out.Total)
	}
	if _, err := mailDigest(Deps{Store: st}).Handler(mcpCtx(), []byte(`{"since":"yesterday-ish"}`)); err == nil {
		t.Error("bad since should be invalid params")
	}
}

func TestMailAwaitingReply(t *testing.T) {
	st := triageStore(t)
	f := newFakeProton(t) // provides own addresses (alice@proton.local)
	deps := Deps{Store: st, Session: f.sess}
	var out struct {
		Messages []struct {
			MessageID   string   `json:"message_id"`
			To          []string `json:"to"`
			DaysWaiting int      `json:"days_waiting"`
		} `json:"messages"`
	}
	callTool(t, mailAwaitingReply(deps), `{"days":3}`, &out)
	if len(out.Messages) != 1 || out.Messages[0].MessageID != "s1" || out.Messages[0].DaysWaiting != 5 {
		t.Errorf("awaiting = %+v (self-addressed mail must be skipped)", out.Messages)
	}
	callTool(t, mailAwaitingReply(deps), `{"days":6}`, &out)
	if len(out.Messages) != 0 {
		t.Errorf("days=6 should exclude 5-day-old mail: %+v", out.Messages)
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"2026-10-01":           time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		"2026-10-04T08:00:00Z": time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC),
		"36h":                  now.Add(-36 * time.Hour),
		"7d":                   now.Add(-7 * 24 * time.Hour),
	} {
		got, err := parseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-5h", "0d", "soon"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("parseSince(%q) should fail", bad)
		}
	}
}
