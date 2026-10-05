package store

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeSubject(t *testing.T) {
	cases := map[string]string{
		"Re: Hearing":              "hearing",
		"RE: Fwd: AW: Hearing":     "hearing",
		"Re[2]: Hearing  schedule": "hearing schedule",
		"Hearing":                  "hearing",
		"Regarding: x":             "regarding: x",
		"":                         "",
	}
	for in, want := range cases {
		if got := NormalizeSubject(in); got != want {
			t.Errorf("NormalizeSubject(%q) = %q, want %q", in, got, want)
		}
	}
}

func seedTriage(t *testing.T, s *Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	day := 24 * time.Hour
	msgs := []struct {
		m      Message
		labels []string
	}{
		// Sent 10 days ago, replied in-thread → not awaiting.
		{Message{ID: "s1", ThreadID: "t1", Subject: "Term sheet", Folder: "sent", Date: now.Add(-10 * day),
			ToJSON: `[{"address":"cfo@target.example"}]`}, []string{"2", "7"}},
		{Message{ID: "r1", ThreadID: "t1", Subject: "Re: Term sheet", Folder: "inbox", Date: now.Add(-9 * day),
			FromAddress: "cfo@target.example"}, []string{"0"}},
		// Sent 6 days ago, reply not threaded but same subject from recipient → not awaiting.
		{Message{ID: "s2", ThreadID: "t2", Subject: "Board pack", Folder: "sent", Date: now.Add(-6 * day),
			ToJSON: `[{"address":"Chair@Company.example"}]`}, []string{"2", "7"}},
		{Message{ID: "r2", ThreadID: "r2", Subject: "AW: Board pack", Folder: "inbox", Date: now.Add(-5 * day),
			FromAddress: "chair@company.example"}, []string{"0"}},
		// Sent 5 days ago, no reply → awaiting.
		{Message{ID: "s3", ThreadID: "t3", Subject: "Arbitration fee", Folder: "sent", Date: now.Add(-5 * day),
			ToJSON: `[{"address":"clerk@lawfirm.ch"}]`, CcJSON: `[{"address":"me@proton.me"}]`}, []string{"2", "7"}},
		// Earlier message in same thread t3 → only latest listed.
		{Message{ID: "s3a", ThreadID: "t3", Subject: "Arbitration fee", Folder: "sent", Date: now.Add(-8 * day),
			ToJSON: `[{"address":"clerk@lawfirm.ch"}]`}, []string{"2", "7"}},
		// Sent 1 day ago → too recent for days=3.
		{Message{ID: "s4", ThreadID: "t4", Subject: "Hello", Folder: "sent", Date: now.Add(-1 * day),
			ToJSON: `[{"address":"x@y.example"}]`}, []string{"2", "7"}},
		// Archived sent message (folder archive, still AllSent) → awaiting.
		{Message{ID: "s5", ThreadID: "t5", Subject: "KYC documents", Folder: "archive", Date: now.Add(-20 * day),
			ToJSON: `[{"address":"kyc@juliusbaer.com"}]`}, []string{"2", "6"}},
		// Incoming, recent, labelled.
		{Message{ID: "i1", ThreadID: "i1", Subject: "Statement", Folder: "inbox", Date: now.Add(-2 * time.Hour),
			FromAddress: "noreply@juliusbaer.com", FromName: "Julius Baer", Unread: true}, []string{"0", "L-bank"}},
		{Message{ID: "i2", ThreadID: "i2", Subject: "Trade confirm", Folder: "inbox", Date: now.Add(-1 * time.Hour),
			FromAddress: "noreply@juliusbaer.com"}, []string{"0", "L-bank", "L-todo"}},
		{Message{ID: "i3", ThreadID: "i3", Subject: "Newsletter", Folder: "inbox", Date: now.Add(-3 * time.Hour),
			FromAddress: "news@example.com", Unread: true}, []string{"0"}},
		{Message{ID: "spam1", ThreadID: "spam1", Subject: "WIN", Folder: "spam", Date: now.Add(-1 * time.Hour),
			FromAddress: "x@spam.example"}, []string{"4"}},
		{Message{ID: "d1", ThreadID: "d1", Subject: "draft", Folder: "drafts", Date: now.Add(-1 * time.Hour)}, []string{"1", "8"}},
	}
	for _, x := range msgs {
		if err := s.UpsertMessage(ctx, x.m); err != nil {
			t.Fatal(err)
		}
		if err := s.SetMessageLabels(ctx, x.m.ID, x.labels); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range []Label{{ID: "L-bank", Name: "Bank", Type: 1}, {ID: "L-todo", Name: "To do", Type: 1}} {
		if err := s.UpsertLabel(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetCachedBody(ctx, "i1", CachedBody{Text: "Your monthly statement is ready."}); err != nil {
		t.Fatal(err)
	}
}

func TestDigestSince(t *testing.T) {
	s := mustOpen(t)
	now := time.Now().UTC()
	seedTriage(t, s, now)
	rows, truncated, err := s.DigestSince(context.Background(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("unexpected truncation")
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.MessageID)
	}
	if len(got) != 3 || got[0] != "i2" || got[1] != "i1" || got[2] != "i3" {
		t.Fatalf("digest rows = %v, want [i2 i1 i3] (no spam/draft/sent)", got)
	}
	if len(rows[0].Labels) != 2 || rows[1].Snippet == "" || len(rows[2].Labels) != 0 {
		t.Errorf("labels/snippets wrong: %+v", rows)
	}
}

func TestSentAndLaterIncoming(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedTriage(t, s, now)
	sent, err := s.SentBetween(ctx, now.Add(-60*24*time.Hour), now.Add(-3*24*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]SentMessage{}
	for _, m := range sent {
		ids[m.MessageID] = m
	}
	for _, want := range []string{"s1", "s2", "s3", "s3a", "s5"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("SentBetween missing %s", want)
		}
	}
	if _, ok := ids["s4"]; ok {
		t.Error("s4 is too recent")
	}
	check := func(id string, want bool) {
		m := ids[id]
		got, err := s.HasLaterIncoming(ctx, m.ThreadID, m.Date, m.Recipients, NormalizeSubject(m.Subject))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("HasLaterIncoming(%s) = %v, want %v", id, got, want)
		}
	}
	check("s1", true)  // same thread
	check("s2", true)  // subject + sender fallback (case-insensitive address)
	check("s3", false) // nothing
	check("s5", false)
}
