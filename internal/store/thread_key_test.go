package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestThreadKeyFromRaw(t *testing.T) {
	cases := map[string]string{
		`{"ExternalID":"<root@mail.example>"}`: "root@mail.example",
		`{"ExternalID":" abc@x "}`:             "abc@x",
		`{"ExternalID":""}`:                    "",
		`{"ID":"x"}`:                           "",
		`{"truncated":true}`:                   "",
		``:                                     "",
		`not json`:                             "",
	}
	for raw, want := range cases {
		if got := ThreadKeyFromRaw(raw); got != want {
			t.Errorf("ThreadKeyFromRaw(%q) = %q, want %q", raw, got, want)
		}
	}
}

func threadOf(t *testing.T, s *Store, id string) string {
	t.Helper()
	m, err := s.GetMessage(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return m.ThreadID
}

func TestUpsertKeysThreadByMessageID(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	d := time.Unix(1_700_000_000, 0)

	// Sync-shaped upserts: ThreadID defaults to the Proton id.
	root := Message{ID: "p-root", ThreadID: "p-root", Date: d, RawJSON: `{"ExternalID":"<root@x>"}`}
	reply := Message{ID: "p-reply", ThreadID: "p-reply", Date: d.Add(time.Hour), RawJSON: `{"ExternalID":"reply@x"}`}
	noExt := Message{ID: "p-draft", ThreadID: "p-draft", Date: d, RawJSON: `{"ExternalID":""}`}
	for _, m := range []Message{root, reply, noExt} {
		if err := s.UpsertMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if got := threadOf(t, s, "p-root"); got != "root@x" {
		t.Errorf("root thread = %q, want its Message-ID", got)
	}
	if got := threadOf(t, s, "p-draft"); got != "p-draft" {
		t.Errorf("no ExternalID should fall back to the Proton id, got %q", got)
	}

	// mail_read decrypts the reply: References[0] = root's Message-ID.
	if err := s.SetCachedBody(ctx, "p-reply", CachedBody{Text: "re", ThreadID: "root@x"}); err != nil {
		t.Fatal(err)
	}
	hits, err := s.Search(ctx, "", SearchOpts{Filter: ListFilter{ThreadID: "root@x"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 {
		t.Fatalf("thread root@x has %d messages, want 2", len(hits))
	}

	// A later sync update (default thread id) must not undo that.
	reply.Subject = "Re: updated flags"
	if err := s.UpsertMessage(ctx, reply); err != nil {
		t.Fatal(err)
	}
	if got := threadOf(t, s, "p-reply"); got != "root@x" {
		t.Errorf("re-sync clobbered header-derived thread: %q", got)
	}

	// An explicit caller-chosen thread id still wins.
	reply.ThreadID = "manual"
	if err := s.UpsertMessage(ctx, reply); err != nil {
		t.Fatal(err)
	}
	if got := threadOf(t, s, "p-reply"); got != "manual" {
		t.Errorf("explicit thread id ignored: %q", got)
	}
}

func TestMigration0007RekeysLegacyRows(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	// Legacy rows written before keying: thread_id = id.
	for _, q := range []string{
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, folder, size_bytes, date, raw_json) VALUES ('a', 'a', '', '', '', '[]', '[]', '', 0, 1, '{"ExternalID":"<a@x>"}')`,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, folder, size_bytes, date, raw_json) VALUES ('b', 'b', '', '', '', '[]', '[]', '', 0, 1, '{"ExternalID":""}')`,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, folder, size_bytes, date, raw_json) VALUES ('c', 'root@x', '', '', '', '[]', '[]', '', 0, 1, '{"ExternalID":"c@x"}')`,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, folder, size_bytes, date, raw_json) VALUES ('d', 'd', '', '', '', '[]', '[]', '', 0, 1, 'not json')`,
	} {
		if _, err := s.DB.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := migrationFS.ReadFile("migrations/0007_thread_key_from_message_id.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(raw)
	up = up[strings.Index(up, "-- +goose Up")+len("-- +goose Up") : strings.Index(up, "-- +goose Down")]
	if _, err := s.DB.ExecContext(ctx, up); err != nil {
		t.Fatalf("migration up: %v", err)
	}
	for id, want := range map[string]string{"a": "a@x", "b": "b", "c": "root@x", "d": "d"} {
		if got := threadOf(t, s, id); got != want {
			t.Errorf("%s: thread_id = %q, want %q", id, got, want)
		}
	}
}
