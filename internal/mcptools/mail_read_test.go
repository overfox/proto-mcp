package mcptools

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func TestMailRead_DefaultsMetadataAndCacheHit(t *testing.T) {
	f := newFakeProton(t)
	id, attIDs := f.createMessageWithAttachments(t, "Q3 statement", "Your statement is attached.",
		fakeAttachment{Name: "q3.csv", MIME: "text/csv", Body: []byte("a,b\n")})
	tl := mailRead(f.deps())

	var first readResult
	callTool(t, tl, fmt.Sprintf(`{"message_id":%q}`, id), &first)
	if first.FromCache {
		t.Error("first read should not be from cache")
	}
	if first.HTML != "" {
		t.Error("default body_format must be text-only")
	}
	if !strings.Contains(first.Text, "Your statement is attached.") || !strings.Contains(first.Text, untrustedBodyBegin) {
		t.Errorf("text missing or unfenced: %q", first.Text)
	}
	if first.Truncated {
		t.Error("short body must not be truncated")
	}
	if len(first.To) != 1 || first.To[0].Address != "bob@example.com" {
		t.Errorf("to = %+v", first.To)
	}
	if len(first.Attachments) != 1 || first.Attachments[0].ID != attIDs[0] ||
		first.Attachments[0].Filename != "q3.csv" || first.Attachments[0].MIMEType != "text/csv" {
		t.Errorf("attachments = %+v", first.Attachments)
	}
	if first.MIMEType == "" {
		t.Error("mime_type missing on fresh read")
	}

	var second readResult
	callTool(t, tl, fmt.Sprintf(`{"message_id":%q}`, id), &second)
	if !second.FromCache {
		t.Fatal("second read should hit the cache")
	}
	if second.MIMEType != first.MIMEType {
		t.Errorf("cache hit dropped mime_type: %q vs %q", second.MIMEType, first.MIMEType)
	}
	if len(second.Attachments) != 1 || second.Attachments[0].Filename != "q3.csv" {
		t.Errorf("cache hit dropped attachments: %+v", second.Attachments)
	}
	if len(second.To) != 1 {
		t.Errorf("cache hit dropped to: %+v", second.To)
	}
}

func TestMailRead_MaxCharsTruncates(t *testing.T) {
	f := newFakeProton(t)
	body := strings.Repeat("abcdefghij", 100) // 1000 chars
	id, _ := f.createMessageWithAttachments(t, "long", body)
	tl := mailRead(f.deps())

	var out readResult
	callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"max_chars":25}`, id), &out)
	if !out.Truncated {
		t.Fatal("expected truncated=true")
	}
	if !strings.Contains(out.Text, "abcdefghijabcdefghijabcde\n"+untrustedBodyEnd) {
		t.Errorf("truncation must happen inside the fence, got %q", out.Text)
	}
	if strings.Contains(out.Text, "abcdefghijabcdefghijabcdef") {
		t.Error("text exceeds max_chars")
	}

	// Above the hard ceiling clamps rather than erroring.
	var big readResult
	callTool(t, tl, fmt.Sprintf(`{"message_id":%q,"max_chars":999999999}`, id), &big)
	if big.Truncated {
		t.Error("1000-char body should fit under the clamped ceiling")
	}
}

func TestMailRead_LegacyCacheWithoutAttachmentMetaRefetches(t *testing.T) {
	f := newFakeProton(t)
	id, _ := f.createMessageWithAttachments(t, "with att", "x",
		fakeAttachment{Name: "a.txt", MIME: "text/plain", Body: []byte("hi")})
	// Simulate a body cached before attachment metadata was stored.
	if err := f.st.SetCachedBody(context.Background(), id, store.CachedBody{Text: "stale"}); err != nil {
		t.Fatal(err)
	}
	var out readResult
	callTool(t, mailRead(f.deps()), fmt.Sprintf(`{"message_id":%q}`, id), &out)
	if out.FromCache || len(out.Attachments) != 1 {
		t.Errorf("expected refetch with attachments, got from_cache=%v atts=%+v", out.FromCache, out.Attachments)
	}
}

func TestMailReadThread_CapsAndSnippets(t *testing.T) {
	f := newFakeProton(t)
	ctx := context.Background()
	a, _ := f.createMessageWithAttachments(t, "Hearing", strings.Repeat("first message ", 50))
	b, _ := f.createMessageWithAttachments(t, "Re: Hearing", "short reply")
	for _, id := range []string{a, b} {
		m, err := f.st.GetMessage(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		m.ThreadID = "thread-1"
		if err := f.st.UpsertMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	// Warm the body cache so the mirror has snippets.
	for _, id := range []string{a, b} {
		callTool(t, mailRead(f.deps()), fmt.Sprintf(`{"message_id":%q}`, id), nil)
	}

	var out struct {
		Messages []readResult `json:"messages"`
	}
	callTool(t, mailReadThread(f.deps()), `{"thread_id":"thread-1","max_chars_per_message":20}`, &out)
	if len(out.Messages) != 2 {
		t.Fatalf("got %d messages", len(out.Messages))
	}
	var sawTrunc, sawWhole bool
	for _, m := range out.Messages {
		if m.Snippet == "" {
			t.Errorf("%s: missing snippet", m.MessageID)
		}
		if m.HTML != "" {
			t.Errorf("%s: thread default should be text-only", m.MessageID)
		}
		if m.MessageID == a && m.Truncated {
			sawTrunc = true
		}
		if m.MessageID == b && !m.Truncated && strings.Contains(m.Text, "short reply") {
			sawWhole = true
		}
	}
	if !sawTrunc || !sawWhole {
		t.Errorf("per-message truncation flags wrong: %+v", out.Messages)
	}

	// Metadata-only listing still carries snippets.
	var meta struct {
		Messages []readResult `json:"messages"`
	}
	callTool(t, mailReadThread(f.deps()), `{"thread_id":"thread-1","include_bodies":false}`, &meta)
	for _, m := range meta.Messages {
		if m.Text != "" || m.Snippet == "" {
			t.Errorf("include_bodies=false: %+v", m)
		}
	}
}
