package store

import (
	"context"
	"testing"
	"time"
)

func TestBodyCacheCarriesMetadata(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	in := CachedBody{
		Text:       "t",
		MIMEType:   "text/html",
		References: []string{"root@x", "mid@x"},
		Attachments: []AttachmentMeta{
			{ID: "a1", Name: "q3.pdf", MIMEType: "application/pdf", Size: 1234},
			{ID: "a2", Name: "logo.png", MIMEType: "image/png", Size: 10, Inline: true},
		},
	}
	if err := s.SetCachedBody(ctx, "m1", in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCachedBody(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MIMEType != "text/html" || len(got.References) != 2 || got.References[0] != "root@x" {
		t.Errorf("mime/refs lost: %+v", got)
	}
	if len(got.Attachments) != 2 || got.Attachments[0].Name != "q3.pdf" || !got.Attachments[1].Inline {
		t.Errorf("attachments lost: %+v", got.Attachments)
	}

	// Purge clears the metadata with the body.
	if _, err := s.PurgeOlderThan(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var mime, refs, atts *string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT body_mime_type, body_references, body_attachments FROM messages WHERE id='m1'`,
	).Scan(&mime, &refs, &atts); err != nil {
		t.Fatal(err)
	}
	if mime != nil || refs != nil || atts != nil {
		t.Errorf("purge left metadata behind: %v %v %v", mime, refs, atts)
	}
}

func TestBodyCacheNoMetadataStoresNull(t *testing.T) {
	s := mustOpen(t)
	ctx := context.Background()
	if err := s.UpsertMessage(ctx, Message{ID: "m1", ThreadID: "m1", Date: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCachedBody(ctx, "m1", CachedBody{Text: "t"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCachedBody(ctx, "m1")
	if err != nil {
		t.Fatal(err)
	}
	if got.MIMEType != "" || got.References != nil || got.Attachments != nil {
		t.Errorf("expected empty metadata, got %+v", got)
	}
}
