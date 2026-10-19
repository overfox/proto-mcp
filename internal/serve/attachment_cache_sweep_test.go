package serve

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// SECURITY M1: the startup hook sweeps the attachment cache and the
// staging ticker repeats it once a day.
func TestAttachmentCacheSweep_StartupAndDaily(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	t.Cleanup(func() {
		attachmentCacheSweeper.mu.Lock()
		attachmentCacheSweeper.st, attachmentCacheSweeper.last = nil, time.Time{}
		attachmentCacheSweeper.mu.Unlock()
	})
	if _, err := st.DB.Exec(`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES ('m', 'm', 's', 'x@y', 'X', '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(id string, cachedAt time.Time) {
		t.Helper()
		if err := st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
			MessageID: "m", AttachmentID: id, Filename: id, MIMEType: "x", SizeBytes: 1, Content: []byte("x"), CachedAt: cachedAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	present := func(id string) bool {
		_, err := st.GetCachedAttachment(ctx, "m", id)
		return err == nil
	}
	put("old", now.Add(-8*24*time.Hour))
	put("new", now.Add(-time.Hour))

	if _, err := SweepStaleBodies(ctx, st); err != nil {
		t.Fatal(err)
	}
	if present("old") || !present("new") {
		t.Fatalf("startup sweep: old=%v new=%v, want old purged (7-day retention)", present("old"), present("new"))
	}

	// "aging" passes the 7-day mark within the hour, but the ticker only
	// sweeps once a day: it survives the hourly tick, not the daily one.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	put("aging", now.Add(-7*24*time.Hour+30*time.Minute))
	sweepAttachmentCacheIfDue(ctx, logger, now.Add(time.Hour))
	if !present("aging") {
		t.Fatal("swept again before the daily interval")
	}
	sweepAttachmentCacheIfDue(ctx, logger, now.Add(25*time.Hour))
	if present("aging") {
		t.Fatal("daily sweep did not purge an expired row")
	}
}
