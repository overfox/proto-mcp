package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// SECURITY M1 regression tests: the decrypted attachment cache is
// purged by age and size, purged bodies leave the FTS index, the
// deleted plaintext is gone from the files on disk, and the database
// is excluded from Time Machine.

func TestSweepAttachmentCache_AgeAndSize(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "m")
	now := time.Now().UTC()
	put := func(id string, age time.Duration, size int) {
		t.Helper()
		if err := st.SetAttachmentCache(ctx, AttachmentCacheRow{
			MessageID: "m", AttachmentID: id, Filename: id, MIMEType: "x",
			SizeBytes: int64(size), Content: bytes.Repeat([]byte("x"), size), CachedAt: now.Add(-age),
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("month-old", 30*24*time.Hour, 10)
	put("eight-days", 8*24*time.Hour, 10)
	put("three-days", 3*24*time.Hour, 600)
	put("two-days", 2*24*time.Hour, 300)
	put("today", time.Hour, 300)

	stats, err := st.SweepAttachmentCache(ctx, now, DefaultAttachmentRetention, 700)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Expired != 2 || stats.Evicted != 1 {
		t.Errorf("stats = %+v, want 2 expired (>7d) + 1 evicted (oldest over the cap)", stats)
	}
	for id, want := range map[string]bool{
		"month-old": false, "eight-days": false, "three-days": false, "two-days": true, "today": true,
	} {
		_, err := st.GetCachedAttachment(ctx, "m", id)
		if got := err == nil; got != want {
			t.Errorf("%s present = %v, want %v (err %v)", id, got, want, err)
		}
	}
	if DefaultAttachmentRetention != 7*24*time.Hour || DefaultAttachmentCacheMaxBytes != 256<<20 {
		t.Errorf("defaults = %v / %d, want 7d / 256 MiB", DefaultAttachmentRetention, DefaultAttachmentCacheMaxBytes)
	}
}

// fileBytes returns store.db plus its WAL, as an attacker with the disk
// (or a backup) would see them.
func fileBytes(t *testing.T, st *Store) []byte {
	t.Helper()
	var all []byte
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(st.Path + suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}

func TestSweepAttachmentCache_PlaintextGoneFromDisk(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedMessage(t, st, "m")
	secret := []byte("ATTACHMENT-PLAINTEXT-7f3a9c")
	content := bytes.Repeat(secret, 200)
	if err := st.SetAttachmentCache(ctx, AttachmentCacheRow{
		MessageID: "m", AttachmentID: "a", Filename: "a", MIMEType: "x",
		SizeBytes: int64(len(content)), Content: content, CachedAt: time.Now().Add(-10 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fileBytes(t, st), secret) {
		t.Fatal("precondition: plaintext not found on disk before the sweep")
	}
	if _, err := st.SweepAttachmentCache(ctx, time.Now(), DefaultAttachmentRetention, DefaultAttachmentCacheMaxBytes); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fileBytes(t, st), secret) {
		t.Error("purged attachment plaintext still present in store.db / WAL")
	}
}

// Purged bodies must leave messages_fts: no MATCH hit and no token
// left in the index's segment blobs (FTS5 secure-delete).
func TestPurgeOlderThan_ClearsFTS(t *testing.T) {
	ctx := context.Background()
	s := newPurgeStore(t)
	now := time.Now().UTC()
	if err := s.UpsertMessage(ctx, Message{ID: "old", ThreadID: "old", Subject: "s", Date: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	const token = "qzxvwplmk"
	if err := s.SetCachedBody(ctx, "old", CachedBody{Text: "the code is " + token, CachedAt: now.Add(-60 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		var n int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH ?`, token).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() != 1 {
		t.Fatal("precondition: body not indexed")
	}
	if _, err := s.PurgeOlderThan(ctx, now.Add(-DefaultBodyRetention)); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Errorf("FTS still matches purged body (%d rows)", n)
	}
	var blobs int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM messages_fts_data WHERE instr(block, ?) > 0`, token).Scan(&blobs); err != nil {
		t.Fatal(err)
	}
	if blobs != 0 {
		t.Errorf("purged token still present in %d FTS segment blobs", blobs)
	}
	if err := s.Compact(ctx); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fileBytes(t, s), []byte(token)) {
		t.Error("purged body token still present in store.db / WAL")
	}
}

func TestOpen_ExcludesFromTimeMachine(t *testing.T) {
	st := newTestStore(t)
	for _, suffix := range []string{"", "-wal"} {
		buf := make([]byte, 128)
		n, err := unix.Getxattr(st.Path+suffix, backupExcludeXattr, buf)
		if err != nil {
			t.Fatalf("%s: xattr missing: %v", suffix, err)
		}
		if !strings.Contains(string(buf[:n]), "com.apple.backupd") {
			t.Errorf("%s: xattr = %q", suffix, buf[:n])
		}
	}
}
