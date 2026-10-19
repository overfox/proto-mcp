package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AttachmentCacheRow is the in-Go representation of one row in the
// attachment_cache table. Phase 8/A. internal/proton's
// FetchAndDecryptAttachment writes; internal/mcptools'
// mail_download_attachment reads.
//
// Filename is the SANITIZED form (sanitize.Filename has run before
// the row hits this layer). Content is plaintext bytes — same D13/
// C-1 plaintext-at-rest posture as body_text/body_html. The
// `secure_delete=on` pragma covers post-purge erasure.
type AttachmentCacheRow struct {
	MessageID    string
	AttachmentID string
	Filename     string
	MIMEType     string
	SizeBytes    int64
	Content      []byte
	CachedAt     time.Time
}

// AttachmentCacheMeta is the per-row metadata without the content
// bytes — useful for purge stats / size accounting without paying
// the BLOB read cost.
type AttachmentCacheMeta struct {
	MessageID    string
	AttachmentID string
	Filename     string
	MIMEType     string
	SizeBytes    int64
	CachedAt     time.Time
}

// ErrAttachmentNotCached is returned by GetCachedAttachment when
// the (message_id, attachment_id) pair has no cached entry.
// Caller's signal to fetch from Proton.
var ErrAttachmentNotCached = errors.New("store: attachment not cached")

// SetAttachmentCache upserts one cached attachment. Called by
// mail_download_attachment after a successful Proton fetch +
// decrypt.
//
// cached_at is set to now() server-side (Go's clock; SQLite has no
// notion of the host time). updated_at is implicit via cached_at —
// this table doesn't distinguish first-write from rewrite.
func (s *Store) SetAttachmentCache(ctx context.Context, row AttachmentCacheRow) error {
	if row.MessageID == "" || row.AttachmentID == "" {
		return errors.New("store: SetAttachmentCache requires non-empty message_id and attachment_id")
	}
	cachedAt := row.CachedAt
	if cachedAt.IsZero() {
		cachedAt = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO attachment_cache
    (message_id, attachment_id, filename, mime_type, size_bytes, content, cached_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(message_id, attachment_id) DO UPDATE SET
    filename   = excluded.filename,
    mime_type  = excluded.mime_type,
    size_bytes = excluded.size_bytes,
    content    = excluded.content,
    cached_at  = excluded.cached_at
`,
		row.MessageID, row.AttachmentID, row.Filename, row.MIMEType,
		row.SizeBytes, row.Content, cachedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("save attachment_cache (%s, %s): %w", row.MessageID, row.AttachmentID, err)
	}
	return nil
}

// GetCachedAttachment returns a cached attachment by composite key.
// Returns ErrAttachmentNotCached if absent — caller treats that as
// "go fetch from Proton."
func (s *Store) GetCachedAttachment(ctx context.Context, messageID, attachmentID string) (AttachmentCacheRow, error) {
	var (
		row      AttachmentCacheRow
		cachedAt int64
	)
	err := s.DB.QueryRowContext(ctx, `
SELECT message_id, attachment_id, filename, mime_type, size_bytes, content, cached_at
FROM attachment_cache
WHERE message_id = ? AND attachment_id = ?
`, messageID, attachmentID).Scan(
		&row.MessageID, &row.AttachmentID, &row.Filename, &row.MIMEType,
		&row.SizeBytes, &row.Content, &cachedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AttachmentCacheRow{}, ErrAttachmentNotCached
	}
	if err != nil {
		return AttachmentCacheRow{}, fmt.Errorf("get attachment_cache (%s, %s): %w", messageID, attachmentID, err)
	}
	row.CachedAt = time.Unix(cachedAt, 0).UTC()
	return row, nil
}

// SumAttachmentBytes returns the total bytes currently held in the
// cache. Used by EvictAttachmentsToFit + by `protonmcp purge`
// stats output.
func (s *Store) SumAttachmentBytes(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	err := s.DB.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(size_bytes), 0) FROM attachment_cache`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("sum attachment_cache: %w", err)
	}
	return n.Int64, nil
}

// CountCachedAttachments returns the row count. Used by purge stats.
func (s *Store) CountCachedAttachments(ctx context.Context) (int64, error) {
	var n int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM attachment_cache`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count attachment_cache: %w", err)
	}
	return n, nil
}

// EvictAttachmentsToFit deletes oldest-cached_at rows until the
// total cached bytes is ≤ ceilingBytes. Returns the number of rows
// evicted.
//
// Called at the end of every mail_download_attachment cache-miss
// path so a steady stream of large downloads doesn't grow the cache
// without bound. Distinct from PurgeAttachmentsOlderThan — that's
// age-based, this is size-based.
//
// Implementation: one DELETE-with-subquery instead of a per-row
// loop. SQLite's planner handles this efficiently with the
// cached_at index.
func (s *Store) EvictAttachmentsToFit(ctx context.Context, ceilingBytes int64) (int64, error) {
	total, err := s.SumAttachmentBytes(ctx)
	if err != nil {
		return 0, err
	}
	if total <= ceilingBytes {
		return 0, nil
	}
	// Compute how many bytes we need to free.
	overflow := total - ceilingBytes

	// Delete in cached_at order until we've freed at least
	// `overflow` bytes. Per-row loop is unavoidable since SQLite
	// can't easily express "delete until cumulative SUM exceeds
	// X" in a single statement.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
SELECT message_id, attachment_id, size_bytes
FROM attachment_cache
ORDER BY cached_at ASC
`)
	if err != nil {
		return 0, fmt.Errorf("evict scan: %w", err)
	}

	type victim struct {
		messageID, attachmentID string
		size                    int64
	}
	var victims []victim
	freed := int64(0)
	for rows.Next() {
		var v victim
		if err := rows.Scan(&v.messageID, &v.attachmentID, &v.size); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("evict scan row: %w", err)
		}
		victims = append(victims, v)
		freed += v.size
		if freed >= overflow {
			break
		}
	}
	_ = rows.Close()

	for _, v := range victims {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM attachment_cache WHERE message_id = ? AND attachment_id = ?`,
			v.messageID, v.attachmentID,
		); err != nil {
			return 0, fmt.Errorf("evict delete: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("evict commit: %w", err)
	}
	return int64(len(victims)), nil
}

// PurgeAttachmentsOlderThan deletes rows whose cached_at is older
// than cutoff. Parallels PurgeOlderThan for the body cache; invoked
// by `protonmcp purge` after the body sweep.
func (s *Store) PurgeAttachmentsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM attachment_cache WHERE cached_at < ?`,
		cutoff.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("purge attachment_cache: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// GetCachedAttachmentMeta is GetCachedAttachment without the content
// BLOB — for display (the save prompt's filename) and accounting.
func (s *Store) GetCachedAttachmentMeta(ctx context.Context, messageID, attachmentID string) (AttachmentCacheMeta, error) {
	var (
		m        AttachmentCacheMeta
		cachedAt int64
	)
	err := s.DB.QueryRowContext(ctx, `
SELECT message_id, attachment_id, filename, mime_type, size_bytes, cached_at
FROM attachment_cache
WHERE message_id = ? AND attachment_id = ?
`, messageID, attachmentID).Scan(
		&m.MessageID, &m.AttachmentID, &m.Filename, &m.MIMEType, &m.SizeBytes, &cachedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AttachmentCacheMeta{}, ErrAttachmentNotCached
	}
	if err != nil {
		return AttachmentCacheMeta{}, fmt.Errorf("get attachment_cache meta (%s, %s): %w", messageID, attachmentID, err)
	}
	m.CachedAt = time.Unix(cachedAt, 0).UTC()
	return m, nil
}

// Attachment-cache retention (SECURITY M1). Decrypted attachments are
// a convenience cache, not an archive: a week covers "read it, then
// save / reply to it", and the byte cap bounds what a stolen disk or a
// backup holds even when a lot was opened recently.
const (
	DefaultAttachmentRetention     = 7 * 24 * time.Hour
	DefaultAttachmentCacheMaxBytes = int64(256 << 20)
)

// AttachmentSweepStats reports what SweepAttachmentCache removed.
type AttachmentSweepStats struct {
	Expired int64 // rows past the age cutoff
	Evicted int64 // rows evicted (oldest first) to get under the byte cap
}

// SweepAttachmentCache applies both retention rules: rows cached
// before now-maxAge go, then the oldest rows until the cache holds at
// most maxBytes. When anything was deleted the store is compacted so
// the deleted plaintext doesn't linger in WAL frames.
func (s *Store) SweepAttachmentCache(ctx context.Context, now time.Time, maxAge time.Duration, maxBytes int64) (AttachmentSweepStats, error) {
	var st AttachmentSweepStats
	n, err := s.PurgeAttachmentsOlderThan(ctx, now.Add(-maxAge))
	if err != nil {
		return st, err
	}
	st.Expired = n
	n, err = s.EvictAttachmentsToFit(ctx, maxBytes)
	if err != nil {
		return st, err
	}
	st.Evicted = n
	if st.Expired+st.Evicted > 0 {
		if err := s.Compact(ctx); err != nil {
			return st, err
		}
	}
	return st, nil
}

// Compact makes deleted plaintext unrecoverable from the files on disk
// as far as SQLite allows without a full VACUUM: freed pages inside
// store.db are already zeroed by secure_delete=on; this reclaims them
// when the database is in incremental auto-vacuum mode, and checkpoints
// + truncates the WAL, whose older frames still hold pre-delete page
// images.
func (s *Store) Compact(ctx context.Context) error {
	if s.Path == ":memory:" {
		return nil
	}
	var mode int
	if err := s.DB.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err == nil && mode == 2 {
		if _, err := s.DB.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
			return fmt.Errorf("incremental_vacuum: %w", err)
		}
	}
	var busy, logFrames, checkpointed int
	if err := s.DB.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return fmt.Errorf("wal_checkpoint: %w", err)
	}
	return nil
}
