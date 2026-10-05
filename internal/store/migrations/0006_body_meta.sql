-- Body-cache metadata that mail_read previously dropped on a cache hit.
--
-- The body cache (body_text / body_html / body_cached_at) only kept the
-- decrypted text, so a cache-hit mail_read lost the MIME type, the
-- References chain and the attachment list that the fresh-fetch path
-- returns. These columns ride alongside the body: written by
-- SetCachedBody, read by GetCachedBody, and NULLed by PurgeOlderThan in
-- the same statement as the body itself (same retention, same
-- secure_delete posture).
--
--   body_mime_type    "text/html" / "text/plain" / "multipart/*".
--   body_references   JSON array of RFC 822 Message-IDs, oldest first.
--   body_attachments  JSON array of {id, name, mime_type, size, inline}
--                     — metadata only, never attachment bytes.

-- +goose Up
ALTER TABLE messages ADD COLUMN body_mime_type   TEXT;
ALTER TABLE messages ADD COLUMN body_references  TEXT;
ALTER TABLE messages ADD COLUMN body_attachments TEXT;

-- +goose Down
ALTER TABLE messages DROP COLUMN body_attachments;
ALTER TABLE messages DROP COLUMN body_references;
ALTER TABLE messages DROP COLUMN body_mime_type;
