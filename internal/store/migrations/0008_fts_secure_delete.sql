-- SECURITY M1 — purged bodies must leave the full-text index too.
--
-- PurgeOlderThan NULLs body_text; the messages_fts_update trigger then
-- deletes and re-inserts the row's FTS entry. A plain FTS5 delete only
-- appends a tombstone: the purged body's tokens stay in the index's
-- %_data segment blobs until a merge happens to rewrite them, so the
-- words of a "purged" email remained recoverable from store.db.
--
-- FTS5's secure-delete option (SQLite 3.42+) removes a deleted row's
-- tokens from the segments immediately. It's a persistent per-table
-- setting. 'optimize' then merges all existing segments once, dropping
-- every token that earlier deletes left behind.

-- +goose Up
INSERT INTO messages_fts(messages_fts, rank) VALUES ('secure-delete', 1);
INSERT INTO messages_fts(messages_fts) VALUES ('optimize');
INSERT INTO calendar_events_fts(calendar_events_fts, rank) VALUES ('secure-delete', 1);
INSERT INTO calendar_events_fts(calendar_events_fts) VALUES ('optimize');

-- +goose Down
INSERT INTO messages_fts(messages_fts, rank) VALUES ('secure-delete', 0);
INSERT INTO calendar_events_fts(calendar_events_fts, rank) VALUES ('secure-delete', 0);
