-- Re-key existing mirror rows by RFC 822 Message-ID.
--
-- Until now sync stored thread_id = Proton message id, so every message
-- was its own thread until mail_read decrypted it and recorded its
-- References root. UpsertMessage now keys new rows by the ExternalID
-- (Message-ID) carried in the metadata; this brings rows already in the
-- mirror into line. Only rows still on the old default (thread_id = id)
-- are touched — header-derived thread ids set by mail_read are kept.
-- raw_json is the marshalled MessageMetadata, so ExternalID is there.

-- +goose Up
UPDATE messages
   SET thread_id = TRIM(json_extract(raw_json, '$.ExternalID'), '<> ')
 WHERE thread_id = id
   AND json_valid(raw_json)
   AND COALESCE(TRIM(json_extract(raw_json, '$.ExternalID'), '<> '), '') <> '';

-- +goose Down
-- Not reversible (the previous value was simply the row id).
UPDATE messages
   SET thread_id = id
 WHERE json_valid(raw_json)
   AND thread_id = TRIM(json_extract(raw_json, '$.ExternalID'), '<> ');
