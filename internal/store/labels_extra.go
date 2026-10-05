package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// MessageHasLabel reports whether the mirror records labelID on msgID.
func (s *Store) MessageHasLabel(ctx context.Context, msgID, labelID string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM message_labels WHERE message_id = ? AND label_id = ?`,
		msgID, labelID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("message has label: %w", err)
	}
	return n > 0, nil
}

// AddMessageLabel records one label on a message in the mirror (no-op
// when already present or when the message row doesn't exist yet —
// the next sync writes the authoritative set either way).
func (s *Store) AddMessageLabel(ctx context.Context, msgID, labelID string) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT OR IGNORE INTO message_labels(message_id, label_id)
SELECT ?, ? WHERE EXISTS (SELECT 1 FROM messages WHERE id = ?)`,
		msgID, labelID, msgID)
	if err != nil {
		return fmt.Errorf("add message label: %w", err)
	}
	return nil
}

// LabelIDByName resolves a label (type 1) or folder (type 3) name,
// case-insensitively, to its id. ErrNotFound when absent; when two
// share a name the first by id wins.
func (s *Store) LabelIDByName(ctx context.Context, name string, labelType int) (string, error) {
	var id string
	err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM labels WHERE LOWER(name) = LOWER(?) AND type = ? ORDER BY id LIMIT 1`,
		name, labelType).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("label by name: %w", err)
	}
	return id, nil
}
