package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Proton system label IDs used by the triage queries. Mirrored from
// go-proton-api's label constants so the store stays SDK-free.
const (
	labelAllDrafts = "1"
	labelAllSent   = "2"
	labelSpam      = "4"
	labelTrash     = "3"
	labelSent      = "7"
	labelDrafts    = "8"
)

// sentPredicate / incomingPredicate classify a messages row. A message
// is "sent" when it carries a Sent label (or sync placed it in the
// sent folder); "incoming" is everything else that isn't a draft.
const (
	sentPredicate = `(messages.folder = 'sent' OR messages.id IN (
		SELECT message_id FROM message_labels WHERE label_id IN ('` + labelAllSent + `', '` + labelSent + `')))`
	incomingPredicate = `(COALESCE(messages.folder, '') NOT IN ('sent', 'drafts') AND messages.id NOT IN (
		SELECT message_id FROM message_labels WHERE label_id IN ('` + labelAllSent + `', '` + labelSent + `', '` + labelAllDrafts + `', '` + labelDrafts + `')))`
)

// DigestRow is one incoming message for mail_digest, with the user
// labels/folders it carries (from the labels mirror).
type DigestRow struct {
	MessageID   string
	ThreadID    string
	Subject     string
	FromAddress string
	FromName    string
	Date        time.Time
	Folder      string
	Unread      bool
	Starred     bool
	Snippet     string
	Labels      []Label // user labels + folders only (system labels omitted)
}

// maxDigestRows bounds how many messages a digest scans.
const maxDigestRows = 5000

// DigestSince returns incoming (non-sent, non-draft) messages dated at
// or after since, newest first, excluding trash and spam. Each row
// carries its user labels. truncated reports that maxDigestRows was hit.
func (s *Store) DigestSince(ctx context.Context, since time.Time) (rows []DigestRow, truncated bool, err error) {
	q := `
SELECT id, thread_id, COALESCE(subject, ''), COALESCE(from_address, ''), COALESCE(from_name, ''),
       date, COALESCE(folder, ''), unread, starred, body_text
  FROM messages
 WHERE messages.date >= ?
   AND ` + incomingPredicate + `
   AND COALESCE(messages.folder, '') NOT IN ('trash', 'spam')
   AND messages.id NOT IN (SELECT message_id FROM message_labels WHERE label_id IN ('` + labelTrash + `', '` + labelSpam + `'))
 ORDER BY messages.date DESC
 LIMIT ?`
	r, err := s.DB.QueryContext(ctx, q, since.Unix(), maxDigestRows+1)
	if err != nil {
		return nil, false, fmt.Errorf("digest: %w", err)
	}
	defer r.Close()
	byID := map[string]int{}
	for r.Next() {
		var (
			d        DigestRow
			dateUnix int64
			unread   int
			starred  int
			body     sql.NullString
		)
		if err := r.Scan(&d.MessageID, &d.ThreadID, &d.Subject, &d.FromAddress, &d.FromName,
			&dateUnix, &d.Folder, &unread, &starred, &body); err != nil {
			return nil, false, fmt.Errorf("digest scan: %w", err)
		}
		d.Date = time.Unix(dateUnix, 0).UTC()
		d.Unread = unread != 0
		d.Starred = starred != 0
		if body.Valid {
			d.Snippet = snippet(body.String, 160)
		}
		byID[d.MessageID] = len(rows)
		rows = append(rows, d)
	}
	if err := r.Err(); err != nil {
		return nil, false, err
	}
	if len(rows) > maxDigestRows {
		rows = rows[:maxDigestRows]
		truncated = true
	}
	if len(rows) == 0 {
		return rows, truncated, nil
	}

	// Attach user labels in one pass over the joined label mirror.
	lr, err := s.DB.QueryContext(ctx, `
SELECT ml.message_id, l.id, l.name, l.type
  FROM message_labels ml JOIN labels l ON l.id = ml.label_id
  JOIN messages ON messages.id = ml.message_id
 WHERE messages.date >= ?`, since.Unix())
	if err != nil {
		return nil, false, fmt.Errorf("digest labels: %w", err)
	}
	defer lr.Close()
	for lr.Next() {
		var msgID string
		var l Label
		if err := lr.Scan(&msgID, &l.ID, &l.Name, &l.Type); err != nil {
			return nil, false, fmt.Errorf("digest labels scan: %w", err)
		}
		if i, ok := byID[msgID]; ok && i < len(rows) {
			rows[i].Labels = append(rows[i].Labels, l)
		}
	}
	return rows, truncated, lr.Err()
}

// SentMessage is one message the user sent, for mail_awaiting_reply.
type SentMessage struct {
	MessageID  string
	ThreadID   string
	Subject    string
	Date       time.Time
	Recipients []string // to + cc addresses, lower-cased
}

// SentBetween returns sent messages dated in [from, to), newest first,
// capped at limit.
func (s *Store) SentBetween(ctx context.Context, from, to time.Time, limit int) ([]SentMessage, error) {
	q := `
SELECT id, thread_id, COALESCE(subject, ''), date, COALESCE(to_json, ''), COALESCE(cc_json, '')
  FROM messages
 WHERE messages.date >= ? AND messages.date < ?
   AND ` + sentPredicate + `
 ORDER BY messages.date DESC
 LIMIT ?`
	r, err := s.DB.QueryContext(ctx, q, from.Unix(), to.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("sent between: %w", err)
	}
	defer r.Close()
	var out []SentMessage
	for r.Next() {
		var (
			m        SentMessage
			dateUnix int64
			toJSON   string
			ccJSON   string
		)
		if err := r.Scan(&m.MessageID, &m.ThreadID, &m.Subject, &dateUnix, &toJSON, &ccJSON); err != nil {
			return nil, fmt.Errorf("sent scan: %w", err)
		}
		m.Date = time.Unix(dateUnix, 0).UTC()
		m.Recipients = append(addressesFromJSON(toJSON), addressesFromJSON(ccJSON)...)
		out = append(out, m)
	}
	return out, r.Err()
}

// HasLaterIncoming reports whether an incoming message arrived after
// `after` that either shares threadID, or comes from one of fromAny
// with a subject whose normalized form equals normSubject. The second
// arm is the best-effort fallback for replies the mirror hasn't
// threaded yet (thread_id is only header-derived once a body is read).
func (s *Store) HasLaterIncoming(ctx context.Context, threadID string, after time.Time, fromAny []string, normSubject string) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `
SELECT COUNT(*) FROM messages
 WHERE messages.thread_id = ? AND messages.date > ? AND `+incomingPredicate,
		threadID, after.Unix()).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("later incoming: %w", err)
	}
	if n > 0 {
		return true, nil
	}
	if len(fromAny) == 0 || normSubject == "" {
		return false, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(fromAny)), ",")
	args := []any{after.Unix()}
	for _, a := range fromAny {
		args = append(args, strings.ToLower(a))
	}
	r, err := s.DB.QueryContext(ctx, `
SELECT COALESCE(subject, '') FROM messages
 WHERE messages.date > ? AND LOWER(COALESCE(messages.from_address, '')) IN (`+ph+`) AND `+incomingPredicate+`
 LIMIT 500`, args...)
	if err != nil {
		return false, fmt.Errorf("later incoming by subject: %w", err)
	}
	defer r.Close()
	for r.Next() {
		var subj string
		if err := r.Scan(&subj); err != nil {
			return false, err
		}
		if NormalizeSubject(subj) == normSubject {
			return true, nil
		}
	}
	return false, r.Err()
}

// NormalizeSubject lower-cases a subject and strips any run of reply /
// forward prefixes (Re:, RE:, Fwd:, Fw:, AW:, WG:, SV:, Antw:, TR:,
// with optional [n] counters) so "Re: Fwd: Hearing" == "hearing".
func NormalizeSubject(s string) string {
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	for {
		trimmed := false
		for _, p := range []string{"re", "fwd", "fw", "aw", "wg", "sv", "antw", "tr", "vs", "rif"} {
			if !strings.HasPrefix(s, p) {
				continue
			}
			rest := s[len(p):]
			if strings.HasPrefix(rest, "[") {
				if end := strings.IndexByte(rest, ']'); end > 0 {
					rest = rest[end+1:]
				}
			}
			if strings.HasPrefix(rest, ":") {
				s = strings.TrimSpace(rest[1:])
				trimmed = true
				break
			}
		}
		if !trimmed {
			return s
		}
	}
}

// addressesFromJSON extracts lower-cased addresses from a to_json /
// cc_json value.
func addressesFromJSON(s string) []string {
	if s == "" {
		return nil
	}
	var list []struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal([]byte(s), &list); err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		if a.Address != "" {
			out = append(out, strings.ToLower(a.Address))
		}
	}
	return out
}
