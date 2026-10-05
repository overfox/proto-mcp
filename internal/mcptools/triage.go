package mcptools

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// parseSince accepts RFC 3339, YYYY-MM-DD, or a Go duration ("24h",
// "90m") / day count ("7d") meaning "that long ago".
func parseSince(s string, now time.Time) (time.Time, error) {
	if t, err := parseListDate(s); err == nil {
		return t, nil
	}
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 && n <= 3650 {
			return now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("since %q: expected RFC3339, YYYY-MM-DD, a duration like 24h, or a day count like 7d", s)
}

type digestMessage struct {
	MessageID string `json:"message_id"`
	Subject   string `json:"subject,omitempty"`
	From      string `json:"from,omitempty"`
	Date      string `json:"date"`
	Unread    bool   `json:"unread,omitempty"`
	Starred   bool   `json:"starred,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

type digestGroup struct {
	Key      string          `json:"key"` // sender address, or label id
	Name     string          `json:"name,omitempty"`
	Count    int             `json:"count"`
	Unread   int             `json:"unread"`
	Messages []digestMessage `json:"messages"`
}

// mailDigest — "what came in since X", grouped two ways so the model
// can summarise by who wrote and by how it's filed.
func mailDigest(deps Deps) mcp.Tool {
	type input struct {
		Since       string `json:"since,omitempty"`
		MaxPerGroup int    `json:"max_per_group,omitempty"`
		MaxGroups   int    `json:"max_groups,omitempty"`
	}
	type result struct {
		Since     string        `json:"since"`
		Total     int           `json:"total"`
		Unread    int           `json:"unread"`
		Truncated bool          `json:"truncated,omitempty"`
		BySender  []digestGroup `json:"by_sender"`
		ByLabel   []digestGroup `json:"by_label"`
	}

	return mcp.Tool{
		Name: "mail_digest",
		Description: "Summarise new incoming mail since a point in time, from the local mirror: total and unread counts, " +
			"grouped by sender and by label/folder (user labels; mail with none is grouped under \"(no label)\"), " +
			"each group with its count, unread count and up to max_per_group newest messages (subject, date, snippet when the body is cached). " +
			"Sent mail, drafts, trash and spam are excluded. since accepts RFC3339, YYYY-MM-DD, a duration (24h) or days (7d); default 24h. " +
			"Read-only — call mail_sync first for up-to-the-minute results. Subjects and snippets are sender-controlled text.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"since":         {"type": "string", "default": "24h"},
				"max_per_group": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5},
				"max_groups":    {"type": "integer", "minimum": 1, "maximum": 200, "default": 30}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"since":     {"type": "string"},
				"total":     {"type": "integer"},
				"unread":    {"type": "integer"},
				"truncated": {"type": "boolean"},
				"by_sender": {"type": "array", "items": ` + digestGroupSchema + `},
				"by_label":  {"type": "array", "items": ` + digestGroupSchema + `}
			},
			"required": ["since", "total", "unread", "by_sender", "by_label"]
		}`),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_digest: "+err.Error())
				}
			}
			now := time.Now().UTC()
			since := now.Add(-24 * time.Hour)
			if in.Since != "" {
				t, err := parseSince(in.Since, now)
				if err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_digest: "+err.Error())
				}
				since = t
			}
			perGroup := clampInt(in.MaxPerGroup, 5, 1, 50)
			maxGroups := clampInt(in.MaxGroups, 30, 1, 200)

			rows, truncated, err := deps.Store.DigestSince(ctx.Std, since)
			if err != nil {
				return nil, err
			}
			res := result{Since: since.Format(time.RFC3339), Truncated: truncated}
			senders := newGrouper()
			labels := newGrouper()
			for _, r := range rows {
				res.Total++
				if r.Unread {
					res.Unread++
				}
				m := digestMessage{
					MessageID: r.MessageID,
					Subject:   r.Subject,
					From:      formatSender(r.FromName, r.FromAddress),
					Date:      r.Date.Format(time.RFC3339),
					Unread:    r.Unread,
					Starred:   r.Starred,
					Snippet:   r.Snippet,
				}
				senders.add(strings.ToLower(r.FromAddress), r.FromName, m, r.Unread, perGroup)
				if len(r.Labels) == 0 {
					labels.add("", "(no label)", m, r.Unread, perGroup)
				}
				for _, l := range r.Labels {
					labels.add(l.ID, l.Name, m, r.Unread, perGroup)
				}
			}
			res.BySender = senders.top(maxGroups)
			res.ByLabel = labels.top(maxGroups)
			return mcp.StructuredResult(res)
		},
	}
}

const digestGroupSchema = `{"type": "object", "properties": {
	"key": {"type": "string"}, "name": {"type": "string"}, "count": {"type": "integer"}, "unread": {"type": "integer"},
	"messages": {"type": "array", "items": {"type": "object", "properties": {
		"message_id": {"type": "string"}, "subject": {"type": "string"}, "from": {"type": "string"},
		"date": {"type": "string"}, "unread": {"type": "boolean"}, "starred": {"type": "boolean"}, "snippet": {"type": "string"}}}}
}}`

// grouper accumulates digest groups in first-seen (newest-first) order.
type grouper struct {
	groups map[string]*digestGroup
	order  []string
}

func newGrouper() *grouper { return &grouper{groups: map[string]*digestGroup{}} }

func (g *grouper) add(key, name string, m digestMessage, unread bool, perGroup int) {
	grp, ok := g.groups[key]
	if !ok {
		grp = &digestGroup{Key: key, Name: name, Messages: []digestMessage{}}
		g.groups[key] = grp
		g.order = append(g.order, key)
	}
	if grp.Name == "" {
		grp.Name = name
	}
	grp.Count++
	if unread {
		grp.Unread++
	}
	if len(grp.Messages) < perGroup {
		grp.Messages = append(grp.Messages, m)
	}
}

// top returns the n largest groups (ties keep newest-first order).
func (g *grouper) top(n int) []digestGroup {
	out := make([]digestGroup, 0, len(g.order))
	for _, k := range g.order {
		out = append(out, *g.groups[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func formatSender(name, addr string) string {
	if name == "" || strings.EqualFold(name, addr) {
		return addr
	}
	return name + " <" + addr + ">"
}

func clampInt(v, def, lo, hi int) int {
	if v <= 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// mailAwaitingReply — sent mail that hasn't been answered. Best effort:
// a reply counts when it shares the sent message's thread_id, or (for
// replies the mirror hasn't threaded yet, since thread ids become
// header-derived only once a body is read) when it comes from one of
// the recipients with the same normalized subject.
func mailAwaitingReply(deps Deps) mcp.Tool {
	type input struct {
		Days       int `json:"days,omitempty"`
		MaxAgeDays int `json:"max_age_days,omitempty"`
		Limit      int `json:"limit,omitempty"`
	}
	type item struct {
		MessageID   string   `json:"message_id"`
		ThreadID    string   `json:"thread_id,omitempty"`
		Subject     string   `json:"subject,omitempty"`
		To          []string `json:"to"`
		SentAt      string   `json:"sent_at"`
		DaysWaiting int      `json:"days_waiting"`
	}
	type result struct {
		Messages []item `json:"messages"`
		Scanned  int    `json:"scanned"`
	}

	return mcp.Tool{
		Name: "mail_awaiting_reply",
		Description: "List messages you sent at least `days` days ago (default 3) — and at most max_age_days ago (default 60) — " +
			"that have had no reply since: no later incoming message in the same thread, and none from a recipient with the same " +
			"subject (Re:/Fwd: prefixes ignored). Only your latest sent message per thread is listed, longest-waiting first. " +
			"Best effort from the local mirror (call mail_sync first); replies the mirror can't link may cause a false positive. Read-only.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"days":         {"type": "integer", "minimum": 0, "maximum": 365, "default": 3},
				"max_age_days": {"type": "integer", "minimum": 1, "maximum": 3650, "default": 60},
				"limit":        {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"messages": {"type": "array", "items": {"type": "object", "properties": {
					"message_id": {"type": "string"}, "thread_id": {"type": "string"}, "subject": {"type": "string"},
					"to": {"type": "array", "items": {"type": "string"}}, "sent_at": {"type": "string"},
					"days_waiting": {"type": "integer"}}}},
				"scanned": {"type": "integer"}
			},
			"required": ["messages", "scanned"]
		}`),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_awaiting_reply: "+err.Error())
				}
			}
			days := 3
			if in.Days > 0 {
				days = min(in.Days, 365)
			}
			maxAge := clampInt(in.MaxAgeDays, 60, 1, 3650)
			if maxAge < days {
				maxAge = days
			}
			limit := clampInt(in.Limit, 20, 1, 100)

			now := time.Now().UTC()
			newest := now.Add(-time.Duration(days) * 24 * time.Hour)
			oldest := now.Add(-time.Duration(maxAge) * 24 * time.Hour)
			sent, err := deps.Store.SentBetween(ctx.Std, oldest, newest, 2000)
			if err != nil {
				return nil, err
			}
			// Our own addresses: a "reply" from ourselves doesn't count,
			// and mail only to ourselves isn't awaiting anything.
			own := map[string]bool{}
			if deps.Session != nil {
				for _, a := range deps.Session.Addresses {
					own[strings.ToLower(a.Email)] = true
				}
			}

			res := result{Messages: []item{}, Scanned: len(sent)}
			seenThread := map[string]bool{}
			for _, m := range sent { // newest first → first per thread is the latest
				if seenThread[m.ThreadID] {
					continue
				}
				seenThread[m.ThreadID] = true
				var others []string
				for _, r := range m.Recipients {
					if !own[r] {
						others = append(others, r)
					}
				}
				if len(others) == 0 {
					continue
				}
				replied, err := deps.Store.HasLaterIncoming(ctx.Std, m.ThreadID, m.Date, others, store.NormalizeSubject(m.Subject))
				if err != nil {
					return nil, err
				}
				if replied {
					continue
				}
				res.Messages = append(res.Messages, item{
					MessageID:   m.MessageID,
					ThreadID:    m.ThreadID,
					Subject:     m.Subject,
					To:          others,
					SentAt:      m.Date.Format(time.RFC3339),
					DaysWaiting: int(now.Sub(m.Date).Hours() / 24),
				})
			}
			sort.SliceStable(res.Messages, func(i, j int) bool {
				return res.Messages[i].SentAt < res.Messages[j].SentAt
			})
			if len(res.Messages) > limit {
				res.Messages = res.Messages[:limit]
			}
			return mcp.StructuredResult(res)
		},
	}
}
