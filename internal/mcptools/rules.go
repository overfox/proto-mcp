package mcptools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"gopkg.in/yaml.v3"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Local rules engine.
//
// A rule is a saved search-DSL query plus a short list of organizing
// actions. The action vocabulary is deliberately closed and benign —
// label, move (never to Trash), star, mark_read — so a rule can never
// send, forward, trash or delete mail no matter what ends up in the
// file: the YAML decoder rejects unknown keys and validation rejects
// disallowed targets on every load, not just on rules_set.
//
// Rules live in ~/Library/Application Support/protonmcp/rules.yaml
// (0600, written atomically). Rules marked auto: true are applied by
// ApplyAutoRules, which the background sync loop calls after each
// sync pass.

const (
	maxRules          = 100
	maxRuleQueryLen   = 1000
	maxRuleActions    = 4
	maxRuleNameLen    = 64
	defaultRuleRunMax = 200
	// rulesAutoWatermarkKey (sync_state) is the time ApplyAutoRules
	// last ran; the next run considers mail from shortly before it.
	rulesAutoWatermarkKey = "rules_auto_watermark"
	// rulesAutoOverlap re-scans a little before the watermark so mail
	// that synced late (dated before the previous run) still gets
	// processed. Actions are idempotent, so overlap is harmless.
	rulesAutoOverlap = time.Hour
	// rulesAutoFirstLookback bounds the very first auto run.
	rulesAutoFirstLookback = 24 * time.Hour
)

var ruleNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]*$`)

// Rule is one saved rule.
type Rule struct {
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description,omitempty" json:"description,omitempty"`
	Query       string       `yaml:"query" json:"query"`
	Actions     []RuleAction `yaml:"actions" json:"actions"`
	Auto        bool         `yaml:"auto,omitempty" json:"auto"`
}

// RuleAction holds exactly one of its fields.
type RuleAction struct {
	Label    string `yaml:"label,omitempty" json:"label,omitempty"`         // label id or name
	Move     string `yaml:"move,omitempty" json:"move,omitempty"`           // inbox | archive | spam | user folder id/name
	Star     bool   `yaml:"star,omitempty" json:"star,omitempty"`           // add the star
	MarkRead bool   `yaml:"mark_read,omitempty" json:"mark_read,omitempty"` // clear unread
}

// rulesFile is the on-disk document.
type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// rulesMu serializes read-modify-write of the rules file within the
// process (rules_set / rules_delete racing each other).
var rulesMu sync.Mutex

// rulesPath resolves the rules file location: Deps.RulesPath when set
// (tests), else the per-user Application Support default.
func rulesPath(deps Deps) (string, error) {
	if deps.RulesPath != "" {
		return deps.RulesPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "rules.yaml"), nil
}

// loadRules reads and validates the rules file. A missing file is an
// empty rule set.
func loadRules(deps Deps) ([]Rule, error) {
	p, err := rulesPath(deps)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open rules: %w", err)
	}
	defer f.Close()
	var doc rulesFile
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, errEOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if err := validateRules(doc.Rules); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return doc.Rules, nil
}

// errEOF is what yaml.v3 returns for an empty document.
var errEOF = func() error {
	var v any
	return yaml.NewDecoder(bytes.NewReader(nil)).Decode(&v)
}()

// saveRules validates and atomically writes the rule set (temp file in
// the same directory, fsync, rename), mode 0600 in a 0700 directory.
func saveRules(deps Deps, rules []Rule) error {
	if err := validateRules(rules); err != nil {
		return err
	}
	p, err := rulesPath(deps)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	var buf bytes.Buffer
	buf.WriteString("# protonmcp local rules — managed by the rules_set / rules_delete tools.\n" +
		"# Actions are limited to label, move (not to trash), star and mark_read.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(rulesFile{Rules: rules}); err != nil {
		return fmt.Errorf("encode rules: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".rules-*.yaml")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

// validateRules enforces the closed action vocabulary and basic sanity.
func validateRules(rules []Rule) error {
	if len(rules) > maxRules {
		return fmt.Errorf("%d rules exceeds the limit of %d", len(rules), maxRules)
	}
	seen := map[string]bool{}
	for i, r := range rules {
		if err := validateRule(r); err != nil {
			return fmt.Errorf("rule %d (%q): %w", i+1, r.Name, err)
		}
		key := strings.ToLower(r.Name)
		if seen[key] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[key] = true
	}
	return nil
}

func validateRule(r Rule) error {
	if r.Name == "" || len(r.Name) > maxRuleNameLen || !ruleNamePattern.MatchString(r.Name) || strings.EqualFold(r.Name, "all") {
		return fmt.Errorf("name must be 1-%d chars of letters, digits, space, _ . - (and not \"all\")", maxRuleNameLen)
	}
	if strings.TrimSpace(r.Query) == "" {
		return errors.New("query is required (a rule with no criteria would match the whole mailbox)")
	}
	if len(r.Query) > maxRuleQueryLen {
		return fmt.Errorf("query longer than %d chars", maxRuleQueryLen)
	}
	if len(r.Actions) == 0 || len(r.Actions) > maxRuleActions {
		return fmt.Errorf("needs 1-%d actions", maxRuleActions)
	}
	for j, a := range r.Actions {
		if err := validateAction(a); err != nil {
			return fmt.Errorf("action %d: %w", j+1, err)
		}
	}
	return nil
}

func validateAction(a RuleAction) error {
	n := 0
	if a.Label != "" {
		n++
	}
	if a.Move != "" {
		n++
	}
	if a.Star {
		n++
	}
	if a.MarkRead {
		n++
	}
	if n != 1 {
		return errors.New("each action must be exactly one of label, move, star, mark_read")
	}
	if a.Move != "" {
		switch strings.ToLower(a.Move) {
		case "trash", "sent", "drafts", "outbox", "all", "all_mail", "starred":
			return fmt.Errorf("move to %q is not allowed (rules never trash or delete mail)", a.Move)
		}
		if a.Move == gpa.TrashLabel || a.Move == gpa.SentLabel || a.Move == gpa.DraftsLabel ||
			a.Move == gpa.AllSentLabel || a.Move == gpa.AllDraftsLabel || a.Move == gpa.AllMailLabel ||
			a.Move == gpa.OutboxLabel || a.Move == gpa.StarredLabel || a.Move == gpa.AllScheduledLabel {
			return fmt.Errorf("move to system label %q is not allowed", a.Move)
		}
	}
	if a.Label != "" && isSystemLabelID(a.Label) {
		return fmt.Errorf("label %q is a system label; use move / star / mark_read instead", a.Label)
	}
	return nil
}

func isSystemLabelID(id string) bool {
	switch id {
	case gpa.InboxLabel, gpa.AllDraftsLabel, gpa.AllSentLabel, gpa.TrashLabel, gpa.SpamLabel,
		gpa.AllMailLabel, gpa.ArchiveLabel, gpa.SentLabel, gpa.DraftsLabel, gpa.OutboxLabel,
		gpa.StarredLabel, gpa.AllScheduledLabel:
		return true
	}
	return false
}

// describeAction renders an action for prompts and results.
func describeAction(a RuleAction) string {
	switch {
	case a.Label != "":
		return "label " + a.Label
	case a.Move != "":
		return "move to " + a.Move
	case a.Star:
		return "star"
	case a.MarkRead:
		return "mark read"
	}
	return "?"
}

// RuleRunResult reports one rule's run.
type RuleRunResult struct {
	Rule      string        `json:"rule"`
	Matched   int           `json:"matched"`
	Capped    bool          `json:"capped,omitempty"`
	Applied   []string      `json:"applied,omitempty"` // action → "N changed" summaries (not dry run)
	Error     string        `json:"error,omitempty"`
	Messages  []ruleMatchID `json:"messages,omitempty"`
	DryRun    bool          `json:"dry_run"`
	SinceUnix int64         `json:"-"`
}

type ruleMatchID struct {
	MessageID string `json:"message_id"`
	Subject   string `json:"subject,omitempty"`
	From      string `json:"from,omitempty"`
	Date      string `json:"date"`
}

// matchRule collects up to max message IDs matching the rule query
// (optionally only mail dated >= sinceUnix). All IDs are collected
// before any action runs, so moves can't shift the paging window.
func matchRule(ctx context.Context, deps Deps, r Rule, sinceUnix int64, max int) ([]store.SearchHit, bool, error) {
	var out []store.SearchHit
	offset := 0
	for len(out) < max {
		page := min(200, max-len(out))
		hits, err := deps.Store.Search(ctx, r.Query, store.SearchOpts{
			Limit:  page,
			Offset: offset,
			Filter: store.ListFilter{SinceUnix: sinceUnix},
		})
		if err != nil {
			return nil, false, err
		}
		out = append(out, hits...)
		if len(hits) < page {
			return out, false, nil
		}
		offset += len(hits)
	}
	// Probe whether more matched than we took.
	more, err := deps.Store.Search(ctx, r.Query, store.SearchOpts{
		Limit: 1, Offset: offset, Filter: store.ListFilter{SinceUnix: sinceUnix},
	})
	if err != nil {
		return out, false, err
	}
	return out, len(more) > 0, nil
}

// runRule matches and (unless dryRun) applies one rule.
func runRule(ctx context.Context, deps Deps, r Rule, dryRun bool, sinceUnix int64, max int) RuleRunResult {
	res := RuleRunResult{Rule: r.Name, DryRun: dryRun}
	hits, capped, err := matchRule(ctx, deps, r, sinceUnix, max)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Matched = len(hits)
	res.Capped = capped
	for i, h := range hits {
		if i >= 50 {
			break // the result lists a sample; counts are exact
		}
		res.Messages = append(res.Messages, ruleMatchID{
			MessageID: h.MessageID, Subject: h.Subject,
			From: h.FromAddress, Date: h.Date.Format(time.RFC3339),
		})
	}
	if dryRun || len(hits) == 0 {
		return res
	}
	if deps.Session == nil || deps.Session.Client == nil {
		res.Error = "session not available"
		return res
	}
	for _, a := range r.Actions {
		n, err := applyRuleAction(ctx, deps, a, hits)
		if err != nil {
			res.Error = fmt.Sprintf("%s: %v", describeAction(a), err)
			return res
		}
		res.Applied = append(res.Applied, fmt.Sprintf("%s: %d changed", describeAction(a), n))
	}
	return res
}

// applyRuleAction performs one action on the messages that don't
// already satisfy it (idempotent: re-running a rule is a no-op).
// Returns how many messages changed.
func applyRuleAction(ctx context.Context, deps Deps, a RuleAction, hits []store.SearchHit) (int, error) {
	switch {
	case a.Star:
		var ids []string
		for _, h := range hits {
			if !h.Starred {
				ids = append(ids, h.MessageID)
			}
		}
		if len(ids) == 0 {
			return 0, nil
		}
		if err := deps.Session.Client.LabelMessages(ctx, ids, gpa.StarredLabel); err != nil {
			return 0, err
		}
		_ = updateMessagesFlag(ctx, deps, ids, func(m *store.Message) { m.Starred = true })
		return len(ids), nil

	case a.MarkRead:
		var ids []string
		for _, h := range hits {
			if h.Unread {
				ids = append(ids, h.MessageID)
			}
		}
		if len(ids) == 0 {
			return 0, nil
		}
		if err := deps.Session.Client.MarkMessagesRead(ctx, ids...); err != nil {
			return 0, err
		}
		_ = updateMessagesFlag(ctx, deps, ids, func(m *store.Message) { m.Unread = false })
		return len(ids), nil

	case a.Label != "":
		labelID, err := resolveLabelRef(ctx, deps, a.Label, 1)
		if err != nil {
			return 0, err
		}
		var ids []string
		for _, h := range hits {
			has, err := deps.Store.MessageHasLabel(ctx, h.MessageID, labelID)
			if err != nil {
				return 0, err
			}
			if !has {
				ids = append(ids, h.MessageID)
			}
		}
		if len(ids) == 0 {
			return 0, nil
		}
		if err := deps.Session.Client.LabelMessages(ctx, ids, labelID); err != nil {
			return 0, err
		}
		for _, id := range ids {
			_ = deps.Store.AddMessageLabel(ctx, id, labelID)
		}
		return len(ids), nil

	case a.Move != "":
		destID, friendly := "", ""
		if id, ok := systemFolderToLabelID[strings.ToLower(a.Move)]; ok {
			destID, friendly = id, strings.ToLower(a.Move)
		} else {
			id, err := resolveLabelRef(ctx, deps, a.Move, 3)
			if err != nil {
				return 0, err
			}
			destID = id
		}
		if err := validateAction(RuleAction{Move: destID}); err != nil {
			return 0, err // a resolved id must still pass the deny list
		}
		want := friendly
		if want == "" {
			want = destID
		}
		var ids []string
		for _, h := range hits {
			if h.Folder != want {
				ids = append(ids, h.MessageID)
			}
		}
		if len(ids) == 0 {
			return 0, nil
		}
		_, _, err := moveMessages(ctx, deps, ids, destID, friendly)
		if err != nil {
			return 0, err
		}
		return len(ids), nil
	}
	return 0, errors.New("empty action")
}

// resolveLabelRef maps a label/folder id or (case-insensitive) name to
// an id from the labels mirror. labelType: 1 = label, 3 = folder.
func resolveLabelRef(ctx context.Context, deps Deps, ref string, labelType int) (string, error) {
	if l, err := deps.Store.GetLabel(ctx, ref); err == nil {
		if l.Type != labelType {
			return "", fmt.Errorf("%q is not a %s", ref, labelKindName(labelType))
		}
		return l.ID, nil
	}
	id, err := deps.Store.LabelIDByName(ctx, ref, labelType)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", fmt.Errorf("no %s named %q in the local mirror (see labels_list / folders_list)", labelKindName(labelType), ref)
		}
		return "", err
	}
	return id, nil
}

func labelKindName(t int) string {
	if t == 3 {
		return "folder"
	}
	return "label"
}

// AutoRulesReport summarises one ApplyAutoRules pass.
type AutoRulesReport struct {
	Since   time.Time       `json:"since"`
	Results []RuleRunResult `json:"results"`
}

// ApplyAutoRules runs every auto: true rule (not dry-run) against mail
// dated since shortly before the previous auto run (first run: the
// last 24h), then advances the watermark stored in sync_state. Meant
// to be called by the background sync loop after each successful sync
// pass. Each rule is capped at defaultRuleRunMax messages per pass; a
// failing rule is reported in its result and does not stop the others.
// Returns an error only when the rules file can't be read or the
// watermark can't be persisted.
func ApplyAutoRules(ctx context.Context, deps Deps) (AutoRulesReport, error) {
	var rep AutoRulesReport
	if deps.Store == nil {
		return rep, errors.New("store not available")
	}
	rulesMu.Lock()
	rules, err := loadRules(deps)
	rulesMu.Unlock()
	if err != nil {
		return rep, err
	}
	now := time.Now().UTC()
	since := now.Add(-rulesAutoFirstLookback)
	if v, err := deps.Store.GetSyncState(ctx, rulesAutoWatermarkKey); err == nil {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil {
			since = t.Add(-rulesAutoOverlap)
		}
	}
	rep.Since = since
	failed := false
	for _, r := range rules {
		if !r.Auto {
			continue
		}
		res := runRule(ctx, deps, r, false, since.Unix(), defaultRuleRunMax)
		res.Messages = nil // keep the report small; counts suffice
		if res.Error != "" {
			failed = true
		}
		rep.Results = append(rep.Results, res)
	}
	// Only advance past mail every auto rule actually processed; after
	// a failure the next pass re-covers the same window (idempotent).
	if failed {
		return rep, nil
	}
	if err := deps.Store.SetSyncState(ctx, rulesAutoWatermarkKey, now.Format(time.RFC3339)); err != nil {
		return rep, err
	}
	return rep, nil
}

func nowUTC() time.Time { return time.Now().UTC() }
