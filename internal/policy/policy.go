// Package policy is the YAML-driven per-tool decision engine.
//
// Every MCP tool call hits Decide(tool, args, caller) before the
// handler runs. The result — allow / prompt / deny — drives the
// middleware in internal/mcp. Default-deny for unknown tools per
// SECURITY Foundational #4.
//
// Configuration:
//
//  1. default.yaml is embedded via //go:embed and parsed at startup.
//     Allows every read tool shipped in Phase 3; pre-declares
//     prompt + confirm for Phase 5's write tools so Decide doesn't
//     fall through to deny when those handlers register.
//
//  2. ~/Library/Application Support/protonmcp/policy.yaml is the
//     user override. Loaded if present, shallow-merged on tool
//     keys (per-tool block replaces the default block — we don't
//     deep-merge field by field, that's a footgun for security
//     fields like confirm:true).
//
// Hot reload via Engine.Reload(). Invalid YAML keeps the previous
// policy in place; we never swap to a partial parse.
package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// Decision is the outcome of Decide.
type Decision string

const (
	DecisionAllow  Decision = "allow"
	DecisionPrompt Decision = "prompt"
	DecisionDeny   Decision = "deny"
)

// Caller is re-exported from internal/caller so consumers of this
// package don't have to import caller separately. Identity-typed —
// it IS caller.Caller, not a copy.
type Caller = caller.Caller

// ToolPolicy is the per-tool entry. Forward-compat fields
// (allowed_recipients, description) are parsed today and enforced
// in Phase 5; baking them into the schema now avoids a YAML break
// on users' override files later.
//
// TTL is stored as a string ("5m", "30s", "0") rather than
// time.Duration because YAML can't auto-convert a bare 0 to
// time.Duration. Parse on read via .TTLDuration().
type ToolPolicy struct {
	Decision          Decision `yaml:"decision"`
	Confirm           bool     `yaml:"confirm,omitempty"`
	RateLimit         string   `yaml:"rate_limit,omitempty"` // "20/hour" — parsed lazily in Phase 5
	TTL               string   `yaml:"ttl,omitempty"`        // "5m", "30s", or "0"
	AllowedRecipients []string `yaml:"allowed_recipients,omitempty"`
	Description       string   `yaml:"description,omitempty"`
}

// TTLDuration parses TTL into a time.Duration. Empty / "0" → zero.
// Anything else goes through time.ParseDuration (e.g., "5m", "30s").
//
// SECURITY D25: parseDocument validates TTL at LOAD time and refuses
// malformed values, so reaching the parse-error branch here means a
// caller skipped the validator (manual construction of ToolPolicy
// in test code, future package-internal construction). Panicking
// surfaces the bug rather than silently caching a zero — a silent
// zero would bypass the cache and cause performance issues, not
// security ones, but the principle is "fail loud on impossible
// states."
func (p ToolPolicy) TTLDuration() time.Duration {
	if p.TTL == "" || p.TTL == "0" {
		return 0
	}
	d, err := time.ParseDuration(p.TTL)
	if err != nil {
		panic(fmt.Sprintf(
			"policy: ToolPolicy.TTL %q invalid at use-site (must be caught by parseDocument at load): %v",
			p.TTL, err,
		))
	}
	return d
}

// document is the on-disk YAML shape. defaults.decision applies to
// unknown tools; the spec's default is deny.
type document struct {
	Defaults ToolPolicy            `yaml:"defaults"`
	Tools    map[string]ToolPolicy `yaml:"tools"`
	// IdleLockMinutes: lock the daemon after this many minutes
	// without a tool call. 0 (or missing) disables the idle timer.
	// Range-checked in parseDocument: must be 0–1440 (one day).
	IdleLockMinutes int `yaml:"idle_lock_minutes,omitempty"`
	// MaxAttachmentBytes: per-attachment size ceiling enforced by
	// mail_download_attachment (before fetch) and mail_send.attachments
	// (before upload). Phase 8/A. 0 / missing → DefaultMaxAttachmentBytes.
	// Range-checked in parseDocument: must be 0 or positive, at most
	// 1 GiB. The 500 MiB total-cache ceiling is hardcoded in
	// internal/store/attachments.go and not user-configurable.
	MaxAttachmentBytes int64 `yaml:"max_attachment_bytes,omitempty"`
	// AttachmentPathAllowlist: absolute directories from which
	// path-based attachments (attachments[].path on the send/draft
	// tools) may be read. Empty / missing → path-based attachments
	// are refused entirely (secure default: the daemon reads no host
	// file on a model's say-so unless the user opted a directory in).
	// Entries must be absolute; symlinks are resolved before the
	// containment check at use-site.
	AttachmentPathAllowlist []string `yaml:"attachment_path_allowlist,omitempty"`
	// KeepAlive: when true, the read-only attachment-access tools in
	// keepAliveSuppressibleTools skip their Touch ID prompt for the
	// session. Defaults false (missing → secure: those tools prompt).
	// Driven by the menu bar "Keep Alive" toggle. The suppressible
	// set is HARDCODED (see keepAliveSuppressibleTools) so no config
	// or injected policy file can widen keep-alive suppression to
	// mutating tools (send / move / label / trash / delete) — the
	// same defense-in-depth stance as the send floor.
	KeepAlive bool `yaml:"keep_alive,omitempty"`
}

// keepAliveSuppressibleTools is the ONLY set of tools whose Touch ID
// prompt KeepAlive removes. Deliberately limited to read-only
// attachment access — fetching an attachment to read it is what
// prompts most often during ordinary reading. Every mailbox-mutating
// tool is absent, so KeepAlive can never un-gate a send, move, label,
// trash, or delete no matter what the config says.
var keepAliveSuppressibleTools = map[string]bool{
	"mail_download_attachment": true,
	"mail_save_attachment":     true,
	// .eml export writes one message (with its attachments) to disk —
	// the same read-and-save shape as mail_save_attachment, given the
	// same treatment by the owner.
	"mail_export_eml": true,
	// Text extraction is read-only attachment access, exactly like
	// mail_download_attachment.
	"mail_attachment_text": true,
}

// DefaultMaxAttachmentBytes is the per-attachment cap when the
// policy doesn't override it. 25 MiB. Round number; matches what
// most free email providers also cap at, leaving room for Proton's
// paid-tier larger attachments via explicit policy override.
const DefaultMaxAttachmentBytes int64 = 25 * 1024 * 1024

// Engine holds the current policy. Reload swaps in a new document
// under a write lock; Decide reads under a read lock so concurrent
// tool calls never see a half-updated state.
//
// Safe for concurrent use. Construct via New().
type Engine struct {
	mu       sync.RWMutex
	doc      document
	override string // path to the user override, "" if none/unreadable

	// gate approves an override that loosens the embedded defaults
	// (SECURITY H6). nil → weakenings are applied unchecked (tests and
	// the read-only CLI paths; the daemon always installs one).
	gate Gate
	// weakenings lists how the policy in force is looser than the
	// embedded defaults (nil when it isn't). overrideErr is why the
	// override file is NOT in force at startup (nil when it is or
	// there is none). Both guarded by mu.
	weakenings  []string
	overrideErr error

	logger *slog.Logger
}

// New constructs an Engine, loading default.yaml + the user override
// from overridePath if present. overridePath may be "" to skip the
// override entirely (useful for tests).
//
// Returns an error only if the embedded default.yaml fails to parse
// — that's our own code, treat as a build-time bug. User override
// failures are logged at Warn level and the default proceeds.
//
// New installs no weakening gate: an override that loosens the
// defaults is applied as long as it passes the floors and hard limits.
// Long-running servers use NewWithGate.
func New(ctx context.Context, overridePath string, logger *slog.Logger) (*Engine, error) {
	return NewWithGate(ctx, overridePath, logger, nil)
}

// NewWithGate is New with a weakening gate (SECURITY H6): an override
// that loosens anything vs the embedded defaults takes effect only if
// gate approves it. A refused override leaves the embedded defaults in
// force (the reason is logged and reported by OverrideError).
func NewWithGate(ctx context.Context, overridePath string, logger *slog.Logger, gate Gate) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	e := &Engine{override: overridePath, logger: logger, gate: gate}
	doc, err := parseDocument(defaultYAML)
	if err != nil {
		return nil, fmt.Errorf("parse embedded default policy: %w", err)
	}
	e.doc = doc
	if overridePath != "" {
		ws, err := e.applyOverrideInto(ctx, &e.doc)
		if err != nil {
			// applyOverrideInto validates + gates before it mutates, so
			// e.doc is still the pristine embedded default here.
			e.overrideErr = err
			logger.Warn("policy override not applied; using embedded defaults only",
				"path", overridePath, "err", err.Error())
		} else {
			e.weakenings = ws
		}
	}
	return e, nil
}

// Weakenings returns how the policy in force is looser than the
// embedded defaults (empty when it isn't). Copy.
func (e *Engine) Weakenings() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.weakenings...)
}

// OverrideError reports why the override file was not applied at
// startup (nil when it was, or when there is none).
func (e *Engine) OverrideError() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.overrideErr
}

// Decide returns the policy entry for the given tool name + args +
// caller. args and caller are passed through for future per-call
// decisions (e.g., Phase 5's allowed_recipients enforcement) — Phase
// 4's engine doesn't read them yet.
//
// Returns (DecisionDeny, &defaults) for unknown tools. The returned
// ToolPolicy pointer is owned by the engine; do NOT mutate it.
func (e *Engine) Decide(tool string, _ []byte, _ Caller) (Decision, *ToolPolicy) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if p, ok := e.doc.Tools[tool]; ok {
		// KeepAlive downgrades ONLY the hardcoded read-only
		// attachment-access tools from prompt → allow, and only when
		// they were actually going to prompt (a config that denies
		// one stays denied). Mutating tools are never in the set.
		if e.doc.KeepAlive && keepAliveSuppressibleTools[tool] && p.Decision == DecisionPrompt {
			p.Decision = DecisionAllow
			return DecisionAllow, &p
		}
		return p.Decision, &p
	}
	d := e.doc.Defaults
	if d.Decision == "" {
		d.Decision = DecisionDeny
	}
	return d.Decision, &d
}

// Reload re-reads the user override and swaps it in atomically.
// On any parse error the previous policy stays in place — there is
// never a window where Decide sees a partial document.
//
// SIGHUP handler calls this. So does the `protonmcp policy reload`
// CLI subcommand via the PID file in this package's pidfile.go.
func (e *Engine) Reload() error {
	return e.ReloadContext(context.Background())
}

// ReloadContext is Reload with a context bounding the weakening
// approval prompt (if the gate needs one). A declined / failed
// approval returns an error wrapping ErrWeakeningNotApproved and keeps
// the previous policy.
func (e *Engine) ReloadContext(ctx context.Context) error {
	if e.override == "" {
		return errors.New("policy: no override path configured")
	}
	// Re-parse the embedded default from scratch — defends against
	// any caller that mutated the in-memory map (we don't expose
	// that path, but Reload is a good safety net).
	base, err := parseDocument(defaultYAML)
	if err != nil {
		return fmt.Errorf("re-parse embedded default: %w", err)
	}

	ws, err := e.applyOverrideInto(ctx, &base)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.doc = base
	e.weakenings = ws
	e.overrideErr = nil
	e.mu.Unlock()
	return nil
}

// readOverride reads + validates the override file: parse, floors and
// hard limits. Returns (nil doc, nil) when there is no file.
func readOverride(path string) (*document, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil // no override file is fine
		}
		return nil, nil, fmt.Errorf("read override: %w", err)
	}
	override, err := parseDocument(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse override: %w", err)
	}
	// Override entries replace default blocks wholesale, and the
	// embedded defaults already satisfy the floors, so validating just
	// the override's own entries covers the merged result.
	if err := enforceSendFloor(&override); err != nil {
		return nil, nil, err
	}
	if err := enforceDestructiveFloor(&override); err != nil {
		return nil, nil, err
	}
	if err := enforceHardLimits(&override); err != nil {
		return nil, nil, err
	}
	return &override, data, nil
}

// AnalyzeOverride validates the override at path like the engine does
// and reports how it would loosen the embedded defaults, plus the
// content hash a weakening approval is bound to. For `policy show` /
// `policy validate`. A missing file returns (nil, "", nil).
func AnalyzeOverride(path string) (weakenings []string, contentHash string, err error) {
	override, data, err := readOverride(path)
	if err != nil || override == nil {
		return nil, "", err
	}
	base, err := parseDocument(defaultYAML)
	if err != nil {
		return nil, "", err
	}
	merged, _ := parseDocument(defaultYAML)
	mergeOverride(&merged, override)
	return computeWeakenings(base, merged), ContentHash(data), nil
}

// applyOverrideInto validates the override, computes its weakenings
// vs the embedded defaults, runs the weakening gate, and only then
// merges it into `into` — every rejection happens BEFORE `into` is
// mutated (NewWithGate merges straight into e.doc). Returns the
// weakenings now in force.
func (e *Engine) applyOverrideInto(ctx context.Context, into *document) ([]string, error) {
	override, data, err := readOverride(e.override)
	if err != nil || override == nil {
		return nil, err
	}
	base, err := parseDocument(defaultYAML)
	if err != nil {
		return nil, fmt.Errorf("re-parse embedded default: %w", err)
	}
	merged, _ := parseDocument(defaultYAML)
	mergeOverride(&merged, override)
	ws := computeWeakenings(base, merged)
	if len(ws) > 0 && e.gate != nil {
		if err := e.gate(ctx, ws, ContentHash(data)); err != nil {
			if !errors.Is(err, ErrWeakeningNotApproved) {
				err = fmt.Errorf("%w: %w", ErrWeakeningNotApproved, err)
			}
			return nil, err
		}
	}
	mergeOverride(into, override)
	return ws, nil
}

// mergeOverride applies a validated override onto into.
func mergeOverride(into *document, override *document) {
	// Shallow merge: per-tool override REPLACES the default block.
	// Don't deep-merge fields — a user who copies our default and
	// forgets to carry over `confirm: true` would silently weaken
	// security.
	if into.Tools == nil {
		into.Tools = map[string]ToolPolicy{}
	}
	for name, p := range override.Tools {
		into.Tools[name] = p
	}
	if override.Defaults.Decision != "" {
		into.Defaults = override.Defaults
	}
	// idle_lock_minutes was documented in configuration.md but never
	// merged from the override, so setting it had no effect. Zero
	// means "not set" here — the embedded default is 0/disabled, so
	// there is no force-back-to-zero case to preserve.
	if override.IdleLockMinutes != 0 {
		into.IdleLockMinutes = override.IdleLockMinutes
	}
	// Same never-merged bug as idle_lock_minutes: max_attachment_bytes
	// was documented as overridable but silently ignored.
	if override.MaxAttachmentBytes != 0 {
		into.MaxAttachmentBytes = override.MaxAttachmentBytes
	}
	if len(override.AttachmentPathAllowlist) > 0 {
		into.AttachmentPathAllowlist = override.AttachmentPathAllowlist
	}
	// keep_alive defaults false in the embedded config, so the only
	// way it turns on is the override setting it true; `keep_alive:
	// false` and an absent key both correctly leave it off.
	if override.KeepAlive {
		into.KeepAlive = true
	}
}

// sendFloorTools may never be weakened below prompt-with-zero-TTL:
// these are the tools that put words in the user's mouth to third
// parties. A stricter setting (deny) is allowed; allow or a nonzero
// approval-cache TTL is not — an override attempting either is
// rejected wholesale, keeping the previous policy in force (Reload)
// or the embedded defaults (startup).
var sendFloorTools = []string{
	"mail_send", "mail_send_draft", "mail_reply", "mail_reply_all", "mail_forward",
}

func enforceSendFloor(doc *document) error {
	for _, name := range sendFloorTools {
		p, ok := doc.Tools[name]
		if !ok {
			continue // no entry → tool doesn't register (default-deny)
		}
		if p.Decision == DecisionAllow {
			return fmt.Errorf("policy floor: %s cannot be set to allow (must stay prompt or deny)", name)
		}
		// parseDocument already validated the TTL string; TTLDuration
		// cannot panic here.
		if p.TTLDuration() != 0 {
			return fmt.Errorf("policy floor: %s ttl must be 0 (every send re-prompts); got %q", name, p.TTL)
		}
	}
	return nil
}

// destructiveFloorTools remove or rearrange mail the user may not get
// back easily (trash, move out of view, relabel, delete labels /
// folders / drafts, permanent delete). A prompt-injected model with
// these on `allow` could silently bury or destroy evidence of its own
// actions, so — like the send floor — no override may set them to
// allow. prompt (ttl at most maxDestructiveTTL — see enforceHardLimits)
// and deny are accepted; a violating override is rejected wholesale.
//
// H6 extended it to standing configuration that acts on mail later
// (rules_set / rules_run / rules_delete) and to spam reporting, which
// moves mail out of view and trains Proton's filter.
var destructiveFloorTools = []string{
	"mail_trash", "mail_move", "mail_label",
	"labels_delete", "folders_delete",
	"mail_draft_delete", "mail_delete_permanent",
	"rules_set", "rules_run", "rules_delete",
	"mail_report_spam",
}

// maxDestructiveTTL caps the approval-cache TTL of every destructive
// floor tool. One approval must not cover a year of silent trashing
// (the assessment's hostile policy set ttl: 8760h).
const maxDestructiveTTL = 15 * time.Minute

// homeDir is os.UserHomeDir, a var for tests.
var homeDir = os.UserHomeDir

// enforceHardLimits rejects (wholesale, like the floors) override
// settings no Touch ID approval can make acceptable (SECURITY H6):
//
//   - defaults: allow — every unknown / future tool would run unprompted;
//   - a destructive-floor tool with ttl > 15m;
//   - an attachment_path_allowlist entry that is "/", $HOME itself,
//     /Users, /Volumes, or any ancestor of $HOME (the daemon would read
//     any user file on a model's say-so).
func enforceHardLimits(doc *document) error {
	if doc.Defaults.Decision == DecisionAllow {
		return errors.New("policy limit: defaults cannot be allow (unknown tools must stay denied or prompt)")
	}
	for _, name := range destructiveFloorTools {
		p, ok := doc.Tools[name]
		if !ok {
			continue
		}
		if p.TTLDuration() > maxDestructiveTTL {
			return fmt.Errorf("policy limit: %s ttl %q exceeds %s (destructive tool)", name, p.TTL, maxDestructiveTTL)
		}
	}
	home, _ := homeDir()
	for _, dir := range doc.AttachmentPathAllowlist {
		if reason := tooBroadAllowlistEntry(dir, home); reason != "" {
			return fmt.Errorf("policy limit: attachment_path_allowlist entry %q is %s", dir, reason)
		}
	}
	return nil
}

// tooBroadAllowlistEntry returns why dir may not be an allowlist entry
// ("" if it may). Checks both the lexical path and, when it exists, its
// symlink-resolved form; comparisons are case-insensitive (APFS default).
func tooBroadAllowlistEntry(dir, home string) string {
	forms := []string{filepath.Clean(dir)}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		forms = append(forms, filepath.Clean(r))
	}
	var homes []string
	if home != "" {
		homes = append(homes, filepath.Clean(home))
		if r, err := filepath.EvalSymlinks(home); err == nil {
			homes = append(homes, filepath.Clean(r))
		}
	}
	for _, d := range forms {
		ld := strings.ToLower(d)
		switch ld {
		case "/":
			return "the filesystem root"
		case "/users", "/volumes", "/private/var/users":
			return "a top-level user/volume directory"
		}
		for _, h := range homes {
			lh := strings.ToLower(h)
			if ld == lh {
				return "your home directory"
			}
			if strings.HasPrefix(lh, ld+"/") {
				return "an ancestor of your home directory"
			}
		}
	}
	return ""
}

func enforceDestructiveFloor(doc *document) error {
	for _, name := range destructiveFloorTools {
		p, ok := doc.Tools[name]
		if !ok {
			continue
		}
		if p.Decision == DecisionAllow {
			return fmt.Errorf("policy floor: %s cannot be set to allow (destructive; must stay prompt or deny)", name)
		}
	}
	return nil
}

// DefaultOverridePath returns the canonical user-override location
// per the design spec. macOS-only path.
func DefaultOverridePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "policy.yaml"), nil
}

// Snapshot returns the currently-merged policy as a parsed document.
// Used by `protonmcp policy show` to print the effective config —
// users want to see what's actually in force, not just diff their
// override against the default mentally.
//
// H6: every field is copied (the old snapshot dropped keep_alive, the
// allowlist, idle lock and the attachment cap, so `policy show` hid
// exactly the settings a hostile override would change).
func (e *Engine) Snapshot() document {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := e.doc
	out.Tools = make(map[string]ToolPolicy, len(e.doc.Tools))
	for k, v := range e.doc.Tools {
		out.Tools[k] = v
	}
	out.AttachmentPathAllowlist = append([]string(nil), e.doc.AttachmentPathAllowlist...)
	return out
}

// snapshotView is the `policy show` rendering: every global field is
// printed even at its zero value (no omitempty), with the effective
// attachment cap.
type snapshotView struct {
	Defaults                ToolPolicy            `yaml:"defaults"`
	KeepAlive               bool                  `yaml:"keep_alive"`
	IdleLockMinutes         int                   `yaml:"idle_lock_minutes"`
	MaxAttachmentBytes      int64                 `yaml:"max_attachment_bytes"`
	AttachmentPathAllowlist []string              `yaml:"attachment_path_allowlist"`
	Tools                   map[string]ToolPolicy `yaml:"tools"`
}

// SnapshotYAML marshals Snapshot back to YAML for the `show` CLI.
func (e *Engine) SnapshotYAML() ([]byte, error) {
	s := e.Snapshot()
	allow := s.AttachmentPathAllowlist
	if allow == nil {
		allow = []string{}
	}
	return yaml.Marshal(snapshotView{
		Defaults:                s.Defaults,
		KeepAlive:               s.KeepAlive,
		IdleLockMinutes:         s.IdleLockMinutes,
		MaxAttachmentBytes:      e.MaxAttachmentBytes(),
		AttachmentPathAllowlist: allow,
		Tools:                   s.Tools,
	})
}

func parseDocument(data []byte) (document, error) {
	var doc document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return document{}, err
	}
	// Validate every tool entry has a known decision. Catches
	// typos ("decision: aloow") before they degrade silently to
	// the empty-string fallback (which would hit our deny default
	// — safe, but confusing). Also validates TTL parses cleanly
	// (lazy parsing in TTLDuration is fine at call-time, but we
	// want config errors surfaced at LOAD time).
	for name, p := range doc.Tools {
		switch p.Decision {
		case DecisionAllow, DecisionPrompt, DecisionDeny:
			// ok
		case "":
			return document{}, fmt.Errorf("tool %q: missing decision", name)
		default:
			return document{}, fmt.Errorf("tool %q: unknown decision %q", name, p.Decision)
		}
		if p.TTL != "" && p.TTL != "0" {
			if _, err := time.ParseDuration(p.TTL); err != nil {
				return document{}, fmt.Errorf("tool %q: invalid ttl %q: %w", name, p.TTL, err)
			}
		}
	}
	// Phase 7/A: idle_lock_minutes range-check. Negative means
	// misconfiguration; >24h is almost certainly a typo (10080 was
	// "I meant a week"). Reject early so the daemon doesn't start
	// with a misleading value.
	if doc.IdleLockMinutes < 0 || doc.IdleLockMinutes > 1440 {
		return document{}, fmt.Errorf("idle_lock_minutes must be in [0, 1440]; got %d", doc.IdleLockMinutes)
	}
	// Phase 8/A. Cap the override at 1 GiB — anything larger is
	// almost certainly a typo + would blow the 500 MiB cache
	// ceiling on the first download.
	if doc.MaxAttachmentBytes < 0 || doc.MaxAttachmentBytes > (1<<30) {
		return document{}, fmt.Errorf("max_attachment_bytes must be in [0, 1 GiB]; got %d", doc.MaxAttachmentBytes)
	}
	for _, dir := range doc.AttachmentPathAllowlist {
		if !filepath.IsAbs(dir) {
			return document{}, fmt.Errorf("attachment_path_allowlist entries must be absolute paths; got %q", dir)
		}
	}
	return doc, nil
}

// IdleLockMinutes returns the configured idle-timer duration, or 0
// if disabled. Phase 7/A — the runtime's idle-lock goroutine polls
// this via the engine so policy reload picks up new values without
// a daemon restart.
func (e *Engine) IdleLockMinutes() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.doc.IdleLockMinutes
}

// MaxAttachmentBytes returns the per-attachment size ceiling from
// the merged policy, or DefaultMaxAttachmentBytes if the policy
// doesn't specify one. Phase 8/A — enforced by
// mail_download_attachment + mail_send.attachments.
func (e *Engine) MaxAttachmentBytes() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.doc.MaxAttachmentBytes <= 0 {
		return DefaultMaxAttachmentBytes
	}
	return e.doc.MaxAttachmentBytes
}

// KeepAlive reports whether the user has Keep Alive switched on.
// Read at event time (not cached by callers) so a menu-bar toggle
// plus policy reload takes effect on the very next lock trigger.
func (e *Engine) KeepAlive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.doc.KeepAlive
}

// AttachmentPathAllowlist returns the directories path-based
// attachments may be read from. Empty slice means the feature is
// disabled. Returns a copy — callers can't mutate engine state.
func (e *Engine) AttachmentPathAllowlist() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, len(e.doc.AttachmentPathAllowlist))
	copy(out, e.doc.AttachmentPathAllowlist)
	return out
}
