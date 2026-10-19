package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

// hostileYAML is the assessment's H6 PoC: a policy.yaml any same-user
// process (or an LLM with a shell connector) could write. It used to be
// accepted wholesale.
const hostileYAML = `
defaults: {decision: allow}
keep_alive: true
attachment_path_allowlist: ["/"]
max_attachment_bytes: 1073741824
tools:
  rules_set: {decision: allow}
  rules_run: {decision: allow}
  rules_delete: {decision: allow}
  mail_report_spam: {decision: allow}
  labels_create: {decision: allow}
  folders_update: {decision: allow}
  mail_save_attachment: {decision: allow}
  mail_export_eml: {decision: allow}
  mail_send: {decision: prompt, ttl: "0s", allowed_recipients: []}
  proton_connect: {decision: deny}
`

func withHome(t *testing.T, home string) {
	t.Helper()
	prev := homeDir
	homeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDir = prev })
}

// H6 regression: the hostile override is refused as a whole; nothing in
// it takes effect.
func TestHostilePolicyRejected(t *testing.T) {
	path := writeOverride(t, hostileYAML)
	e, err := New(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.OverrideError() == nil {
		t.Fatal("hostile override was accepted")
	}
	for _, tool := range []string{"rules_set", "rules_run", "mail_report_spam", "mail_save_attachment", "unknown_tool"} {
		if d, _ := e.Decide(tool, nil, caller.Caller{}); d == DecisionAllow {
			t.Errorf("%s = allow after hostile override", tool)
		}
	}
	if e.KeepAlive() || len(e.AttachmentPathAllowlist()) != 0 || e.MaxAttachmentBytes() != DefaultMaxAttachmentBytes {
		t.Errorf("globals leaked: keep_alive=%v allowlist=%v max=%d",
			e.KeepAlive(), e.AttachmentPathAllowlist(), e.MaxAttachmentBytes())
	}
}

func TestHardLimits(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	parent := filepath.Dir(home)
	cases := map[string]string{
		"defaults allow":         "defaults: {decision: allow}\n",
		"root allowlist":         "attachment_path_allowlist: [\"/\"]\n",
		"home allowlist":         "attachment_path_allowlist: [\"" + home + "\"]\n",
		"home trailing slash":    "attachment_path_allowlist: [\"" + home + "/\"]\n",
		"home ancestor":          "attachment_path_allowlist: [\"" + parent + "\"]\n",
		"/Users":                 "attachment_path_allowlist: [\"/Users\"]\n",
		"/users case":            "attachment_path_allowlist: [\"/users\"]\n",
		"/Volumes":               "attachment_path_allowlist: [\"/Volumes\"]\n",
		"dotdot to /Users":       "attachment_path_allowlist: [\"/Users/x/..\"]\n",
		"trash ttl 1y":           "tools:\n  mail_trash: {decision: prompt, ttl: 8760h}\n",
		"draft_delete ttl 16m":   "tools:\n  mail_draft_delete: {decision: prompt, ttl: 16m}\n",
		"report_spam allow":      "tools:\n  mail_report_spam: {decision: allow}\n",
		"rules_delete allow":     "tools:\n  rules_delete: {decision: allow}\n",
		"folders_delete allow":   "tools:\n  folders_delete: {decision: allow}\n",
		"rules_run ttl 24h":      "tools:\n  rules_run: {decision: prompt, ttl: 24h}\n",
		"labels_delete allow":    "tools:\n  labels_delete: {decision: allow}\n",
		"rules_set allow":        "tools:\n  rules_set: {decision: allow}\n",
		"mail_trash allow (old)": "tools:\n  mail_trash: {decision: allow}\n",
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			e, _ := New(context.Background(), writeOverride(t, y), nil)
			if e.OverrideError() == nil {
				t.Fatalf("override %q accepted", y)
			}
		})
	}
	// A narrow allowlist entry inside $HOME is fine (prompted as a
	// weakening by the daemon, but not hard-rejected).
	e, _ := New(context.Background(), writeOverride(t, "attachment_path_allowlist: [\""+home+"/Documents/out\"]\n"), nil)
	if e.OverrideError() != nil {
		t.Fatalf("narrow allowlist rejected: %v", e.OverrideError())
	}
}

// Reload with a hard-limit violation keeps the previous policy.
func TestReloadHardLimitKeepsPrevious(t *testing.T) {
	path := writeOverride(t, "tools:\n  mail_trash: {decision: prompt, ttl: 10m}\n")
	e, _ := New(context.Background(), path, nil)
	if err := os.WriteFile(path, []byte("tools:\n  mail_trash: {decision: prompt, ttl: 8760h}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err == nil {
		t.Fatal("reload accepted ttl 8760h")
	}
	if _, p := e.Decide("mail_trash", nil, caller.Caller{}); p.TTL != "10m" {
		t.Fatalf("ttl = %q, want previous 10m", p.TTL)
	}
}

func TestComputeWeakenings(t *testing.T) {
	ws, _, err := AnalyzeOverride(writeOverride(t, `
keep_alive: true
max_attachment_bytes: 52428800
tools:
  labels_create: {decision: allow}
  mail_trash: {decision: prompt, ttl: 15m}
  mail_move: {decision: deny}
  brand_new_tool: {decision: prompt}
`))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(ws, "\n")
	for _, want := range []string{"keep_alive: on", "max_attachment_bytes", "labels_create: prompt → allow",
		"mail_trash: ttl 5m → 15m", "brand_new_tool: deny → prompt"} {
		if !strings.Contains(joined, want) {
			t.Errorf("weakenings missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "mail_move") {
		t.Errorf("a stricter setting (mail_move: deny) was reported as a weakening:\n%s", joined)
	}

	// Stricter-only override → no weakenings.
	ws, _, _ = AnalyzeOverride(writeOverride(t, "idle_lock_minutes: 15\ntools:\n  mail_list: {decision: deny}\n"))
	if len(ws) != 0 {
		t.Fatalf("stricter override reported weakenings: %v", ws)
	}
}

// fakeKey is an in-memory stand-in for the Keychain HMAC key.
type fakeKey struct{ key []byte }

func (k *fakeKey) get(create bool) ([]byte, error) {
	if k.key == nil {
		if !create {
			return nil, errors.New("no key")
		}
		k.key = []byte("0123456789abcdef0123456789abcdef")
	}
	return k.key, nil
}

type fakeApprover struct {
	calls  int
	titles []string
	bodies []string
	err    error
}

func (a *fakeApprover) prompt(_ context.Context, title, body string) error {
	a.calls++
	a.titles = append(a.titles, title)
	a.bodies = append(a.bodies, body)
	return a.err
}

func gatedEngine(t *testing.T, path string, store ApprovalStore, ap *fakeApprover) *Engine {
	t.Helper()
	e, err := NewWithGate(context.Background(), path, nil, TouchIDGate(store, ap.prompt, nil))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A weakening needs Touch ID; declined at startup → embedded defaults.
func TestWeakeningRequiresApproval_StartupDeclined(t *testing.T) {
	path := writeOverride(t, "tools:\n  labels_create: {decision: allow}\n")
	store := ApprovalStore{Path: filepath.Join(t.TempDir(), "policy.approved"), Key: (&fakeKey{}).get}
	ap := &fakeApprover{err: errors.New("user canceled approval")}
	e := gatedEngine(t, path, store, ap)
	if ap.calls != 1 {
		t.Fatalf("prompts = %d, want 1", ap.calls)
	}
	if !errors.Is(e.OverrideError(), ErrWeakeningNotApproved) {
		t.Fatalf("OverrideError = %v, want ErrWeakeningNotApproved", e.OverrideError())
	}
	if d, _ := e.Decide("labels_create", nil, caller.Caller{}); d != DecisionPrompt {
		t.Fatalf("labels_create = %s, want default prompt", d)
	}
	if !strings.Contains(ap.bodies[0], "labels_create: prompt → allow") {
		t.Fatalf("prompt body doesn't list the loosening:\n%s", ap.bodies[0])
	}
}

// Approved → applied, hash recorded, and the same content is reused
// without a second prompt (restart / no-op reload).
func TestWeakeningApprovedHashReused(t *testing.T) {
	path := writeOverride(t, "tools:\n  labels_create: {decision: allow}\n")
	key := &fakeKey{}
	store := ApprovalStore{Path: filepath.Join(t.TempDir(), "policy.approved"), Key: key.get}
	ap := &fakeApprover{}
	e := gatedEngine(t, path, store, ap)
	if d, _ := e.Decide("labels_create", nil, caller.Caller{}); d != DecisionAllow {
		t.Fatalf("approved weakening not applied: %s", d)
	}
	if ap.calls != 1 {
		t.Fatalf("prompts = %d, want 1", ap.calls)
	}
	if fi, err := os.Stat(store.Path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("policy.approved: %v mode=%v", err, fi)
	}

	// Restart: no prompt.
	e2 := gatedEngine(t, path, store, ap)
	if ap.calls != 1 {
		t.Fatalf("restart re-prompted (calls=%d)", ap.calls)
	}
	if d, _ := e2.Decide("labels_create", nil, caller.Caller{}); d != DecisionAllow {
		t.Fatal("approved weakening not applied after restart")
	}
	// Reload unchanged: no prompt.
	if err := e2.Reload(); err != nil || ap.calls != 1 {
		t.Fatalf("no-op reload: err=%v calls=%d", err, ap.calls)
	}

	// Changed content → new prompt; declined → previous policy kept.
	if err := os.WriteFile(path, []byte("tools:\n  labels_create: {decision: allow}\n  folders_create: {decision: allow}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ap.err = errors.New("declined")
	if err := e2.Reload(); !errors.Is(err, ErrWeakeningNotApproved) {
		t.Fatalf("reload err = %v, want ErrWeakeningNotApproved", err)
	}
	if ap.calls != 2 {
		t.Fatalf("changed content didn't prompt (calls=%d)", ap.calls)
	}
	if d, _ := e2.Decide("folders_create", nil, caller.Caller{}); d != DecisionPrompt {
		t.Fatal("declined reload applied anyway")
	}
	if d, _ := e2.Decide("labels_create", nil, caller.Caller{}); d != DecisionAllow {
		t.Fatal("declined reload dropped the previously approved policy")
	}
}

// A forged / tampered policy.approved (MAC mismatch, or no Keychain
// key to verify it) re-prompts.
func TestWeakeningHMACMismatchReprompts(t *testing.T) {
	data := "tools:\n  labels_create: {decision: allow}\n"
	path := writeOverride(t, data)
	approved := filepath.Join(t.TempDir(), "policy.approved")
	hash := ContentHash([]byte(data))
	// Attacker writes the right hash with a made-up MAC.
	if err := os.WriteFile(approved, []byte("v1 "+hash+" "+strings.Repeat("00", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := &fakeKey{}
	_, _ = key.get(true)
	ap := &fakeApprover{err: errors.New("declined")}
	e := gatedEngine(t, path, ApprovalStore{Path: approved, Key: key.get}, ap)
	if ap.calls != 1 {
		t.Fatalf("forged approval file honored (prompts=%d)", ap.calls)
	}
	if d, _ := e.Decide("labels_create", nil, caller.Caller{}); d == DecisionAllow {
		t.Fatal("forged approval applied the weakening")
	}

	// A valid record made under a different key is also rejected.
	other := &fakeKey{key: []byte("ffffffffffffffffffffffffffffffff")}
	if err := (ApprovalStore{Path: approved, Key: other.get}).Record(hash); err != nil {
		t.Fatal(err)
	}
	_ = gatedEngine(t, path, ApprovalStore{Path: approved, Key: key.get}, ap)
	if ap.calls != 2 {
		t.Fatalf("record under a foreign key honored (prompts=%d)", ap.calls)
	}
}

// Keep Alive alone (the menu bar toggle) gets the plain prompt.
func TestKeepAliveOnlyPrompt(t *testing.T) {
	path := writeOverride(t, "keep_alive: true\nidle_lock_minutes: 0\n")
	ap := &fakeApprover{}
	e := gatedEngine(t, path, ApprovalStore{Path: filepath.Join(t.TempDir(), "a"), Key: (&fakeKey{}).get}, ap)
	if ap.calls != 1 || ap.titles[0] != "Turn on Keep Alive?" {
		t.Fatalf("calls=%d titles=%v", ap.calls, ap.titles)
	}
	if !e.KeepAlive() {
		t.Fatal("approved keep_alive not applied")
	}
	// Turning it off (stricter) needs no prompt.
	if err := os.WriteFile(path, []byte("keep_alive: false\nidle_lock_minutes: 15\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err != nil || ap.calls != 1 || e.KeepAlive() {
		t.Fatalf("keep alive off: err=%v calls=%d keepalive=%v", err, ap.calls, e.KeepAlive())
	}
}

// `policy show` prints every field, including the ones the old
// snapshot dropped.
func TestSnapshotYAMLShowsAllFields(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	e, _ := New(context.Background(), writeOverride(t,
		"keep_alive: true\nidle_lock_minutes: 7\nattachment_path_allowlist: [\""+home+"/out\"]\n"), nil)
	out, err := e.SnapshotYAML()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"keep_alive: true", "idle_lock_minutes: 7", "max_attachment_bytes: 26214400", home + "/out"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("snapshot missing %q:\n%s", want, out)
		}
	}
}

// Tool names from the YAML are sanitized before they reach the dialog.
func TestWeakeningPromptStripsFormatChars(t *testing.T) {
	ws, _, _ := AnalyzeOverride(writeOverride(t, "tools:\n  \"evil\u202etool\": {decision: allow}\n"))
	_, body := WeakeningPrompt(ws)
	if strings.ContainsRune(body, '\u202e') {
		t.Fatal("bidi override reached the prompt")
	}
}
