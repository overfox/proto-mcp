package policy

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Weakening detection (SECURITY H6).
//
// policy.yaml lives in a user-writable directory, so anything running
// as the user — including an LLM with a shell connector — can rewrite
// it and `protonmcp policy reload`. The floors and hard limits refuse
// the worst settings outright; everything else that LOOSENS the
// embedded defaults is listed here and must be approved with Touch ID
// at the Mac before it takes effect (see Gate / TouchIDGate).

// decisionRank orders decisions by permissiveness.
func decisionRank(d Decision) int {
	switch d {
	case DecisionAllow:
		return 2
	case DecisionPrompt:
		return 1
	default: // deny, "" (→ deny)
		return 0
	}
}

func effDecision(d Decision) Decision {
	if d == "" {
		return DecisionDeny
	}
	return d
}

func effMaxAttachment(n int64) int64 {
	if n <= 0 {
		return DefaultMaxAttachmentBytes
	}
	return n
}

// keepAliveWeakening is the exact string for "keep_alive turned on"; a
// weakening list consisting of only this gets the "Turn on Keep Alive?"
// prompt (the menu bar's toggle).
const keepAliveWeakening = "keep_alive: on (no Touch ID for attachment reads; no idle/screen-lock/sleep auto-lock)"

// computeWeakenings lists every way merged is more permissive than
// base (the embedded defaults). Global settings first, then tools in
// name order. Empty when merged is equal or stricter everywhere.
func computeWeakenings(base, merged document) []string {
	var out []string
	if decisionRank(merged.Defaults.Decision) > decisionRank(base.Defaults.Decision) {
		out = append(out, fmt.Sprintf("defaults: %s → %s",
			effDecision(base.Defaults.Decision), effDecision(merged.Defaults.Decision)))
	}
	if merged.KeepAlive && !base.KeepAlive {
		out = append(out, keepAliveWeakening)
	}
	if base.IdleLockMinutes > 0 && (merged.IdleLockMinutes == 0 || merged.IdleLockMinutes > base.IdleLockMinutes) {
		out = append(out, fmt.Sprintf("idle_lock_minutes: %d → %d", base.IdleLockMinutes, merged.IdleLockMinutes))
	}
	if b, m := effMaxAttachment(base.MaxAttachmentBytes), effMaxAttachment(merged.MaxAttachmentBytes); m > b {
		out = append(out, fmt.Sprintf("max_attachment_bytes: %d → %d", b, m))
	}
	baseAllow := map[string]bool{}
	for _, d := range base.AttachmentPathAllowlist {
		baseAllow[d] = true
	}
	for _, d := range merged.AttachmentPathAllowlist {
		if !baseAllow[d] {
			out = append(out, "attachment_path_allowlist: + "+promptSafe(d))
		}
	}

	names := make([]string, 0, len(merged.Tools))
	for n := range merged.Tools {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		m := merged.Tools[name]
		b, ok := base.Tools[name]
		if !ok {
			// A tool the defaults don't list falls back to defaults
			// (deny): any entry for it is measured against that.
			b = ToolPolicy{Decision: effDecision(base.Defaults.Decision)}
		}
		label := promptSafe(name)
		if decisionRank(m.Decision) > decisionRank(b.Decision) {
			out = append(out, fmt.Sprintf("%s: %s → %s", label, effDecision(b.Decision), effDecision(m.Decision)))
		} else if m.Decision == DecisionPrompt && b.Decision == DecisionPrompt && m.TTLDuration() > b.TTLDuration() {
			out = append(out, fmt.Sprintf("%s: ttl %s → %s", label, ttlLabel(b.TTL), ttlLabel(m.TTL)))
		}
		if len(b.AllowedRecipients) > 0 {
			if len(m.AllowedRecipients) == 0 {
				out = append(out, label+": allowed_recipients removed")
			} else {
				had := map[string]bool{}
				for _, r := range b.AllowedRecipients {
					had[strings.ToLower(r)] = true
				}
				for _, r := range m.AllowedRecipients {
					if !had[strings.ToLower(r)] {
						out = append(out, label+": allowed_recipients + "+promptSafe(r))
					}
				}
			}
		}
	}
	return out
}

func ttlLabel(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// promptSafe strips non-printing / format characters (bidi overrides,
// zero-width joiners, controls) and caps length: tool names and paths
// come from the user-writable YAML and end up in the Touch ID dialog.
func promptSafe(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue
		}
		if n >= 80 {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// maxPromptWeakenings caps how many lines the dialog lists.
const maxPromptWeakenings = 10

// WeakeningPrompt builds the Touch ID dialog for a weakening approval.
// Keep Alive alone (the menu bar toggle) gets a plain "Turn on Keep
// Alive?" dialog.
func WeakeningPrompt(ws []string) (title, body string) {
	if len(ws) == 1 && ws[0] == keepAliveWeakening {
		return "Turn on Keep Alive?",
			"Keep Alive skips Touch ID for attachment reads and turns off idle, screen-lock and sleep auto-lock " +
				"until you switch it off."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "policy.yaml loosens %d setting(s) vs the built-in defaults:\n", len(ws))
	for i, w := range ws {
		if i == maxPromptWeakenings {
			fmt.Fprintf(&b, "…and %d more (see `protonmcp policy show`)\n", len(ws)-i)
			break
		}
		b.WriteString("• " + w + "\n")
	}
	b.WriteString("\nApprove only if you made this change yourself.")
	return "Loosen Proton MCP policy?", b.String()
}
