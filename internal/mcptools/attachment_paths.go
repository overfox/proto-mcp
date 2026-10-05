package mcptools

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Tiered path attachments (attachments[].path on the draft/send tools).
//
// Threat model: the model is prompt-injectable (it reads untrusted
// email), and the daemon reads host files on its say-so. The tiers keep
// "attach the PDF on my Desktop" possible without letting an injected
// model quietly mail out ~/.ssh/id_rsa:
//
//	a. inside attachment_path_allowlist   → attach, no extra prompt
//	b. elsewhere under $HOME or /Volumes  → attach only after a Touch ID
//	   approval that shows the full absolute path + size (drafts: a
//	   dedicated per-call prompt; sends: listed in the send dialog)
//	c. hard denylist (credentials, keychains, app state, hidden paths
//	   outside the allowlist) → never, regardless of approval
//	   anything else (/etc, /tmp, /private, ...) → refused
//
// Symlinks are resolved BEFORE every check, so a link named report.pdf
// pointing at ~/.ssh/id_rsa is judged as ~/.ssh/id_rsa. The read uses
// O_NOFOLLOW on the resolved path and verifies (os.SameFile) it is the
// same file that was checked and approved.

type pathTier int

const (
	// tierAllowlisted: inside attachment_path_allowlist.
	tierAllowlisted pathTier = iota
	// tierNeedsApproval: under $HOME or /Volumes, outside the allowlist.
	tierNeedsApproval
)

// resolvedAttachmentPath is a path attachment after resolution and
// classification, before its bytes are read.
type resolvedAttachmentPath struct {
	Requested string // as the caller passed it
	Resolved  string // symlink-resolved absolute path
	Tier      pathTier
	Size      int64
	info      os.FileInfo
}

// deniedHomeDirs (relative to $HOME, lower-cased — APFS is
// case-insensitive by default) can never be attached from, allowlist or
// approval notwithstanding.
var deniedHomeDirs = []string{
	".ssh",
	".gnupg",
	".aws",
	".config/gcloud",
	".kube",
	".docker",
	"library/keychains",
	"library/cookies",
	"library/application support/protonmcp",
	"library/application support/claude",
	"library/mail",
}

// deniedNamePatterns are filepath.Match patterns (lower-case) for file
// names that are credentials / key material wherever they live.
var deniedNamePatterns = []string{
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"*.keychain*",
	"id_rsa*",
	"id_ed25519*",
	".env*",
	"*.kdbx",
	"credentials*",
	".netrc",
}

// coworkPathHint explains VM-only paths: Cowork / sandboxed clients see
// their own filesystem (/sessions/..., /mnt/...), which doesn't exist
// on the host where this daemon runs.
func coworkPathHint(p string) string {
	if strings.HasPrefix(p, "/sessions/") || strings.HasPrefix(p, "/mnt/") {
		return " (this looks like a path inside a Cowork/VM sandbox, not a path on the host Mac — " +
			"use the file's real location on the Mac, e.g. /Users/<you>/Documents/..., or content_b64)"
	}
	return ""
}

// within reports whether p is dir or inside it (both already cleaned /
// resolved). filepath.Rel, not string prefix, so /allowed-evil doesn't
// match /allowed.
func within(dir, p string) (string, bool) {
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func resolvedOrSelf(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// inAttachmentAllowlist reports whether resolved sits inside one of the
// symlink-resolved attachment_path_allowlist directories.
func inAttachmentAllowlist(deps Deps, resolved string) bool {
	if deps.Policy == nil {
		return false
	}
	for _, dir := range deps.Policy.AttachmentPathAllowlist() {
		rdir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue // unresolvable allowlist entry grants nothing
		}
		if _, ok := within(rdir, resolved); ok {
			return true
		}
	}
	return false
}

// hasHiddenComponent reports whether any component of rel starts with
// "." (rel is relative to $HOME or /Volumes).
func hasHiddenComponent(rel string) bool {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}
	}
	return false
}

// checkAttachmentDenylist applies tier c. relHome is resolved's path
// relative to $HOME (lower-cased) or "" when not under home; relVol the
// same for /Volumes.
func checkAttachmentDenylist(resolved, relHome, relVol string, underHome, underVol, allowlisted bool) error {
	base := strings.ToLower(filepath.Base(resolved))
	for _, pat := range deniedNamePatterns {
		if ok, _ := filepath.Match(pat, base); ok {
			return fmt.Errorf("refusing to attach %q: files named like %q are credentials/key material and are never attachable", resolved, pat)
		}
	}
	if underHome {
		for _, d := range deniedHomeDirs {
			if relHome == d || strings.HasPrefix(relHome, d+"/") {
				return fmt.Errorf("refusing to attach %q: ~/%s is never attachable (credentials / app state)", resolved, d)
			}
		}
		if !allowlisted && hasHiddenComponent(relHome) {
			return fmt.Errorf("refusing to attach %q: hidden files/folders under your home folder are never attachable "+
				"unless their directory is in attachment_path_allowlist", resolved)
		}
	}
	if underVol && !allowlisted && hasHiddenComponent(relVol) {
		return fmt.Errorf("refusing to attach %q: hidden files/folders are never attachable unless allowlisted", resolved)
	}
	return nil
}

// resolveAttachmentPath resolves and classifies one path attachment
// without reading it. Errors are refusals (tier c, not found, not a
// regular file, outside $HOME and /Volumes).
func resolveAttachmentPath(deps Deps, p string) (resolvedAttachmentPath, error) {
	if p == "" || !filepath.IsAbs(p) {
		return resolvedAttachmentPath{}, fmt.Errorf("path %q must be absolute%s", p, coworkPathHint(p))
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return resolvedAttachmentPath{}, fmt.Errorf("resolve path %q: %w%s", p, err, coworkPathHint(p))
	}
	resolved = filepath.Clean(resolved)

	allowlisted := inAttachmentAllowlist(deps, resolved)

	var relHome, relVol string
	underHome, underVol := false, false
	if home, herr := os.UserHomeDir(); herr == nil && home != "" {
		rhome := strings.ToLower(resolvedOrSelf(home))
		relHome, underHome = within(rhome, strings.ToLower(resolved))
	}
	relVol, underVol = within(strings.ToLower(resolvedOrSelf("/Volumes")), strings.ToLower(resolved))

	if err := checkAttachmentDenylist(resolved, relHome, relVol, underHome, underVol, allowlisted); err != nil {
		return resolvedAttachmentPath{}, err
	}

	st, err := os.Stat(resolved)
	if err != nil {
		return resolvedAttachmentPath{}, fmt.Errorf("stat %q: %w", p, err)
	}
	if !st.Mode().IsRegular() {
		return resolvedAttachmentPath{}, fmt.Errorf("path %q is not a regular file", p)
	}

	out := resolvedAttachmentPath{Requested: p, Resolved: resolved, Size: st.Size(), info: st}
	switch {
	case allowlisted:
		out.Tier = tierAllowlisted
	case underHome || underVol:
		out.Tier = tierNeedsApproval
	default:
		return resolvedAttachmentPath{}, fmt.Errorf("path %q (resolved %q) is outside your home folder and /Volumes; "+
			"only files there can be attached", p, resolved)
	}
	return out, nil
}

// readResolvedAttachment reads a path that resolveAttachmentPath
// accepted. O_NOFOLLOW is a TOCTOU backstop; SameFile confirms the
// opened file is the one that was checked (and, for tier b, approved);
// the size cap is enforced from fstat AND on the read itself so a file
// growing after the check can't balloon memory.
func readResolvedAttachment(r resolvedAttachmentPath, cap int64) ([]byte, error) {
	f, err := os.OpenFile(r.Resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", r.Requested, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", r.Requested, err)
	}
	if r.info != nil && !os.SameFile(r.info, st) {
		return nil, fmt.Errorf("%q changed after it was checked; refusing", r.Requested)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("path %q is not a regular file", r.Requested)
	}
	if st.Size() > cap {
		return nil, fmt.Errorf(
			"%q is %d bytes; exceeds max_attachment_bytes (%d). "+
				"Increase the policy cap in ~/Library/Application Support/protonmcp/policy.yaml to override.",
			r.Requested, st.Size(), cap,
		)
	}
	b, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", r.Requested, err)
	}
	if int64(len(b)) > cap {
		return nil, fmt.Errorf("%q grew past max_attachment_bytes (%d) while reading", r.Requested, cap)
	}
	return b, nil
}

// clipRunes truncates s to max runes, appending "…" when cut.
func clipRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}
