package mcptools

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
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
// pointing at ~/.ssh/id_rsa is judged as ~/.ssh/id_rsa. Every
// comparison runs on canonName (Unicode case fold + NFKC), because
// APFS opens "~/Library/Cookieſ" as ~/Library/Cookies. Files with more
// than one hard link are refused (a link elsewhere disguises a
// protected file and no path check can see it). The read uses
// O_NOFOLLOW on the resolved path, verifies the opened file is the one
// that was checked — and, for tier b, the one an approval dialog
// showed (device, inode, size, mtime) — and re-runs the denylist on
// the kernel's own name for the open file (F_GETPATH).

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
	fp        fileFingerprint
}

// deniedHomeDirs (relative to a home folder, compared after canonName)
// can never be attached from, allowlist or approval notwithstanding.
// Applied to $HOME and to every /Volumes/<vol>/Users/<name> home.
var deniedHomeDirs = canonList(
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
)

// deniedNamePatterns are filepath.Match patterns (compared after
// canonName) for file names that are credentials / key material
// wherever they live.
var deniedNamePatterns = canonList(
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
)

func canonList(items ...string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = canonName(s)
	}
	return out
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
// "." (rel is relative to a home folder or /Volumes).
func hasHiddenComponent(rel string) bool {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}
	}
	return false
}

// pathClass is where a resolved path sits, for tiering.
type pathClass struct {
	allowlisted bool
	underHome   bool
	underVol    bool
}

// classifyAttachmentPath applies tier c to resolved and reports where
// it sits. All comparisons are on canonName forms.
func classifyAttachmentPath(deps Deps, resolved string) (pathClass, error) {
	return classifyPathAllowlisted(resolved, inAttachmentAllowlist(deps, resolved))
}

// classifyPathAllowlisted is classifyAttachmentPath with the allowlist
// membership already decided.
func classifyPathAllowlisted(resolved string, allowlisted bool) (pathClass, error) {
	pc := pathClass{allowlisted: allowlisted}
	c := canonName(resolved)

	var relHome string
	if home, herr := os.UserHomeDir(); herr == nil && home != "" {
		relHome, pc.underHome = within(canonName(resolvedOrSelf(home)), c)
	}
	relVol, underVol := within(canonName(resolvedOrSelf("/Volumes")), c)
	pc.underVol = underVol

	base := canonName(filepath.Base(resolved))
	for _, pat := range deniedNamePatterns {
		if ok, _ := filepath.Match(pat, base); ok {
			return pc, fmt.Errorf("refusing to attach %q: files named like %q are credentials/key material and are never attachable", resolved, pat)
		}
	}
	if pc.underHome {
		if err := checkHomeDenylist(resolved, "~/", relHome, pc.allowlisted); err != nil {
			return pc, err
		}
	}
	if pc.underVol {
		// Another Mac's (or a backup's) home folder on an external
		// volume holds the same secrets as ours: /Volumes/<vol>/Users/
		// <name>/... gets the home rules relative to that home.
		parts := strings.Split(relVol, string(filepath.Separator))
		if len(parts) >= 3 && parts[1] == canonName("users") {
			homeLabel := "/Volumes/" + parts[0] + "/Users/" + parts[2] + "/"
			if err := checkHomeDenylist(resolved, homeLabel, filepath.Join(parts[3:]...), pc.allowlisted); err != nil {
				return pc, err
			}
		}
		if !pc.allowlisted && hasHiddenComponent(relVol) {
			return pc, fmt.Errorf("refusing to attach %q: hidden files/folders are never attachable unless allowlisted", resolved)
		}
	}
	return pc, nil
}

// checkHomeDenylist applies the home-folder rules to rel (canonical,
// relative to a home folder labelled homeLabel in messages).
func checkHomeDenylist(resolved, homeLabel, rel string, allowlisted bool) error {
	for _, d := range deniedHomeDirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return fmt.Errorf("refusing to attach %q: %s%s is never attachable (credentials / app state)", resolved, homeLabel, d)
		}
	}
	if !allowlisted && hasHiddenComponent(rel) {
		return fmt.Errorf("refusing to attach %q: hidden files/folders under a home folder are never attachable "+
			"unless their directory is in attachment_path_allowlist", resolved)
	}
	return nil
}

// fileFingerprint identifies one version of one file: an approval is
// bound to it, not to the path string.
type fileFingerprint struct {
	dev, ino uint64
	size     int64
	mtimeNs  int64
	nlink    uint64
}

func fingerprintOf(fi os.FileInfo) fileFingerprint {
	fp := fileFingerprint{size: fi.Size(), mtimeNs: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fp.dev = uint64(st.Dev)
		fp.ino = uint64(st.Ino)
		fp.nlink = uint64(st.Nlink)
	}
	return fp
}

func (f fileFingerprint) sameVersion(o fileFingerprint) bool {
	return f.dev == o.dev && f.ino == o.ino && f.size == o.size && f.mtimeNs == o.mtimeNs
}

func hardLinkError(p string, n uint64) error {
	return fmt.Errorf("refusing to attach %q: it has %d hard links, and a hard link can disguise a protected "+
		"file's real location — attach a copy of the file instead", p, n)
}

// shownFiles records the identity of every out-of-allowlist file at the
// moment an approval dialog listed it (resolveAttachmentPath is what the
// send dialogs call). The send handler runs after the user approved,
// re-resolving the same path; if the file was replaced or rewritten in
// between, the identity no longer matches what was shown and the read
// is refused. Records are kept (not consumed) for shownFileTTL, which
// outlives the send-approval ledger; every unexpired record for a path
// must match, so a second dialog after a swap can't launder it.
const shownFileTTL = 5 * time.Minute

type shownFileRecord struct {
	fp fileFingerprint
	at time.Time
}

type shownFileRegistry struct {
	mu  sync.Mutex
	m   map[string][]shownFileRecord
	now func() time.Time
}

var shownFiles = &shownFileRegistry{m: map[string][]shownFileRecord{}, now: time.Now}

func (r *shownFileRegistry) gcLocked(now time.Time) {
	for p, recs := range r.m {
		kept := recs[:0]
		for _, rec := range recs {
			if now.Sub(rec.at) < shownFileTTL {
				kept = append(kept, rec)
			}
		}
		if len(kept) == 0 {
			delete(r.m, p)
		} else {
			r.m[p] = kept
		}
	}
}

func (r *shownFileRegistry) record(path string, fp fileFingerprint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.gcLocked(now)
	r.m[path] = append(r.m[path], shownFileRecord{fp: fp, at: now})
}

// check returns an error if any unexpired record for path disagrees
// with fp. No record → nil (the draft flow approves inside the handler,
// after resolve; readResolvedAttachment's resolve-time comparison
// covers that window).
func (r *shownFileRegistry) check(path string, fp fileFingerprint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked(r.now())
	for _, rec := range r.m[path] {
		if !rec.fp.sameVersion(fp) {
			return fmt.Errorf("%q changed after it was shown in an approval dialog; refusing "+
				"(retry in a few minutes so a fresh dialog shows the current file)", path)
		}
	}
	return nil
}

// resolveAttachmentPath resolves and classifies one path attachment
// for an approval dialog: it's resolveAttachmentPathForRead plus a
// record of the file's identity, which the later read must match.
func resolveAttachmentPath(deps Deps, p string) (resolvedAttachmentPath, error) {
	r, err := resolveAttachmentPathForRead(deps, p)
	if err == nil && r.Tier == tierNeedsApproval {
		shownFiles.record(r.Resolved, r.fp)
	}
	return r, err
}

// resolveAttachmentPathForRead resolves and classifies one path
// attachment without reading it. Errors are refusals (tier c, not
// found, not a regular file, hard-linked, outside $HOME and /Volumes).
func resolveAttachmentPathForRead(deps Deps, p string) (resolvedAttachmentPath, error) {
	if p == "" || !filepath.IsAbs(p) {
		return resolvedAttachmentPath{}, fmt.Errorf("path %q must be absolute%s", p, coworkPathHint(p))
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return resolvedAttachmentPath{}, fmt.Errorf("resolve path %q: %w%s", p, err, coworkPathHint(p))
	}
	resolved = filepath.Clean(resolved)

	pc, err := classifyAttachmentPath(deps, resolved)
	if err != nil {
		return resolvedAttachmentPath{}, err
	}

	st, err := os.Stat(resolved)
	if err != nil {
		return resolvedAttachmentPath{}, fmt.Errorf("stat %q: %w", p, err)
	}
	if !st.Mode().IsRegular() {
		return resolvedAttachmentPath{}, fmt.Errorf("path %q is not a regular file", p)
	}
	fp := fingerprintOf(st)
	if fp.nlink > 1 {
		return resolvedAttachmentPath{}, hardLinkError(p, fp.nlink)
	}

	out := resolvedAttachmentPath{Requested: p, Resolved: resolved, Size: st.Size(), info: st, fp: fp}
	switch {
	case pc.allowlisted:
		out.Tier = tierAllowlisted
	case pc.underHome || pc.underVol:
		out.Tier = tierNeedsApproval
	default:
		return resolvedAttachmentPath{}, fmt.Errorf("path %q (resolved %q) is outside your home folder and /Volumes; "+
			"only files there can be attached", p, resolved)
	}
	return out, nil
}

// readResolvedAttachment reads a path that resolveAttachmentPath
// accepted. O_NOFOLLOW is a TOCTOU backstop; the fstat identity must
// match the resolve-time one (and, for tier b, every approval dialog
// that showed the path); the kernel's name for the open file is put
// through the denylist again; the size cap is enforced from fstat AND
// on the read itself so a file growing after the check can't balloon
// memory.
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
	fp := fingerprintOf(st)
	if fp.nlink > 1 {
		return nil, hardLinkError(r.Requested, fp.nlink)
	}
	if r.info != nil && !r.fp.sameVersion(fp) {
		return nil, fmt.Errorf("%q changed after it was checked; refusing", r.Requested)
	}
	if r.Tier == tierNeedsApproval {
		if err := shownFiles.check(r.Resolved, fp); err != nil {
			return nil, err
		}
	}
	// Defense in depth: the kernel's canonical name for what we
	// actually opened must pass the denylist too.
	if kp, kerr := kernelPath(f); kerr == nil && kp != "" {
		if _, err := classifyPathAllowlisted(kp, r.Tier == tierAllowlisted); err != nil {
			return nil, fmt.Errorf("refusing to attach %q: its on-disk name %q is protected: %w", r.Requested, kp, err)
		}
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
