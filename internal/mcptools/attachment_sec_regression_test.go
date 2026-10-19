package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Regression tests for the 2026-10 file-handling findings (WS-C):
// M2 (APFS case folding defeats the denylists) and the path lows
// (hard links, /Volumes homes, approval bound to the path string).

// caseInsensitiveFS reports whether dir's volume opens "ſ" as "s".
func caseInsensitiveFS(t *testing.T, dir string) bool {
	t.Helper()
	p := filepath.Join(dir, "probe-s")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	_, err := os.Stat(filepath.Join(dir, "probe-ſ"))
	return err == nil
}

// M2: every ſ spelling of a protected path is denied — both on the
// path string (no filesystem involved) and end to end.
func TestSec_LongS_DenylistRead(t *testing.T) {
	home := fakeHome(t)
	writeFile(t, filepath.Join(home, "Library", "Application Support", "protonmcp", "policy.yaml"), "secret")
	writeFile(t, filepath.Join(home, "Library", "Cookies", "Cookies.binarycookies"), "cookie")
	writeFile(t, filepath.Join(home, "Documents", "keys", "id_rsa"), "PRIVATE KEY")
	writeFile(t, filepath.Join(home, "Documents", "credentials.json"), "creds")

	paths := []string{
		filepath.Join(home, "Library", "Application Support", "protonmcp", "policy.yaml"),
		filepath.Join(home, "Library", "Application ſupport", "protonmcp", "policy.yaml"),
		filepath.Join(home, "LIBRARY", "Cookieſ", "Cookies.binarycookies"),
		filepath.Join(home, "Documents", "keys", "id_rsa"),
		filepath.Join(home, "Documents", "keys", "id_rſa"),
		filepath.Join(home, "Documents", "credentialſ.json"),
		filepath.Join(home, "Documents", "ＩＤ_ＲＳＡ"), // fullwidth: NFKC folds it too
	}
	for _, p := range paths {
		if _, err := classifyAttachmentPath(Deps{}, p); err == nil {
			t.Errorf("classify(%q): not denied", p)
		}
		_, err := resolveAttachmentPath(Deps{}, p)
		if err == nil {
			t.Errorf("resolve(%q): readable, want denied", p)
			continue
		}
		if _, serr := os.Stat(p); serr == nil && !strings.Contains(err.Error(), "never attachable") {
			t.Errorf("resolve(%q): err = %v, want a denylist refusal", p, err)
		}
	}
}

// M2 defense in depth: even if a spelling slipped past the path-string
// check, the kernel's on-disk name for the opened file is re-checked.
func TestSec_KernelPathRecheck(t *testing.T) {
	home := fakeHome(t)
	if !caseInsensitiveFS(t, home) {
		t.Skip("temp volume is case-sensitive")
	}
	real := writeFile(t, filepath.Join(home, "Library", "Cookies", "c.binarycookies"), "cookie")
	alias := filepath.Join(home, "Library", "Cookieſ", "c.binarycookies")
	f, err := os.Open(alias)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := kernelPath(f)
	f.Close()
	if err != nil {
		t.Fatalf("kernelPath: %v", err)
	}
	if canonName(kp) != canonName(real) || !strings.Contains(kp, "Cookies") {
		t.Fatalf("kernelPath = %q, want on-disk name %q", kp, real)
	}
	// Simulate a classifier miss: hand the read a pre-approved alias.
	st, _ := os.Stat(alias)
	r := resolvedAttachmentPath{Requested: alias, Resolved: alias, Tier: tierNeedsApproval, info: st, fp: fingerprintOf(st)}
	if _, err := readResolvedAttachment(r, 1<<20); err == nil || !strings.Contains(err.Error(), "on-disk name") {
		t.Fatalf("read via alias: err = %v, want on-disk-name refusal", err)
	}
}

// M2 save side: ſ spellings and the extended agent/build/run-on-open
// lists are refused after sanitization.
func TestSec_LongS_SaveNames(t *testing.T) {
	for _, n := range []string{
		"AGENTſ.md", "ſettings.json", "taſkſ.json", "CLAUDE.md", "GEMINI.md",
		"conftest.py", "package.json", "Makefile", "pyproject.toml", "setup.py", "Dockerfile",
		"mcp.json", "settings.local.json",
		"x.jar", "x.shortcut", "x.terminal", "x.prefPane", "x.saver", "x.mobileconfig",
		"x.dmg", "x.pkg", "x.mpkg", "x.workflow", "x.scpt", "x.applescript", "x.webloc",
		"x.inetloc", "x.fileloc", "x.url", "x.desktop", "x.action", "x.definition",
		"x.wflow", "x.osax", "x.kext", "x.qlgenerator", "x.mdimporter", "x.JAR",
	} {
		s := sanitize.Filename(n)
		if err := checkSaveName(s); err == nil {
			t.Errorf("checkSaveName(%q → %q) = nil, want refusal", n, s)
		}
		if _, err := saveFilename(n); err == nil {
			t.Errorf("saveFilename(%q) = nil error, want refusal", n)
		}
	}
	// Dot-files are checked as given too (direct callers).
	for _, n := range []string{".cursorrules", ".envrc", ".npmrc", ".pypirc", ".mcp.json", "Makefile."} {
		if err := checkSaveName(n); err == nil {
			t.Errorf("checkSaveName(%q) = nil, want refusal", n)
		}
	}
	for _, n := range []string{"report.pdf", "statement.xlsx", "notes.md", "photo.jpg"} {
		if err := checkSaveName(n); err != nil {
			t.Errorf("checkSaveName(%q) = %v, want ok", n, err)
		}
	}
	for _, d := range []string{"/Users/u/Library/LaunchAgents", "/Users/u/Library/LaunchAgentſ", "/Users/u/.claude"} {
		if err := checkSaveDir(d); err == nil {
			t.Errorf("checkSaveDir(%q) = nil, want refusal", d)
		}
	}
}

// Low: a hard link inside the allowlist to ~/.ssh/id_rsa is refused
// (allowlisted tier — no gate) and so is any multiply-linked file.
func TestSec_HardlinkRefused(t *testing.T) {
	home := fakeHome(t)
	key := writeFile(t, filepath.Join(home, ".ssh", "id_rsa"), "PRIVATE KEY")
	allow := filepath.Join(home, "Documents", "Claude")
	if err := os.MkdirAll(allow, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allow, "notes.txt")
	if err := os.Link(key, link); err != nil {
		t.Fatal(err)
	}
	g := &recordingGate{}
	_, err := decodeAttachmentsGated(Deps{Policy: engineWithAllowlist(t, allow)}, []sendAttachmentInput{{Path: link}}, g.gate)
	if err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("allowlisted hard link: err = %v, want hard-link refusal", err)
	}
	if g.calls != 0 {
		t.Errorf("gate called %d times", g.calls)
	}

	// Tier b too.
	doc := writeFile(t, filepath.Join(home, "Desktop", "a.pdf"), "pdf")
	if err := os.Link(doc, filepath.Join(home, "Desktop", "b.pdf")); err != nil {
		t.Fatal(err)
	}
	_, err = decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: doc}}, g.gate)
	if err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("tier-b hard link: err = %v, want hard-link refusal", err)
	}
}

// Low: /Volumes/<vol>/Users/<name>/... is treated as that user's home.
func TestSec_VolumesHomeDenylist(t *testing.T) {
	fakeHome(t)
	for _, p := range []string{
		"/Volumes/X/Users/u/.ssh/id_x",
		"/Volumes/X/Users/u/Library/Keychains/login.keychain-db",
		"/Volumes/X/Users/u/Library/Cookieſ/Cookies.binarycookies",
		"/Volumes/Backup/Users/someone/Library/Application Support/protonmcp/store.db",
		"/Volumes/X/Users/u/Library/Mail/V10/x.emlx",
	} {
		if _, err := classifyAttachmentPath(Deps{}, p); err == nil {
			t.Errorf("classify(%q): not denied", p)
		}
	}
	pc, err := classifyAttachmentPath(Deps{}, "/Volumes/X/Users/u/Documents/report.pdf")
	if err != nil || !pc.underVol {
		t.Errorf("ordinary volume file: pc=%+v err=%v, want allowed (tier b)", pc, err)
	}
}

// Low: an approval is bound to the file the dialog showed, not to the
// path. Swapping the inode (or rewriting it) after the dialog is
// refused even though the path is the same.
func TestSec_ApprovalBoundToFile(t *testing.T) {
	home := fakeHome(t)
	p := writeFile(t, filepath.Join(home, "Desktop", "report.pdf"), "the report")

	// Unchanged: dialog (resolveAttachmentPath) then handler read → ok.
	if _, err := resolveAttachmentPath(Deps{}, p); err != nil {
		t.Fatal(err)
	}
	g := &recordingGate{}
	got, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: p}}, g.gate)
	if err != nil || string(got[0].Plain) != "the report" {
		t.Fatalf("unchanged file: %v", err)
	}

	// Swap: a different inode at the same path after the dialog.
	q := writeFile(t, filepath.Join(home, "Desktop", "swap.pdf"), "the report")
	p2 := writeFile(t, filepath.Join(home, "Desktop", "invoice.pdf"), "invoice")
	if _, err := resolveAttachmentPath(Deps{}, p2); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(q, p2); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: p2}}, g.gate); err == nil ||
		!strings.Contains(err.Error(), "changed after it was shown") {
		t.Fatalf("inode swap after approval: err = %v, want refusal", err)
	}

	// Rewrite in place (same inode, new size / mtime).
	p3 := writeFile(t, filepath.Join(home, "Desktop", "memo.pdf"), "memo")
	if _, err := resolveAttachmentPath(Deps{}, p3); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p3, []byte("something else entirely"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(p3, future, future)
	if _, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: p3}}, g.gate); err == nil ||
		!strings.Contains(err.Error(), "changed after it was shown") {
		t.Fatalf("rewrite after approval: err = %v, want refusal", err)
	}
}

// Records expire, so a legitimately edited file is attachable again.
func TestSec_ShownFileRecordsExpire(t *testing.T) {
	now := time.Unix(1000, 0)
	r := &shownFileRegistry{m: map[string][]shownFileRecord{}, now: func() time.Time { return now }}
	r.record("/p", fileFingerprint{ino: 1, size: 1})
	if err := r.check("/p", fileFingerprint{ino: 2, size: 1}); err == nil {
		t.Fatal("mismatch within TTL accepted")
	}
	now = now.Add(shownFileTTL + time.Second)
	if err := r.check("/p", fileFingerprint{ino: 2, size: 1}); err != nil {
		t.Fatalf("after TTL: %v", err)
	}
}

// M2: the save prompt names the file that will be written (the
// sender's name, from the cache) and flags names the handler refuses.
func TestSec_SavePromptShowsResolvedName(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.DB.ExecContext(ctx,
		`INSERT INTO messages (id, thread_id, subject, from_address, from_name, to_json, cc_json, date, unread, starred, has_attachments, folder, size_bytes, raw_json) VALUES ('m1', 'm1', 'hi', 'x@y', 'X', '[]', '[]', 0, 0, 0, 1, 'inbox', 0, '{}')`,
	); err != nil {
		t.Fatal(err)
	}
	for id, name := range map[string]string{"a1": "Q3 report.pdf", "a2": "AGENTſ.md"} {
		if err := st.SetAttachmentCache(ctx, store.AttachmentCacheRow{
			MessageID: "m1", AttachmentID: id, Filename: name, SizeBytes: 1, Content: []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	tl := mailSaveAttachment(Deps{Store: st})
	_, body := tl.PromptBody(json.RawMessage(`{"message_id":"m1","attachment_id":"a1"}`))
	if !strings.Contains(body, "as Q3 report.pdf to") || strings.Contains(body, "name from message") {
		t.Errorf("prompt = %q, want the resolved filename", body)
	}
	_, body = tl.PromptBody(json.RawMessage(`{"message_id":"m1","attachment_id":"a2"}`))
	if !strings.Contains(body, "WILL BE REFUSED") {
		t.Errorf("prompt = %q, want the refusal flagged", body)
	}
}
