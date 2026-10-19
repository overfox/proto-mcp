package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// Regression tests for the round-2 verification findings (WS-C):
// home denylists on any ".../Users/<name>/" path, backup stores,
// ctime in the approval fingerprint, more refused save names, and the
// cap on concurrent extraction children.

// Home rules apply to every /Users/<name>/ segment, not just
// /Volumes/<vol>/Users/<name>/; backup stores are refused outright.
func TestSec2_UsersAnywhereAndBackups(t *testing.T) {
	home := fakeHome(t)
	denied := []string{
		// Time Machine (HFS+ backupdb) — refused as a backup store.
		"/Volumes/TM/Backups.backupdb/mac/2026-10-01/Macintosh HD - Data/Users/farid/Library/Mail/V10/INBOX.mbox/1.emlx",
		"/Volumes/TM/Backups.backupdb/mac/2026-10-01/Macintosh HD - Data/Users/farid/Library/Application Support/protonmcp/store.db",
		"/Volumes/TM/Backups.backupdb/mac/2026-10-01/Macintosh HD - Data/Users/farid/Documents/report.pdf",
		"/Volumes/TM/BACKUPS.BACKUPDB/x/report.pdf",
		"/Volumes/NAS/mac.sparsebundle/bands/0",
		"/Volumes/NAS/mac.backupbundle/x",
		"/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/x/report.pdf",
		"/Volumes/com.apple.TimeMachine.localsnapshots/2026-10-01/Data/Users/farid/Documents/report.pdf",
		"/.MobileBackups/Computer/2026/Macintosh HD/Users/farid/Documents/x.pdf",
		// APFS Time Machine destinations: a /Users/<name>/ deeper in.
		"/Volumes/Backups of Mac/2026-10-01-120000.previous/Macintosh HD - Data/Users/farid/Library/Mail/x.emlx",
		"/Volumes/Backups of Mac/2026-10-01-120000.previous/Macintosh HD - Data/Users/farid/.ssh/id_x",
		// Nested copies.
		"/Volumes/Ext/Users/farid/Library/Mail/x.emlx",
		"/Volumes/Ext/Old/Users/farid/Library/Cookies/Cookies.binarycookies",
		"/Volumes/Ext/Old/USERS/farid/Library/Cookieſ/Cookies.binarycookies",
		"/Volumes/Ext/a/b/c/Users/x/Library/Keychains/login.keychain-db",
		// An old home copied under our own home.
		filepath.Join(home, "Backups", "Users", "farid", "Library", "Application Support", "Claude", "config.json"),
		filepath.Join(home, "Backups", "Users", "farid", "Library", "Mail", "x.emlx"),
	}
	for _, p := range denied {
		if _, err := classifyPathAllowlisted(p, false); err == nil || !strings.Contains(err.Error(), "never attachable") {
			t.Errorf("classify(%q) = %v, want denylist refusal", p, err)
		}
		// Allowlisting doesn't lift it.
		if _, err := classifyPathAllowlisted(p, true); err == nil {
			t.Errorf("classify(%q, allowlisted) = nil, want refusal", p)
		}
	}
	for _, p := range []string{
		"/Volumes/Ext/Old/Users/farid/Documents/report.pdf",
		"/Volumes/Ext/Users/farid/Desktop/photo.jpg",
		filepath.Join(home, "Backups", "Users", "farid", "Documents", "report.pdf"),
	} {
		if _, err := classifyPathAllowlisted(p, false); err != nil {
			t.Errorf("classify(%q) = %v, want allowed", p, err)
		}
	}
}

// Denylist messages show the path as spelled, not lowercased.
func TestSec2_DenylistMessageOriginalCase(t *testing.T) {
	_, err := classifyPathAllowlisted("/Volumes/Ext/Old/Users/Farid/Library/Mail/V10/x.emlx", false)
	if err == nil || !strings.Contains(err.Error(), "/Volumes/Ext/Old/Users/Farid/Library/Mail is never attachable") {
		t.Fatalf("err = %v, want original-case label", err)
	}
	_, err = classifyPathAllowlisted("/Volumes/TM/Backups.backupdb/mac/x.pdf", false)
	if err == nil || !strings.Contains(err.Error(), "/Volumes/TM/Backups.backupdb is a backup store") {
		t.Fatalf("err = %v, want original-case backup label", err)
	}
	home := fakeHome(t)
	_, err = classifyPathAllowlisted(filepath.Join(home, "Library", "Cookies", "c"), false)
	if err == nil || !strings.Contains(err.Error(), "~/Library/Cookies is never attachable") {
		t.Fatalf("err = %v, want ~/Library/Cookies", err)
	}
}

// A same-inode, same-size rewrite after the dialog, with mtime put
// back via Chtimes, is refused: ctime can't be restored.
func TestSec2_SameInodeRewriteMtimeRestored(t *testing.T) {
	home := fakeHome(t)
	p := writeFile(t, filepath.Join(home, "Documents", "holiday.txt"), "HOLIDAY PHOTOS 0001")
	st0, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := resolveAttachmentPath(Deps{}, p) // dialog time
	if err != nil || r.Tier != tierNeedsApproval {
		t.Fatalf("resolve: %v tier=%v", err, r.Tier)
	}
	time.Sleep(10 * time.Millisecond) // let ctime move on coarse clocks
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("SECRET-KEY-MATERIAL"), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chtimes(p, time.Now(), st0.ModTime()); err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(p)
	if !st1.ModTime().Equal(st0.ModTime()) || st1.Size() != st0.Size() {
		t.Fatalf("setup: mtime/size not restored")
	}
	r2, err := resolveAttachmentPathForRead(Deps{}, p) // handler time
	if err != nil {
		t.Fatal(err)
	}
	if fingerprintOf(st0).ctimeNs == 0 {
		t.Skip("platform doesn't report ctime")
	}
	b, err := readResolvedAttachment(r2, 1<<20)
	if err == nil || !strings.Contains(err.Error(), "changed after it was shown") {
		t.Fatalf("read after in-place rewrite = %q, %v; want refusal", b, err)
	}
}

// Build/test entry points, plug-in bundles and shell scripts can't be
// saved, in any folded spelling.
func TestSec2_SaveNamesRound2(t *testing.T) {
	for _, n := range []string{
		"test_x.py", "TEST_payload.py", "x_test.py", "x_test.go", "X_TEST.GO", "x_teſt.go", "conftest.py",
		"build.rs", "Justfile", "justfile", "Rakefile", "Gemfile", "Taskfile.yml", "Taskfile.yaml",
		"CMakeLists.txt", "meson.build", "BUILD", "BUILD.bazel", "WORKSPACE", "MODULE.bazel",
		"gradlew", "build.gradle", "build.gradle.kts", "settings.gradle.kts", "pom.xml",
		".pre-commit-config.yaml", "pre-commit-config.yaml", "Gemfile.", "ＧＥＭＦＩＬＥ",
		"x.bundle", "x.plugin", "x.xip", "x.appex", "x.xpc", "x.component", "x.vst", "x.vst3",
		"x.sh", "x.zsh", "x.bash", "x.fish", "x.ps1", "x.SH", "x.ſh", "x.command",
	} {
		if err := checkSaveName(n); err == nil {
			t.Errorf("checkSaveName(%q) = nil, want refusal", n)
		}
		if _, err := saveFilename(n); err == nil {
			t.Errorf("saveFilename(%q → %q) = nil, want refusal", n, sanitize.Filename(n))
		}
	}
	for _, n := range []string{"report.py", "testimony.pdf", "latest.go.txt", "build-notes.md", "photo.jpg", "data.json"} {
		if err := checkSaveName(n); err != nil {
			t.Errorf("checkSaveName(%q) = %v, want ok", n, err)
		}
	}
	for _, d := range []string{"/Users/u/proj/.github/workflows", "/Users/u/proj/.vscode", "/Users/u/proj/.idea"} {
		if err := checkSaveDir(d); err == nil {
			t.Errorf("checkSaveDir(%q) = nil, want refusal", d)
		}
	}
}

// At most extractMaxChildren children run at once; a call that can't
// get a slot in time fails instead of piling up another child.
func TestSec2_ExtractChildConcurrencyCap(t *testing.T) {
	if !extractSandboxEnabled.Load() {
		t.Fatal("TestMain should have enabled the extraction child")
	}
	prevEnv, prevTimeout, prevWait := extractChildEnv, extractSandboxTimeout, extractSlotWait
	extractChildEnv = append([]string{testChildHangEnv}, prevEnv...)
	extractSandboxTimeout = 1500 * time.Millisecond
	extractSlotWait = 20 * time.Second
	t.Cleanup(func() { extractChildEnv, extractSandboxTimeout, extractSlotWait = prevEnv, prevTimeout, prevWait })

	var peak atomic.Int64
	stop := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		for {
			if n := int64(len(extractChildSlots)); n > peak.Load() {
				peak.Store(n)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = extractTextIsolated(context.Background(), "pdf", buildPDF("x"), 100)
		}(i)
	}
	wg.Wait()
	close(stop)
	sampler.Wait()
	if p := peak.Load(); p > extractMaxChildren || p == 0 {
		t.Fatalf("peak concurrent children = %d, want 1..%d", p, extractMaxChildren)
	}
	for i, err := range errs {
		if err == nil || !strings.Contains(err.Error(), "stopped after") {
			t.Errorf("call %d: err = %v, want child timeout", i, err)
		}
	}

	// Slots full: the call fails fast after extractSlotWait, or when
	// its context ends, without starting a child.
	for range extractMaxChildren {
		extractChildSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range extractMaxChildren {
			<-extractChildSlots
		}
	})
	extractSlotWait = 200 * time.Millisecond
	_, _, err := extractTextIsolated(context.Background(), "pdf", buildPDF("x"), 100)
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("err = %v, want busy refusal", err)
	}
	extractSlotWait = 20 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := extractTextIsolated(ctx, "pdf", buildPDF("x"), 100); err == nil {
		t.Fatal("want ctx error while slots are full")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("waited %s past ctx deadline", el)
	}
}
