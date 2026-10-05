package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// engineWithAllowlist builds a policy engine whose override sets the
// attachment_path_allowlist to the given dirs.
func engineWithAllowlist(t *testing.T, dirs ...string) *policy.Engine {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("attachment_path_allowlist:\n")
	for _, d := range dirs {
		sb.WriteString("  - " + d + "\n")
	}
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := policy.New(context.Background(), p, nil)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	return e
}

// fakeHome points $HOME at a fresh temp dir and returns it
// symlink-resolved (macOS temp dirs live under /var → /private/var).
func fakeHome(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	r, err := filepath.EvalSymlinks(h)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func writeFile(t *testing.T, p, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const needsApprovalMsg = "outside attachment_path_allowlist and needs a Touch ID approval"

// Empty allowlist (the shipped default) + no approval gate: a home
// file is refused (it would need a Touch ID approval).
func TestPathAttachmentRefusedWithoutAllowlist(t *testing.T) {
	home := fakeHome(t)
	f := writeFile(t, filepath.Join(home, "Documents", "doc.pdf"), "x")
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{{Path: f}})
	if err == nil || !strings.Contains(err.Error(), needsApprovalMsg) {
		t.Fatalf("err = %v, want needs-approval refusal", err)
	}
}

// Paths outside $HOME and /Volumes are refused outright.
func TestPathAttachmentOutsideHomeRefused(t *testing.T) {
	fakeHome(t)
	f := writeFile(t, filepath.Join(t.TempDir(), "doc.pdf"), "x")
	approve := func([]resolvedAttachmentPath) error { return nil }
	_, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: f}}, approve)
	if err == nil || !strings.Contains(err.Error(), "outside your home folder and /Volumes") {
		t.Fatalf("err = %v, want outside-home refusal", err)
	}
}

// A file inside an allowlisted dir is read; filename defaults to the
// basename.
func TestPathAttachmentHappyPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(f, []byte("hello attachment"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Policy: engineWithAllowlist(t, dir)}
	got, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{{Path: f}})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Filename != "report.pdf" || string(got[0].Plain) != "hello attachment" {
		t.Errorf("got %+v, want report.pdf with content", got)
	}
}

// A path outside every allowlisted dir isn't silently granted,
// including the string-prefix trick (/allowed-evil vs /allowed): it
// falls to the needs-approval tier.
func TestPathAttachmentOutsideAllowlist(t *testing.T) {
	home := fakeHome(t)
	dir := filepath.Join(home, "allowed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := writeFile(t, filepath.Join(home, "allowed-evil", "secret.txt"), "secret")
	deps := Deps{Policy: engineWithAllowlist(t, dir)}
	_, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{{Path: f}})
	if err == nil || !strings.Contains(err.Error(), needsApprovalMsg) {
		t.Fatalf("err = %v, want needs-approval refusal", err)
	}
}

// A symlink planted inside the allowlisted dir pointing outside it
// must not grant silent access to the target.
func TestPathAttachmentSymlinkEscape(t *testing.T) {
	home := fakeHome(t)
	dir := filepath.Join(home, "allowed")
	outside := writeFile(t, filepath.Join(home, "Private", "notes.txt"), "PRIVATE")
	link := filepath.Join(dir, "innocent.pdf")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Policy: engineWithAllowlist(t, dir)}
	_, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{{Path: link}})
	if err == nil || !strings.Contains(err.Error(), needsApprovalMsg) {
		t.Fatalf("err = %v, want symlink-escape refusal", err)
	}
}

// content_b64 and path are mutually exclusive; neither is an error too.
func TestPathAttachmentExclusivity(t *testing.T) {
	deps := Deps{Policy: engineWithAllowlist(t, t.TempDir())}
	_, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{
		{Filename: "a", ContentB64: "aGk=", Path: "/tmp/x"},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("both set: err = %v, want mutual-exclusion error", err)
	}
	_, err = decodeAndValidateAttachments(deps, []sendAttachmentInput{{Filename: "a"}})
	if err == nil || !strings.Contains(err.Error(), "one of content_b64 or path") {
		t.Fatalf("neither set: err = %v, want one-of error", err)
	}
}

// Relative paths are refused before any filesystem access.
func TestPathAttachmentRelativeRefused(t *testing.T) {
	deps := Deps{Policy: engineWithAllowlist(t, t.TempDir())}
	_, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{{Path: "docs/x.pdf"}})
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("err = %v, want absolute-path refusal", err)
	}
}
