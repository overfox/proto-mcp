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

// Empty allowlist (the shipped default) refuses every path attachment.
func TestPathAttachmentRefusedWithoutAllowlist(t *testing.T) {
	f := filepath.Join(t.TempDir(), "doc.pdf")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{{Path: f}})
	if err == nil || !strings.Contains(err.Error(), "attachment_path_allowlist is empty") {
		t.Fatalf("err = %v, want empty-allowlist refusal", err)
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

// A path outside every allowlisted dir is refused, including the
// string-prefix trick (/allowed-evil vs /allowed).
func TestPathAttachmentOutsideAllowlist(t *testing.T) {
	dir := t.TempDir()
	evil := dir + "-evil"
	if err := os.MkdirAll(evil, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(evil, "secret.txt")
	if err := os.WriteFile(f, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Policy: engineWithAllowlist(t, dir)}
	_, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{{Path: f}})
	if err == nil || !strings.Contains(err.Error(), "outside attachment_path_allowlist") {
		t.Fatalf("err = %v, want outside-allowlist refusal", err)
	}
}

// A symlink planted inside the allowlisted dir pointing outside it
// must not grant access to the target.
func TestPathAttachmentSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "ssh_key")
	if err := os.WriteFile(outside, []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "innocent.pdf")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Policy: engineWithAllowlist(t, dir)}
	_, err := decodeAndValidateAttachments(deps, []sendAttachmentInput{{Path: link}})
	if err == nil || !strings.Contains(err.Error(), "outside attachment_path_allowlist") {
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
