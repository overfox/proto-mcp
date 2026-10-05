package mcptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingGate approves (or declines) and records what it was shown.
type recordingGate struct {
	calls   int
	shown   []resolvedAttachmentPath
	decline bool
}

func (g *recordingGate) gate(outside []resolvedAttachmentPath) error {
	g.calls++
	g.shown = append(g.shown, outside...)
	if g.decline {
		return errors.New("user canceled")
	}
	return nil
}

// Tier a: inside the allowlist → read with no gate call.
func TestTier_AllowlistedNoPrompt(t *testing.T) {
	home := fakeHome(t)
	dir := filepath.Join(home, "proj")
	f := writeFile(t, filepath.Join(dir, "spec.pdf"), "spec")
	g := &recordingGate{}
	got, err := decodeAttachmentsGated(Deps{Policy: engineWithAllowlist(t, dir)},
		[]sendAttachmentInput{{Path: f}}, g.gate)
	if err != nil {
		t.Fatal(err)
	}
	if g.calls != 0 {
		t.Errorf("gate called %d times for an allowlisted file", g.calls)
	}
	if len(got) != 1 || string(got[0].Plain) != "spec" || got[0].OutsideAllowlist {
		t.Errorf("got %+v", got)
	}
}

// Tier b: elsewhere under home → ONE gate call listing every outside
// file (full resolved path + size), then read.
func TestTier_OutsideApprovedOnePromptForAll(t *testing.T) {
	home := fakeHome(t)
	a := writeFile(t, filepath.Join(home, "Desktop", "a.pdf"), "aaaa")
	b := writeFile(t, filepath.Join(home, "Documents", "sub", "b.txt"), "bb")
	g := &recordingGate{}
	got, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: a}, {Path: b}, {Filename: "c.txt", ContentB64: "aGk="}}, g.gate)
	if err != nil {
		t.Fatal(err)
	}
	if g.calls != 1 || len(g.shown) != 2 {
		t.Fatalf("gate calls=%d shown=%d, want 1 call covering 2 files", g.calls, len(g.shown))
	}
	if g.shown[0].Resolved != a || g.shown[0].Size != 4 || g.shown[1].Resolved != b {
		t.Errorf("gate shown %+v", g.shown)
	}
	if len(got) != 3 || string(got[0].Plain) != "aaaa" || !got[0].OutsideAllowlist || got[0].SourcePath != a {
		t.Errorf("got %+v", got)
	}
}

// Declining the prompt refuses the whole call.
func TestTier_OutsideDeclined(t *testing.T) {
	home := fakeHome(t)
	a := writeFile(t, filepath.Join(home, "Desktop", "a.pdf"), "aaaa")
	g := &recordingGate{decline: true}
	_, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: a}}, g.gate)
	if err == nil || g.calls != 1 {
		t.Fatalf("err=%v calls=%d, want refusal after one prompt", err, g.calls)
	}
}

// Tier c: hard denylist, never attachable even with an approving gate
// (and the gate is never even asked).
func TestTier_Denylist(t *testing.T) {
	home := fakeHome(t)
	cases := []string{
		filepath.Join(home, ".ssh", "config"),
		filepath.Join(home, ".SSH", "notes.txt"), // case-insensitive FS
		filepath.Join(home, ".aws", "config"),
		filepath.Join(home, ".config", "gcloud", "x.json"),
		filepath.Join(home, ".kube", "config"),
		filepath.Join(home, ".docker", "config.json"),
		filepath.Join(home, ".gnupg", "pubring.kbx"),
		filepath.Join(home, "Library", "Keychains", "login.db"),
		filepath.Join(home, "Library", "Cookies", "c.binarycookies"),
		filepath.Join(home, "Library", "Application Support", "protonmcp", "state.db"),
		filepath.Join(home, "Library", "Application Support", "Claude", "config.json"),
		filepath.Join(home, "Library", "Mail", "V10", "x.emlx"),
		filepath.Join(home, ".hidden-project", "readme.txt"),
		filepath.Join(home, "Documents", "server.pem"),
		filepath.Join(home, "Documents", "tls.KEY"),
		filepath.Join(home, "Documents", "cert.p12"),
		filepath.Join(home, "Documents", "cert.pfx"),
		filepath.Join(home, "Documents", "old.keychain-db"),
		filepath.Join(home, "Documents", "id_rsa.pub"),
		filepath.Join(home, "Documents", "id_ed25519"),
		filepath.Join(home, "Documents", ".env.local"),
		filepath.Join(home, "Documents", "vault.kdbx"),
		filepath.Join(home, "Documents", "credentials.json"),
		filepath.Join(home, ".netrc"),
	}
	for _, p := range cases {
		t.Run(strings.TrimPrefix(p, home), func(t *testing.T) {
			writeFile(t, p, "SECRET")
			g := &recordingGate{}
			_, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: p}}, g.gate)
			if err == nil {
				t.Fatalf("denylisted %s was attachable", p)
			}
			if g.calls != 0 {
				t.Errorf("gate should not be asked for a denylisted file")
			}
		})
	}
}

// The denylist holds even inside the allowlist, except the hidden-path
// rule, which an explicit allowlist entry waives.
func TestTier_DenylistVsAllowlist(t *testing.T) {
	home := fakeHome(t)
	ssh := filepath.Join(home, ".ssh")
	key := writeFile(t, filepath.Join(ssh, "id_rsa"), "PRIVATE")
	cfg := writeFile(t, filepath.Join(ssh, "config"), "Host x")
	deps := Deps{Policy: engineWithAllowlist(t, ssh)}
	for _, p := range []string{key, cfg} {
		if _, err := decodeAttachmentsGated(deps, []sendAttachmentInput{{Path: p}}, (&recordingGate{}).gate); err == nil {
			t.Errorf("%s attachable via allowlist; ~/.ssh must stay denied", p)
		}
	}

	proj := filepath.Join(home, ".myproject")
	notes := writeFile(t, filepath.Join(proj, "notes.txt"), "ok")
	got, err := decodeAttachmentsGated(Deps{Policy: engineWithAllowlist(t, proj)},
		[]sendAttachmentInput{{Path: notes}}, nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("explicitly allowlisted hidden dir should attach: err=%v", err)
	}
}

// A symlink with an innocent name pointing into the denylist is judged
// by its target — refused even with an approving gate, and even when
// the link sits inside the allowlist.
func TestTier_SymlinkIntoDenylist(t *testing.T) {
	home := fakeHome(t)
	target := writeFile(t, filepath.Join(home, ".ssh", "id_ed25519"), "PRIVATE")
	aws := writeFile(t, filepath.Join(home, ".aws", "credentials"), "AKIA")
	allowed := filepath.Join(home, "allowed")
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	link1 := filepath.Join(home, "Documents", "report.pdf")
	if err := os.MkdirAll(filepath.Dir(link1), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link1); err != nil {
		t.Fatal(err)
	}
	link2 := filepath.Join(allowed, "invoice.pdf")
	if err := os.Symlink(aws, link2); err != nil {
		t.Fatal(err)
	}
	deps := Deps{Policy: engineWithAllowlist(t, allowed)}
	for _, l := range []string{link1, link2} {
		g := &recordingGate{}
		if _, err := decodeAttachmentsGated(deps, []sendAttachmentInput{{Path: l}}, g.gate); err == nil {
			t.Errorf("symlink %s into the denylist was attachable", l)
		}
		if g.calls != 0 {
			t.Errorf("gate asked for a denylisted symlink target")
		}
	}
}

// A file swapped between the check/approval and the read is refused.
func TestTier_SwappedAfterCheck(t *testing.T) {
	home := fakeHome(t)
	p := writeFile(t, filepath.Join(home, "Desktop", "a.pdf"), "original")
	r, err := resolveAttachmentPath(Deps{}, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "swapped!")
	if _, err := readResolvedAttachment(r, 1<<20); err == nil || !strings.Contains(err.Error(), "changed after") {
		t.Fatalf("err = %v, want changed-after-check refusal", err)
	}
}

// Directories and Cowork/VM paths get clear refusals.
func TestTier_NonFileAndCoworkHint(t *testing.T) {
	home := fakeHome(t)
	dir := filepath.Join(home, "Documents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAttachmentPath(Deps{}, dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("dir: err = %v", err)
	}
	if _, err := resolveAttachmentPath(Deps{}, "/sessions/abc/mnt/outputs/x.pdf"); err == nil ||
		!strings.Contains(err.Error(), "Cowork") {
		t.Errorf("cowork path: err = %v, want Cowork hint", err)
	}
}

// The draft gate calls deps.Approve once with every path listed, and
// a nil Approve (no broker) refuses.
func TestDraftAttachmentGate(t *testing.T) {
	home := fakeHome(t)
	a := writeFile(t, filepath.Join(home, "Desktop", "a.pdf"), "aaaa")
	b := writeFile(t, filepath.Join(home, "Downloads", "b.zip"), "bb")

	var calls int
	var gotBody string
	deps := Deps{Approve: func(_ context.Context, _, body string) error {
		calls++
		gotBody = body
		return nil
	}}
	gate := draftAttachmentGate(context.Background(), deps, "mail_draft_create", "Q3 report", []string{"boss@example.com"})
	if _, err := decodeAttachmentsGated(deps, []sendAttachmentInput{{Path: a}, {Path: b}}, gate); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("Approve calls = %d, want 1", calls)
	}
	for _, want := range []string{a, b, "4 B", "2 B", "Q3 report", "boss@example.com"} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("prompt body missing %q:\n%s", want, gotBody)
		}
	}

	declined := Deps{Approve: func(context.Context, string, string) error { return errors.New("canceled") }}
	if _, err := decodeAttachmentsGated(declined, []sendAttachmentInput{{Path: a}},
		draftAttachmentGate(context.Background(), declined, "mail_draft_create", "", nil)); err == nil {
		t.Error("declined approval must refuse")
	}
	if _, err := decodeAttachmentsGated(Deps{}, []sendAttachmentInput{{Path: a}},
		draftAttachmentGate(context.Background(), Deps{}, "mail_draft_create", "", nil)); err == nil {
		t.Error("nil Approve must refuse")
	}
}
