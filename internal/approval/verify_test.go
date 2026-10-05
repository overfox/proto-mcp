package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func promptReq() Request {
	return Request{
		Tool:   "test_tool",
		Caller: caller.Caller{PID: 1},
		Args:   json.RawMessage(`{}`),
		Policy: policy.ToolPolicy{Decision: policy.DecisionPrompt},
		Title:  "t",
		Body:   "b",
	}
}

// Pinned hash matches → helper runs.
func TestBrokerPinnedHashMatch(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.helperSHA256 = fileSHA(t, helper)
	if _, err := b.Request(context.Background(), promptReq()); err != nil {
		t.Fatalf("matching hash: err = %v, want approval", err)
	}
}

// A helper swapped for an "exit 0" script after build fails closed —
// even though the swapped script would itself approve.
func TestBrokerPinnedHashMismatchFailsClosed(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.helperSHA256 = fileSHA(t, helper)
	// Swap the helper content (still exit 0, still owner-only).
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n# evil\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = b.Request(context.Background(), promptReq())
	if !errors.Is(err, mcperrors.ErrAuthFailed) {
		t.Fatalf("swapped helper: err = %v, want ErrAuthFailed", err)
	}
}

// Unpinned (plain go build) falls back to owner/permission checks.
func TestBrokerUnpinnedFallsBack(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.helperSHA256 = ""
	if _, err := b.Request(context.Background(), promptReq()); err != nil {
		t.Fatalf("unpinned: err = %v, want approval with warning", err)
	}
}

// A helper not owned by the expected uid is refused.
func TestBrokerRejectsForeignOwner(t *testing.T) {
	helper := fixtureHelper(t, 0)
	b, err := New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.uid = os.Getuid() + 4242 // pretend the daemon runs as someone else
	if os.Getuid() == 0 {
		t.Skip("root-owned files are accepted by design")
	}
	_, err = b.Request(context.Background(), promptReq())
	if !errors.Is(err, mcperrors.ErrAuthFailed) {
		t.Fatalf("foreign owner: err = %v, want ErrAuthFailed", err)
	}
}

// A group/world-writable helper is refused at exec time too.
func TestVerifyHelperRejectsWritable(t *testing.T) {
	helper := fixtureHelper(t, 0)
	if err := os.Chmod(helper, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyHelper(helper, "", nil, os.Getuid()); !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("err = %v, want ErrHelperUntrusted", err)
	}
}

// Symlinks are resolved before verification (cask layout).
func TestVerifyHelperFollowsSymlink(t *testing.T) {
	helper := fixtureHelper(t, 0)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(helper, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyHelper(link, fileSHA(t, helper), nil, os.Getuid()); err != nil {
		t.Fatalf("symlinked helper: %v", err)
	}
	if err := verifyHelper(link, fileSHA(t, link), nil, os.Getuid()); err != nil {
		t.Fatalf("symlinked helper hash via link: %v", err)
	}
	bad := "00" + fileSHA(t, helper)[2:]
	if err := verifyHelper(link, bad, nil, os.Getuid()); !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("bad hash via symlink: err = %v, want ErrHelperUntrusted", err)
	}
}

func TestVerifyHelperMalformedHash(t *testing.T) {
	helper := fixtureHelper(t, 0)
	if err := verifyHelper(helper, "nothex", nil, os.Getuid()); !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("malformed hash: err = %v, want ErrHelperUntrusted", err)
	}
}

// Approver runs the helper with no policy/cache, and a nil broker
// fails closed.
func TestApprover(t *testing.T) {
	ok := fixtureHelper(t, 0)
	b, err := New(ok, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Approver()(context.Background(), "t", "b"); err != nil {
		t.Errorf("approve: %v", err)
	}

	deny := fixtureHelper(t, 1)
	b2, err := New(deny, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Approver()(context.Background(), "t", "b"); !errors.Is(err, mcperrors.ErrUserCanceled) {
		t.Errorf("decline: err = %v, want ErrUserCanceled", err)
	}

	var nilBroker *Broker
	if err := nilBroker.Approver()(context.Background(), "t", "b"); err == nil {
		t.Error("nil broker Approver must refuse")
	}
}
