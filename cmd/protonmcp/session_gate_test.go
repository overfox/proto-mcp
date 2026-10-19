package main

import (
	"context"
	"errors"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/session"
)

// stubKeychain replaces the Keychain probes and the gate for one test.
func stubKeychain(t *testing.T, exists bool, gate func(context.Context, string) error) (resumed, loaded *int) {
	t.Helper()
	var r, l int
	prevE, prevR, prevL, prevG := keystoreExists, tryResume, keystoreLoad, cliTouchIDGate
	keystoreExists = func() (bool, error) { return exists, nil }
	tryResume = func(context.Context) (*session.Bundle, error) {
		r++
		return &session.Bundle{}, nil
	}
	keystoreLoad = func() (keystore.Live, error) {
		l++
		return keystore.Live{Email: "a@b.c"}, nil
	}
	cliTouchIDGate = gate
	t.Cleanup(func() {
		keystoreExists, tryResume, keystoreLoad, cliTouchIDGate = prevE, prevR, prevL, prevG
	})
	return &r, &l
}

// SECURITY H2 — the CLI's session acquire (whoami / read / backfill /
// sync / calendar-backfill) runs the Touch ID gate before it touches
// the Keychain blob, naming the subcommand.
func TestAcquireSession_RunsGateBeforeKeychain(t *testing.T) {
	var gotCmd string
	resumed, _ := stubKeychain(t, true, func(_ context.Context, cmd string) error {
		gotCmd = cmd
		return nil
	})
	if _, err := acquireSession(context.Background(), "read"); err != nil {
		t.Fatal(err)
	}
	if gotCmd != "read" {
		t.Fatalf("gate cmd = %q, want read", gotCmd)
	}
	if *resumed != 1 {
		t.Fatalf("resume calls = %d, want 1", *resumed)
	}
}

// A declined gate stops before the Keychain read and does NOT fall
// through to an interactive login.
func TestAcquireSession_DeclinedGateBlocksKeychain(t *testing.T) {
	resumed, _ := stubKeychain(t, true, func(context.Context, string) error {
		return errors.New("user canceled approval")
	})
	_, err := acquireSession(context.Background(), "whoami")
	if err == nil || !isGateRefusal(err) {
		t.Fatalf("err = %v, want a gate refusal", err)
	}
	if *resumed != 0 {
		t.Fatal("Keychain session was loaded despite the declined Touch ID gate")
	}
}

// inspect / logout read the blob through the same gate.
func TestLoadStoredSession_Gated(t *testing.T) {
	gateCalls := 0
	_, loaded := stubKeychain(t, true, func(context.Context, string) error {
		gateCalls++
		return errors.New("declined")
	})
	if _, err := loadStoredSession(context.Background(), "inspect"); !isGateRefusal(err) {
		t.Fatalf("err = %v, want gate refusal", err)
	}
	if gateCalls != 1 || *loaded != 0 {
		t.Fatalf("gate=%d loads=%d, want 1/0", gateCalls, *loaded)
	}
}

// Nothing stored → nothing to unlock → no prompt.
func TestLoadStoredSession_NothingStoredNoPrompt(t *testing.T) {
	_, _ = stubKeychain(t, false, func(context.Context, string) error {
		t.Fatal("gate prompted with no stored session")
		return nil
	})
	if _, err := loadStoredSession(context.Background(), "inspect"); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// inspect never prints token characters.
func TestDescribeSecretNoPrefix(t *testing.T) {
	tok := "abcdefghijklmnopqrstuvwxyz012345"
	if got := describeSecret(tok); got != "set (len=32)" {
		t.Fatalf("describeSecret = %q", got)
	}
}
