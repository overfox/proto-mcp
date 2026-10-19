package serve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
)

func fakeHelper(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// A timed-out prompt kills the helper (exit -1). That used to match
// the exit-code switch first and read "helper exit -1"; it must be
// reported as a timeout.
func TestPromptStartupTouchID_TimeoutLabel(t *testing.T) {
	old := startupGateTimeout
	startupGateTimeout = 100 * time.Millisecond
	defer func() { startupGateTimeout = old }()

	err := promptStartupTouchID(context.Background(), fakeHelper(t, "sleep 5"), discardLogger())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestPromptStartupTouchID_ExitCodes(t *testing.T) {
	cases := map[string]string{
		"exit 0": "",
		"exit 1": "canceled",
		"exit 2": "rejected",
		"exit 7": "helper exit 7",
	}
	for script, want := range cases {
		err := promptStartupTouchID(context.Background(), fakeHelper(t, "cat >/dev/null; "+script), discardLogger())
		if want == "" {
			if err != nil {
				t.Errorf("%s: err = %v, want nil", script, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want containing %q", script, err, want)
		}
	}
}

// Parent cancellation (SIGTERM during the prompt) is reported as an
// abort carrying ctx's error, not as a timeout.
func TestPromptStartupTouchID_ParentCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	err := promptStartupTouchID(ctx, fakeHelper(t, "sleep 5"), discardLogger())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// SECURITY M4 — the startup gate verifies the helper's pinned SHA-256
// before exec. A helper that would approve (exit 0) but doesn't match
// the pin must be refused without running and without the inner acquire
// (the Keychain load) being reached.
func TestStartupGate_RefusesHelperWithWrongHash(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	helper := fakeHelper(t, "cat >/dev/null; touch "+marker+"; exit 0")
	restore := approval.SetTouchIDHashForTesting(strings.Repeat("0f", 32))
	defer restore()

	innerCalled := false
	acq := newStartupGatedAcquire(helper, func(context.Context) (SessionBundle, error) {
		innerCalled = true
		return fakeBundle{}, nil
	}, discardLogger())
	_, err := acq(context.Background())
	if !errors.Is(err, ErrTouchIDGate) || !errors.Is(err, approval.ErrHelperUntrusted) {
		t.Fatalf("err = %v, want ErrTouchIDGate wrapping ErrHelperUntrusted", err)
	}
	if innerCalled {
		t.Fatal("session acquire ran despite an untrusted helper")
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("untrusted helper was executed")
	}
}

// The unlock requester is named in the dialog body.
func TestStartupGate_NamesRequester(t *testing.T) {
	out := filepath.Join(t.TempDir(), "stdin")
	helper := fakeHelper(t, "cat > "+out)
	ctx := withUnlockRequester(context.Background(), "proton_connect from claude (pid 42)")
	if err := promptStartupTouchID(ctx, helper, discardLogger()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), "Requested by: proton_connect from claude (pid 42)") {
		t.Fatalf("helper payload %s does not name the requester", got)
	}
}

// Every prompt failure is tagged ErrTouchIDGate so Setup starts locked
// instead of exiting; an approval runs the inner acquire.
func TestStartupGatedAcquire_TagsGateFailures(t *testing.T) {
	inner := func(context.Context) (SessionBundle, error) { return fakeBundle{}, nil }
	acq := newStartupGatedAcquire(fakeHelper(t, "cat >/dev/null; exit 1"), inner, discardLogger())
	if _, err := acq(context.Background()); !errors.Is(err, ErrTouchIDGate) {
		t.Fatalf("declined prompt: err = %v, want ErrTouchIDGate", err)
	}
	innerErr := errors.New("login required")
	acq = newStartupGatedAcquire(fakeHelper(t, "cat >/dev/null"),
		func(context.Context) (SessionBundle, error) { return nil, innerErr }, discardLogger())
	if _, err := acq(context.Background()); errors.Is(err, ErrTouchIDGate) || !errors.Is(err, innerErr) {
		t.Fatalf("acquire failure after approval: err = %v, want inner error only", err)
	}
}
