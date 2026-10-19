package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/session"
)

// sessionBundle is an alias of the shared session.Bundle. Kept under
// this local name to avoid a churn-y rename across the CLI
// subcommands (whoami / backfill / sync / etc all reference
// sessionBundle today). Phase 6's `internal/session` extraction
// keeps the type, just relocates the implementation so the daemon
// can use it without duplicating ~150 LOC.
type sessionBundle = session.Bundle

// acquireSessionResumeOnly delegates to internal/session for the
// resume-from-Keychain path. Same exported error messages. Only
// serve-stdio uses it, and serve.Setup wraps it in the daemon's Touch
// ID startup gate.
func acquireSessionResumeOnly(ctx context.Context) (*sessionBundle, error) {
	return session.AcquireResumeOnly(ctx)
}

// cliGateTimeout bounds the CLI's Touch ID prompt.
const cliGateTimeout = 60 * time.Second

// cliTouchIDGate is the biometric gate every CLI path runs before it
// reads the Proton session out of the Keychain (SECURITY H2). It is
// the same gate as the daemon's startup gate: the Touch ID helper,
// resolved next to the running binary and SHA-256-pin-verified before
// exec (approval.PromptDirect). There is no bypass flag. A var so tests
// can substitute a fake.
var cliTouchIDGate = func(ctx context.Context, cmd string) error {
	helper, err := approval.ResolveHelperPath(os.Args[0])
	if err != nil {
		return fmt.Errorf("refusing to unlock the Proton session without a trusted Touch ID helper "+
			"(run `make touchid` or reinstall): %w", err)
	}
	return approval.PromptDirect(ctx, helper, approval.DirectPrompt{
		Title:   "Unlock Proton keys",
		Body:    fmt.Sprintf("protonmcp %s wants to unlock your Proton keys.", cmd),
		Caller:  "protonmcp " + cmd,
		Timeout: cliGateTimeout,
	}, slog.Default())
}

// Injectable Keychain probes (tests).
var (
	keystoreExists = keystore.Exists
	tryResume      = session.TryResume
	keystoreLoad   = keystore.Load
)

// unlockStoredSession runs the Touch ID gate when a session blob exists
// in the Keychain. Returns (stored, nil) when the caller may read the
// blob, (false, nil) when nothing is stored (nothing to protect — the
// caller falls back to an interactive login or reports "not logged
// in"), or an error when the gate refused. A Keychain query error is
// treated as "stored" so the gate fails closed.
func unlockStoredSession(ctx context.Context, cmd string) (bool, error) {
	ok, err := keystoreExists()
	if err == nil && !ok {
		return false, nil
	}
	if gerr := cliTouchIDGate(ctx, cmd); gerr != nil {
		return true, fmt.Errorf("%w for `protonmcp %s`: %w", errTouchIDRequired, cmd, gerr)
	}
	return true, nil
}

// errTouchIDRequired tags every CLI gate refusal.
var errTouchIDRequired = errors.New("Touch ID required to unlock your Proton keys")

func isGateRefusal(err error) bool { return errors.Is(err, errTouchIDRequired) }

// loadStoredSession is keystore.Load behind the Touch ID gate. Used by
// the subcommands that read the blob directly (inspect, logout).
func loadStoredSession(ctx context.Context, cmd string) (keystore.Live, error) {
	stored, err := unlockStoredSession(ctx, cmd)
	if err != nil {
		return keystore.Live{}, err
	}
	if !stored {
		return keystore.Live{}, keystore.ErrNotFound
	}
	return keystoreLoad()
}

// acquireSession is the unified login-or-resume helper. Flow:
//
//  0. If the Keychain holds a session, require Touch ID first (H2:
//     every CLI Keychain load is biometric-gated, like the daemon's).
//     A declined prompt is an error — it does NOT fall through to the
//     interactive login.
//
//  1. Preload the stored cookies into a fresh jar, build the Manager
//     around that jar, and call Resume.
//
//  2. On Resume success, wire OnAuthUpdate so rotated tokens AND
//     refreshed cookies get written back to the Keychain. Returns.
//
//  3. On ErrSessionExpired: wipe the Keychain entry (so we don't loop
//     on the dead token), print a loud message that we're falling
//     through, then continue to step 4.
//
//  4. First-run / no-stored / re-auth path: empty jar, full
//     interactive SRP + TOTP, save session + cookies on success.
//
// cmd names the subcommand in the Touch ID dialog. Interactive — stays
// in cmd/protonmcp because it depends on internal/cli's /dev/tty
// prompts.
func acquireSession(ctx context.Context, cmd string) (*sessionBundle, error) {
	stored, err := unlockStoredSession(ctx, cmd)
	if err != nil {
		return nil, err
	}
	if stored {
		if b, err := tryResume(ctx); err == nil {
			return b, nil
		} else if !errors.Is(err, keystore.ErrNotFound) {
			slog.Warn("stored session unusable; re-authenticating", "err", err.Error())
		}
	}

	jar := protonclient.NewCookieJar()
	mgr := protonclient.NewManager(jar)

	creds, err := collectCredentials(ctx)
	if err != nil {
		mgr.Close()
		return nil, err
	}
	defer creds.Zero()

	sess, err := protonclient.Login(ctx, mgr, creds)
	if err != nil {
		mgr.Close()
		return nil, fmt.Errorf("login: %w", err)
	}

	bundle := &session.Bundle{Session: sess, Manager: mgr, Jar: jar}
	if err := session.Persist(bundle); err != nil {
		slog.Warn("failed to save session to Keychain; subsequent runs will need to log in again", "err", err.Error())
	}
	session.WireKeystoreSync(bundle)
	return bundle, nil
}
