package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
)

// newStartupGatedAcquire wraps an AcquireSession callback with a
// Touch-ID prompt. Phase 6/E — the application-layer substitute for
// the deferred Keychain ACL.
//
// Why this exists vs. just calling broker.Request: at the point we
// need to gate startup, the broker hasn't been constructed yet
// (broker construction is step 7 in Setup, AcquireSession is step
// 3). We invoke the helper directly (approval.PromptDirect) with a
// minimal payload matching the helper's stdin JSON contract.
//
// SECURITY M4: PromptDirect re-verifies the helper's pinned SHA-256
// before every exec, exactly like the broker — this gate used to exec
// whatever sat at helperPath unverified.
//
// Unlock-driven re-acquires hit the SAME wrapper (because
// rt.acquireSession is the gated callback), so SIGUSR2 and
// proton_connect also Touch-ID-prompt before touching the keychain;
// the requester (withUnlockRequester) is named in the dialog.
func newStartupGatedAcquire(helperPath string, inner func(context.Context) (SessionBundle, error), logger *slog.Logger) func(context.Context) (SessionBundle, error) {
	return func(ctx context.Context) (SessionBundle, error) {
		if err := promptStartupTouchID(ctx, helperPath, logger); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrTouchIDGate, err)
		}
		return inner(ctx)
	}
}

// ErrTouchIDGate wraps every failure of the Touch ID prompt itself
// (declined, timed out, helper error) — as opposed to a failure of the
// session acquire that runs after an approval. Setup matches it to come
// up locked instead of failing: exiting non-zero made launchd relaunch
// the daemon, which prompted again, all night.
var ErrTouchIDGate = errors.New("touch-id startup gate")

// startupGateTimeout caps the Touch ID prompt. 60s matches the
// approval broker's per-call timeout doubled — startup is rare and
// the user may need a moment to locate their finger. A var so tests
// can shorten it.
var startupGateTimeout = 60 * time.Second

type unlockRequesterKey struct{}

// withUnlockRequester names who asked for an unlock ("proton_connect
// from claude (pid 123)", "SIGUSR2 (protonmcp unlock / menu bar)") so
// the Touch ID dialog can say so.
func withUnlockRequester(ctx context.Context, who string) context.Context {
	return context.WithValue(ctx, unlockRequesterKey{}, who)
}

func unlockRequester(ctx context.Context) string {
	v, _ := ctx.Value(unlockRequesterKey{}).(string)
	return v
}

func promptStartupTouchID(ctx context.Context, helperPath string, logger *slog.Logger) error {
	body := "Touch ID required to unlock your saved Proton session so Claude can access Proton Mail."
	if who := unlockRequester(ctx); who != "" {
		body += "\n\nRequested by: " + who
	}
	err := approval.PromptDirect(ctx, helperPath, approval.DirectPrompt{
		Title:   "Unlock Proton Mail for Claude",
		Body:    body,
		Caller:  "protonmcp daemon",
		Timeout: startupGateTimeout,
	}, logger)
	if err == nil {
		logger.Info("touch-id startup gate approved")
	}
	return err
}
