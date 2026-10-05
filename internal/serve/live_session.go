package serve

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// liveSession owns one acquired Proton session for as long as anything
// is still using it. It exists because Lock used to Close the session
// out from under the background sync goroutine (and in-flight tools),
// which then nil-dereferenced the client and took the whole daemon down.
//
// Every user takes a reference via acquire and drops it via the
// returned release. retire (Lock / Close) cancels the session context
// — aborting in-flight HTTP — and refuses new references; the actual
// Close (keyring wipe, client teardown) runs when the last reference
// is released. drained is closed once that has happened, so Lock can
// wait for it with a bound.
type liveSession struct {
	sess   *protonclient.Session
	bundle SessionBundle

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	refs    int
	retired bool
	drained chan struct{}
}

func newLiveSession(bundle SessionBundle) *liveSession {
	ctx, cancel := context.WithCancel(context.Background())
	return &liveSession{
		sess:    bundle.GetSession(),
		bundle:  bundle,
		ctx:     ctx,
		cancel:  cancel,
		drained: make(chan struct{}),
	}
}

// acquire takes a reference and returns a context derived from parent
// that is additionally cancelled when the session is retired. The
// caller MUST call release exactly once. Fails with ErrSessionClosed
// once the session is retired (or on a nil liveSession — the runtime
// is locked with no session at all).
func (ls *liveSession) acquire(parent context.Context) (context.Context, func(), error) {
	if ls == nil {
		return nil, nil, protonclient.ErrSessionClosed
	}
	ls.mu.Lock()
	if ls.retired {
		ls.mu.Unlock()
		return nil, nil, protonclient.ErrSessionClosed
	}
	ls.refs++
	ls.mu.Unlock()

	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ls.ctx, cancel)
	var once sync.Once
	release := func() {
		once.Do(func() {
			stop()
			cancel()
			ls.release()
		})
	}
	return ctx, release, nil
}

func (ls *liveSession) release() {
	ls.mu.Lock()
	ls.refs--
	closeNow := ls.retired && ls.refs == 0
	ls.mu.Unlock()
	if closeNow {
		ls.closeSession()
	}
}

// retire stops handing out references, cancels in-flight users, and
// closes the session as soon as the last reference is released
// (immediately if there are none). Idempotent. Returns drained.
func (ls *liveSession) retire() <-chan struct{} {
	ls.mu.Lock()
	if ls.retired {
		ls.mu.Unlock()
		return ls.drained
	}
	ls.retired = true
	closeNow := ls.refs == 0
	ls.mu.Unlock()

	ls.cancel()
	if closeNow {
		ls.closeSession()
	}
	return ls.drained
}

// closeSession runs exactly once per liveSession: it is reached either
// from retire (no refs) or from the release that dropped refs to zero
// after retire, and those two are mutually exclusive under mu.
func (ls *liveSession) closeSession() {
	if ls.bundle != nil {
		ls.bundle.Close()
	}
	if ls.sess != nil {
		// Session.Close zeros the in-memory keyring + drops the
		// access/refresh tokens from the wrapped client. The Keychain
		// blob is untouched; unlock re-loads from there.
		ls.sess.Close()
	}
	close(ls.drained)
}

// lockedMessage is what a session-backed tool returns when it reaches a
// retired (or absent) session — the same guidance the middleware's
// lock gate gives.
const lockedMessage = "Proton is locked. Call the proton_connect tool to ask the user " +
	"for Touch ID, then retry this call."

// wrapTools pins every session-backed tool to ls: each call holds a
// reference for its duration (so Lock can't close the session under
// it) and runs with a context that Lock cancels. AllowWhenLocked tools
// (proton_connect) don't touch the session and pass through unchanged.
// ls may be nil (runtime started locked): wrapped tools then refuse.
func wrapTools(ls *liveSession, tools []mcp.Tool) []mcp.Tool {
	for i := range tools {
		t := &tools[i]
		if t.AllowWhenLocked || t.Handler == nil {
			continue
		}
		inner := t.Handler
		t.Handler = func(c mcp.Context, params json.RawMessage) (*mcp.ToolResult, error) {
			ctx, release, err := ls.acquire(c.Std)
			if err != nil {
				return mcp.ErrorResult(lockedMessage), nil
			}
			defer release()
			c.Std = ctx
			return inner(c, params)
		}
	}
	return tools
}

// recordToolCalls reports each tool's completion to the state file
// (last_tool / last_tool_at). Outermost wrapper, so a call refused by
// wrapTools still counts as the last thing the model tried. No-op
// without a publisher.
func recordToolCalls(p *StatePublisher, tools []mcp.Tool) []mcp.Tool {
	if p == nil {
		return tools
	}
	for i := range tools {
		t := &tools[i]
		if t.Handler == nil {
			continue
		}
		inner, name := t.Handler, t.Name
		t.Handler = func(c mcp.Context, params json.RawMessage) (*mcp.ToolResult, error) {
			defer p.ToolCalled(name)
			return inner(c, params)
		}
	}
	return tools
}
