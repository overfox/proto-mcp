// Package serve assembles the long-running MCP-server runtime: the
// session, policy engine, audit writer, approval broker, caller
// resolver, and configured mcp.Server. Shared by serve-stdio (one
// transport, stdin/stdout) and protonmcpd (one transport, Unix
// socket accept loop).
//
// The split is for code reuse, not for hiding the wiring. The setup
// is intentionally explicit — callers pass Deps with their own
// session-acquire callback so the daemon can choose resume-only
// behavior while a future interactive command could prompt.
package serve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// Runtime is the bundle of state every long-running MCP-serving
// process holds. Construct via Setup(). The MCPServer field is
// what transport code (stdio / Unix socket) calls Serve on.
//
// Concurrency: every field is independently safe for concurrent
// use. The daemon model (one Runtime, N connections) shares this
// instance across goroutines without additional locking.
type Runtime struct {
	Store     *store.Store
	Session   *protonclient.Session
	Bundle    SessionBundle // close + revoke surface from the cmd package
	Policy    *policy.Engine
	Audit     *audit.Writer
	Broker    *approval.Broker
	Resolver  *caller.Resolver
	MCPServer *mcp.Server

	// Phase 6/E — lock/unlock state. The lock signal (SIGUSR1 or
	// `protonmcp lock`) zeroes Session and flips Locked=true; the
	// MCP middleware checks Locked before running any tool and
	// returns a structured "daemon_locked" error. Unlock (SIGUSR2
	// or `protonmcp unlock`) prompts Touch ID via the existing
	// approval broker, then re-runs the session-acquire callback.
	//
	// The Locked flag is intentionally readable without a lock
	// (via Locked() method). Concurrent reads from middleware vs
	// writes from the signal handler are race-safe via the mu
	// mutex on the write path; the worst-case race lets one
	// in-flight tool call get through during the lock signal,
	// which is acceptable (lock is best-effort hygiene, not a
	// hard wall).
	mu             sync.RWMutex
	locked         bool
	lockReason     string
	acquireSession func(context.Context) (SessionBundle, error)

	// live owns the current session's lifetime (guarded by mu; nil
	// while locked). Background sync and every session-backed tool
	// hold a reference on it, so Lock can never close the session out
	// from under them — see liveSession. lastEmail survives a lock so
	// the state file can still name the account.
	live      *liveSession
	lastEmail string

	// unlockSem serializes Unlock so two concurrent unlocks don't both
	// fire a Touch ID prompt. It is held across the (slow) prompt, but
	// — unlike r.mu — nothing on the tool-call hot path or Lock touches
	// it, so a pending unlock can't freeze the daemon (PROTO-141). A
	// channel rather than a Mutex so waiters can give up on ctx.
	unlockSem     chan struct{}
	unlockSemOnce sync.Once

	// state publishes transitions to state.json for the menu bar (nil
	// outside the daemon). pubMu orders read-state + write so two
	// racing transitions can't land on disk out of order.
	state *StatePublisher
	pubMu sync.Mutex

	// syncFn / fullRefreshFn replace the real Proton calls in tests.
	// nil → syncpkg.
	syncFn        func(ctx context.Context, sess *protonclient.Session, st *store.Store, logger *slog.Logger)
	fullRefreshFn func(ctx context.Context, sess *protonclient.Session, st *store.Store) (*syncpkg.BackfillResult, error)

	// lastFullRefresh (unix nanos) rate-limits the automatic backfill
	// the daemon runs when the event stream demands a full refresh.
	lastFullRefresh atomic.Int64

	// connectFailedAt records the last declined proton_connect, guarded
	// by mu. Drives connectCooldown.
	connectFailedAt time.Time

	// Phase 7/A — auto-lock infrastructure. idleTracker bumps on
	// every tool call via the mcp.WithToolCallObserver hook.
	// lockwatchCancel terminates the Swift lockwatch helper on
	// runtime Close (the helper inherits our SIGTERM via its own
	// process group but we cancel explicitly for cleanliness).
	idleTracker     *idleTracker
	lockwatchCancel func()

	// bgSyncCancel stops the background goroutines (sync ticker —
	// PROTO-144 —, idle tracker, pending SIGUSR2 unlocks) on Close.
	bgSyncCancel func()

	hupStop   chan struct{}
	pidUnlink func()
}

// Locked reports whether the runtime is currently in the locked
// state. Middleware checks this on every tool call.
func (r *Runtime) Locked() (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.locked, r.lockReason
}

// lockDrainTimeout bounds how long Lock waits for in-flight session
// users (background sync, tool calls) to notice the cancellation and
// release the session. Past it, Lock returns anyway; the session is
// closed by whichever user finishes last.
const lockDrainTimeout = 5 * time.Second

// Lock drops the in-memory session and flips Locked=true. Idempotent
// (re-lock from an already-locked state is a no-op). Reason is shown
// to the LLM in the structured error response so it knows whether
// the lock was manual, idle, or signal-driven.
//
// The session is retired, not closed on the spot: its context is
// cancelled (aborting in-flight HTTP) and the keyring wipe runs once
// the last user releases it. Closing it directly used to nil the
// client under the background sync goroutine and crash the daemon.
func (r *Runtime) Lock(reason string) {
	r.mu.Lock()
	if r.locked {
		r.mu.Unlock()
		return
	}
	r.locked = true
	r.lockReason = reason
	ls := r.live
	legacy := r.Session
	r.live = nil
	r.Session = nil
	r.Bundle = nil
	// Point the tools at "no session" so nothing keeps a handle on the
	// retired one. Under mu so a racing Unlock's rebind can't be
	// clobbered by ours.
	if r.MCPServer != nil {
		r.MCPServer.ReplaceTools(r.toolsFor(nil))
	}
	// Drop every cached approval — a locked-then-unlocked daemon
	// shouldn't honor pre-lock prompts (the user may have wanted
	// to revoke them by locking).
	if r.Broker != nil {
		r.Broker.Invalidate()
	}
	r.mu.Unlock()
	slog.Info("daemon locked", "reason", reason)
	r.publishState()

	switch {
	case ls != nil:
		waitDrained(ls.retire(), lockDrainTimeout)
	case legacy != nil:
		// A session installed without a liveSession (tests build
		// Runtimes by hand); nothing can hold a reference to it.
		legacy.Close()
	}
}

func waitDrained(drained <-chan struct{}, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-drained:
	case <-t.C:
		slog.Warn("session still in use after lock; it will be closed when the last call finishes",
			"waited", timeout.String())
	}
}

// ErrUnlockInProgress is returned by Connect when another unlock (a
// pending Touch ID prompt or a network retry) already holds the slot.
var ErrUnlockInProgress = errors.New("an unlock is already in progress; try again shortly")

func (r *Runtime) unlockSlot() chan struct{} {
	r.unlockSemOnce.Do(func() { r.unlockSem = make(chan struct{}, 1) })
	return r.unlockSem
}

// Unlock re-acquires the session by calling the same callback that
// Setup used at startup. Caller-supplied (typically Touch ID gated
// via the approval broker). Returns the error from session acquire
// so the CLI / signal handler can report it. Waits (bounded by ctx)
// for a concurrent unlock to finish rather than prompting twice.
func (r *Runtime) Unlock(ctx context.Context) error {
	return r.unlock(ctx, true)
}

func (r *Runtime) unlock(ctx context.Context, wait bool) error {
	// Serialize unlocks (so two don't both prompt) WITHOUT holding the
	// runtime RWMutex across the prompt — see unlockSem's doc.
	slot := r.unlockSlot()
	if wait {
		select {
		case slot <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	} else {
		select {
		case slot <- struct{}{}:
		default:
			return ErrUnlockInProgress
		}
	}
	defer func() { <-slot }()

	r.mu.RLock()
	locked := r.locked
	acquire := r.acquireSession
	r.mu.RUnlock()
	if !locked {
		return nil
	}
	if acquire == nil {
		return errors.New("runtime: no acquireSession callback registered for unlock")
	}

	// PROTO-141: the Touch-ID-gated acquire (up to a 60s human prompt)
	// runs OUTSIDE r.mu, so it can't block the tool-call hot path
	// (r.Locked() → RLock) or an emergency Lock for the prompt's
	// duration. We take the write lock only for the fast state swap.
	bundle, err := acquire(ctx)
	if err != nil {
		// The acquire may have published "connecting" while it waited
		// on the network; put the file back to the real (locked) state.
		r.publishState()
		return err
	}
	ls := newLiveSession(bundle)

	r.mu.Lock()
	if !r.locked {
		// Lost a race with a concurrent unlock; discard our acquire.
		r.mu.Unlock()
		ls.retire()
		return nil
	}
	r.live = ls
	r.Bundle = bundle
	r.Session = ls.sess
	if ls.sess != nil {
		r.lastEmail = ls.sess.Email
	}
	// PROTO-132: rebind every session-backed tool handler to the freshly
	// acquired session. Handlers captured the OLD (now Closed) session
	// pointer at Setup; without this they'd dereference a closed session
	// after the first lock/unlock cycle.
	if r.MCPServer != nil {
		r.MCPServer.ReplaceTools(r.toolsFor(ls))
	}
	r.locked = false
	r.lockReason = ""
	r.mu.Unlock()

	// An unlock is activity: without this the idle clock still read
	// the last pre-lock tool call, and the daemon re-locked on the very
	// next idle tick.
	if r.idleTracker != nil {
		r.idleTracker.bumpActivity()
	}
	slog.Info("daemon unlocked")
	r.publishState()
	return nil
}

// toolsFor builds the full tool set bound to ls (nil = locked, no
// session). Must not take r.mu — Lock / unlock call it while holding
// the write lock.
func (r *Runtime) toolsFor(ls *liveSession) []mcp.Tool {
	var sess *protonclient.Session
	if ls != nil {
		sess = ls.sess
	}
	tools := wrapTools(ls, mcptools.All(mcptools.Deps{
		Session: sess,
		Store:   r.Store,
		Policy:  r.Policy,
		Connect: r.Connect,
		Approve: r.Broker.Approver(),
	}))
	return recordToolCalls(r.state, tools)
}

// publishState writes the current lock state to the state file.
func (r *Runtime) publishState() {
	if r.state == nil {
		return
	}
	r.pubMu.Lock()
	defer r.pubMu.Unlock()
	r.mu.RLock()
	locked, reason, email := r.locked, r.lockReason, r.lastEmail
	r.mu.RUnlock()
	if locked {
		r.state.SetState(StateLocked, reason, email)
	} else {
		r.state.SetState(StateUnlocked, "", email)
	}
}

// connectCooldown is how long proton_connect refuses to re-prompt after
// a declined or failed Touch ID. Stops a looping or prompt-injected
// model from stacking dialogs on the user's screen.
const connectCooldown = 20 * time.Second

// unlockTimeout bounds a SIGUSR2 / `protonmcp unlock`: the Touch ID
// prompt plus the session resume, including the daemon's network
// retry loop. It used to run under context.Background(), so an offline
// unlock held the unlock slot forever and every proton_connect hung
// behind it.
const unlockTimeout = 3 * time.Minute

// connectBound caps Runtime.Connect: the Touch ID prompt (60s) plus a
// single resume attempt.
const connectBound = 2 * time.Minute

// Connect backs the proton_connect tool. Already unlocked → reports
// that without prompting. Locked → runs the same Touch-ID-gated Unlock
// as SIGUSR2 / `protonmcp unlock`, but with network retry disabled
// (an offline Mac gets an error back, not a tool call that hangs for
// minutes) and without queueing behind another in-flight unlock.
func (r *Runtime) Connect(ctx context.Context) (alreadyConnected bool, email string, err error) {
	if locked, _ := r.Locked(); !locked {
		return true, r.sessionEmail(), nil
	}
	r.mu.RLock()
	wait := time.Until(r.connectFailedAt.Add(connectCooldown))
	r.mu.RUnlock()
	if wait > 0 {
		return false, "", fmt.Errorf("previous Touch ID attempt was declined; retry in %ds", int(wait.Seconds())+1)
	}
	ctx, cancel := context.WithTimeout(WithoutNetworkRetry(ctx), connectBound)
	defer cancel()
	if err := r.unlock(ctx, false); err != nil {
		// Cool down only after a declined / timed-out prompt — that's
		// the dialog-stacking risk. A network failure after approval
		// may be retried right away.
		if errors.Is(err, ErrTouchIDGate) {
			r.mu.Lock()
			r.connectFailedAt = time.Now()
			r.mu.Unlock()
		}
		return false, "", err
	}
	return false, r.sessionEmail(), nil
}

// Email returns the connected account ("" while locked with no session).
func (r *Runtime) Email() string { return r.sessionEmail() }

func (r *Runtime) sessionEmail() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.Session == nil {
		return ""
	}
	return r.Session.Email
}

type noRetryKey struct{}

// WithoutNetworkRetry marks ctx so an AcquireSession callback makes a
// single attempt instead of waiting out a network outage. Runtime.Connect
// sets it: the model is waiting on the tool call.
func WithoutNetworkRetry(ctx context.Context) context.Context {
	return context.WithValue(ctx, noRetryKey{}, true)
}

// NetworkRetryAllowed reports whether an AcquireSession callback may
// retry network failures under ctx (false under WithoutNetworkRetry).
func NetworkRetryAllowed(ctx context.Context) bool {
	v, _ := ctx.Value(noRetryKey{}).(bool)
	return !v
}

// SessionBundle is the cmd-side wrapper around a Proton session.
// We refer to it via an interface here so internal/serve doesn't
// import cmd/protonmcp (which would be a cycle anyway). The
// underlying type lives in cmd/protonmcp's session.go.
type SessionBundle interface {
	Close()
	GetSession() *protonclient.Session
}

// SweepStaleBodies hard-deletes cached body rows older than
// store.DefaultBodyRetention. The default SetupConfig hook for the
// SECURITY D13 / C-1 startup sweep — both serve-stdio and
// protonmcpd pass this in.
func SweepStaleBodies(ctx context.Context, st *store.Store) (int64, error) {
	cutoff := time.Now().Add(-store.DefaultBodyRetention).UTC()
	// PROTO-135 — best-effort sweep of the on-disk decrypted-attachment
	// staging dir at the same retention cutoff, so daemon startup also
	// clears stale plaintext files (not just the SQLite cache rows).
	_, _ = mcptools.SweepStagingOlderThan(cutoff)
	return st.PurgeOlderThan(ctx, cutoff)
}

// SetupConfig is the input to Setup. Callers fill it in based on
// which transport they're building.
type SetupConfig struct {
	// DBPath overrides the SQLite store path. "" → DefaultPath().
	DBPath string

	// AcquireSession is how this runtime should obtain a logged-in
	// Proton session. serve-stdio passes acquireSessionResumeOnly;
	// the daemon does too. Future interactive commands could pass
	// a prompt-allowed variant.
	AcquireSession func(ctx context.Context) (SessionBundle, error)

	// SweepBodiesAtStartup — optional D13/C-1 retention sweep.
	// Pass cmd/protonmcp's sweepBodiesAtStartup wrapper or nil.
	SweepBodiesAtStartup func(ctx context.Context, st *store.Store) (int64, error)

	// State, if set, receives lock-state transitions and tool calls
	// (protonmcpd's state.json for the menu bar). nil → no state file.
	// The caller owns its heartbeat (State.Run) and Remove.
	State *StatePublisher

	// Logger overrides slog.Default for runtime-level diagnostics.
	// Tool handlers and middleware still use slog.Default; this
	// is just for Setup / Close / HUP messages.
	Logger *slog.Logger
}

// Setup assembles every dependency a long-running MCP server needs.
// Returns a Runtime + an error. On error any partially-initialized
// resources are torn down before returning so callers don't have
// to special-case half-built runtimes.
//
// Lifecycle: the SIGHUP handler is installed by Setup and torn
// down by Close. Same for the PID file (so `protonmcp policy
// reload` can find a running daemon).
func Setup(ctx context.Context, cfg SetupConfig) (*Runtime, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Store.
	path := cfg.DBPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return nil, fmt.Errorf("default db path: %w", err)
		}
		path = p
	}
	st, err := store.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// 2. Retention sweep (D13/C-1).
	if cfg.SweepBodiesAtStartup != nil {
		if n, err := cfg.SweepBodiesAtStartup(ctx, st); err != nil {
			logger.Warn("body purge sweep failed at startup", "err", err.Error())
		} else if n > 0 {
			logger.Info("purged stale cached bodies at startup", "rows", n)
		}
	}

	// 3. Session (eager-acquire). Phase 6/E added the application-
	// layer Touch-ID-at-startup gate as a substitute for the then-
	// deferred OS Keychain ACL.
	//
	// D40 (and its revert): Phase 7/D briefly shipped the real OS-
	// level ACL and we dropped this gate on darwin to avoid the
	// double prompt. But 7/D required a `keychain-access-groups`
	// entitlement that Developer ID Application signing alone
	// can't authorize (restricted entitlement; needs a real
	// provisioning profile), so the kernel SIGKILLs the signed
	// binary. D37 was reopened and deferred to Phase 7/E (.app
	// bundle + provisioning); the application-layer gate is back
	// in unconditionally on every platform. See [[D37]] / [[D40]]
	// in DEFECTS.html for the full story.
	if cfg.AcquireSession == nil {
		_ = st.Close()
		return nil, errors.New("serve.Setup: AcquireSession is required")
	}

	startupHelperPath, helperResolveErr := approval.ResolveHelperPath(os.Args[0])
	// PROTO-127: fail CLOSED. Previously a missing/untrusted helper fell
	// through to an UNGATED session load — the daemon came up fully
	// authenticated from the Keychain with no biometric check. Since the
	// application-layer Touch ID gate is the only biometric barrier (the
	// OS-level Keychain ACL, D37, is deferred), refuse to load the
	// session without it rather than silently bypass.
	if helperResolveErr != nil {
		_ = st.Close()
		return nil, fmt.Errorf(
			"refusing to load the Proton session without a trusted Touch ID helper "+
				"(would be an ungated session load — PROTO-127). Run `make touchid` "+
				"or reinstall so the helper is present: %w", helperResolveErr)
	}
	gatedAcquire := newStartupGatedAcquire(startupHelperPath, cfg.AcquireSession, logger)

	// Try the gate exactly once, so a normal boot gets exactly one
	// prompt. A declined / timed-out prompt no longer fails Setup:
	// exiting non-zero made launchd relaunch the daemon, which
	// prompted again — hundreds of times overnight. Instead come up
	// LOCKED (LockReasonTouchIDRequired) with the socket open; the user
	// unlocks via proton_connect, `protonmcp unlock`, or the menu bar.
	// Failures of the acquire itself (login required, shutdown) still
	// fail Setup as before.
	var ls *liveSession
	bundle, err := gatedAcquire(ctx)
	switch {
	case err == nil:
		ls = newLiveSession(bundle)
	case errors.Is(err, ErrTouchIDGate) && ctx.Err() == nil:
		logger.Warn("touch-id startup gate not approved; starting locked",
			"err", err.Error(), "unlock", "proton_connect tool or `protonmcp unlock`")
	default:
		_ = st.Close()
		return nil, fmt.Errorf("acquire session: %w", err)
	}
	cleanupSession := func() {
		if ls != nil {
			ls.retire()
		}
	}

	// 4. Policy engine.
	overridePath, err := policy.DefaultOverridePath()
	if err != nil {
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("policy override path: %w", err)
	}
	engine, err := policy.New(ctx, overridePath, logger)
	if err != nil {
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("policy engine: %w", err)
	}

	// 5. PID file (so `policy reload` can pgrep us).
	pidPath, err := policy.DefaultPIDPath()
	if err != nil {
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("pid file path: %w", err)
	}
	pidCleanup, err := policy.WritePIDFile(pidPath)
	if err != nil {
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("pid file: %w", err)
	}

	// 6. Audit writer.
	jsonlPath, err := audit.DefaultJSONLPath()
	if err != nil {
		pidCleanup()
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("audit path: %w", err)
	}
	auditWriter, err := audit.New(st.DB, jsonlPath, logger)
	if err != nil {
		pidCleanup()
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("audit writer: %w", err)
	}

	// 7. Approval broker. The helper is guaranteed present here — Setup
	// fails closed above (PROTO-127) if it couldn't resolve a trusted
	// one — so there's no nil-broker / "prompts denied" degraded mode.
	// Reuse the resolved path so we only pgrep + stat once.
	broker, err := approval.New(startupHelperPath, logger)
	if err != nil {
		_ = auditWriter.Close()
		pidCleanup()
		cleanupSession()
		_ = st.Close()
		return nil, fmt.Errorf("approval broker: %w", err)
	}

	// 8. Caller resolver.
	resolver := caller.New()

	// 9. SIGHUP handler — policy reload + approval cache drop.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	hupStop := make(chan struct{})
	go func() {
		for {
			select {
			case <-hupCh:
				if rerr := engine.Reload(); rerr != nil {
					logger.Warn("policy reload failed; previous policy retained", "err", rerr.Error())
					continue
				}
				n := 0
				if broker != nil {
					n = broker.Invalidate()
				}
				logger.Info("policy reloaded", "approvals_dropped", n)
			case <-hupStop:
				signal.Stop(hupCh)
				return
			}
		}
	}()

	// 10. MCP server with full middleware stack.
	//
	// rt is built post-srv so the lock-state callback closes over
	// it. Done in two steps so the closure has a stable target.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	rt := &Runtime{
		Store:          st,
		Policy:         engine,
		Audit:          auditWriter,
		Broker:         broker,
		Resolver:       resolver,
		hupStop:        hupStop,
		pidUnlink:      pidCleanup,
		acquireSession: gatedAcquire,
		state:          cfg.State,
		bgSyncCancel:   bgCancel,
	}
	if ls != nil {
		rt.live = ls
		rt.Bundle = bundle
		rt.Session = ls.sess
		if ls.sess != nil {
			rt.lastEmail = ls.sess.Email
		}
	} else {
		rt.locked = true
		rt.lockReason = LockReasonTouchIDRequired
	}
	rt.idleTracker = newIdleTracker()
	opts := []mcp.Option{
		mcp.WithPolicy(engine),
		mcp.WithAudit(auditWriter),
		mcp.WithCallerResolver(resolver),
		mcp.WithRateLimitPersister(newRateLimitStoreAdapter(st)),
		mcp.WithLockState(rt.Locked),
		mcp.WithToolCallObserver(rt.idleTracker.bumpActivity),
	}
	if broker != nil {
		opts = append(opts, mcp.WithApproval(broker))
	}
	srv := mcp.New(logger, opts...)
	// Session-backed handlers are bound to ls (nil when starting
	// locked: they refuse, and the middleware lock gate refuses them
	// first anyway). Unlock rebinds via ReplaceTools.
	for _, tl := range rt.toolsFor(ls) {
		srv.Register(tl)
	}
	rt.MCPServer = srv

	// Phase 6/E — install SIGUSR1 / SIGUSR2 handlers for lock /
	// unlock. The signals are documented in the protonmcp lock /
	// unlock CLI subcommands; the daemon binary's main signal
	// loop is separate (SIGTERM-as-shutdown), so these two are
	// handled here.
	//
	// Unlock runs off the signal loop (so a pending prompt or network
	// retry can't delay a SIGUSR1 lock) and is bounded by
	// unlockTimeout. A second SIGUSR2 while one is pending is dropped
	// rather than stacking another prompt.
	usrCh := make(chan os.Signal, 2)
	signal.Notify(usrCh, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range usrCh {
			switch sig {
			case syscall.SIGUSR1:
				rt.Lock("SIGUSR1")
			case syscall.SIGUSR2:
				go func() {
					uctx, cancel := context.WithTimeout(bgCtx, unlockTimeout)
					defer cancel()
					if err := rt.unlock(uctx, false); err != nil {
						logger.Warn("unlock failed", "err", err.Error())
					}
				}()
			}
		}
	}()

	// Phase 7/A — idle-lock + lockwatch helper.
	//
	// Idle lock: goroutine ticks every 30s, checks the engine's
	// IdleLockMinutes() (policy reload picks up new values), locks
	// the runtime when threshold exceeded.
	//
	// Lockwatch: spawn the Swift helper as a managed subprocess if
	// the binary is on disk. The helper writes "screen_locked" /
	// "sleep" lines to stdout when macOS broadcasts the
	// corresponding distributed notifications; we read those and
	// call Lock with the reason. If the helper isn't built, fall
	// through silently — the daemon still works, just without the
	// auto-lock triggers.
	// Both automatic triggers route through autoLock so Keep Alive can
	// veto them. Manual locks (SIGUSR1 / `protonmcp lock` / menu Lock
	// Now) call rt.Lock directly and are never vetoed.
	autoLock := keepAliveGuard(engine.KeepAlive, rt.Lock, logger)
	idleSkip := func() bool {
		locked, _ := rt.Locked()
		return locked || engine.KeepAlive()
	}
	go rt.idleTracker.run(bgCtx, engine.IdleLockMinutes, idleSkip, autoLock, logger)
	if lockwatchPath, found := resolveLockwatchPath(); found {
		rt.lockwatchCancel = startLockwatch(lockwatchPath, autoLock, logger)
	} else {
		logger.Info("lockwatch helper not found; screen-lock and sleep auto-lock disabled",
			"hint", "run `make lockwatch` from the repo root")
	}

	// PROTO-144 — background sync. Without this the local mirror only
	// refreshes on an explicit mail_sync, so mail_list / mail_search
	// serve stale data. Drain the event stream on a fixed cadence,
	// skipping while locked (no session) and stopping on Close.
	go rt.runBackgroundSync(bgCtx, logger)
	go runStagingSweep(bgCtx, logger) // hourly attachment-staging retention sweep (staging_sweep.go)

	// State file: publish the post-Setup state. The heartbeat
	// goroutine (StatePublisher.Run) is the caller's: it must already
	// be running during Setup, which can sit in "connecting" for as
	// long as the network is down.
	cfg.State.SetKeepAlive(engine.KeepAlive)
	rt.publishState()

	return rt, nil
}

// backgroundSyncInterval / Timeout — the cadence at which the daemon
// drains the Proton event stream into the local mirror, and the
// per-tick deadline so a stalled sync can't pin the goroutine.
const (
	backgroundSyncInterval = 2 * time.Minute
	backgroundSyncTimeout  = 90 * time.Second
)

// runBackgroundSync ticks until ctx is cancelled (Close), draining the
// event stream each tick. PROTO-144.
func (r *Runtime) runBackgroundSync(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(backgroundSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.backgroundSyncOnce(ctx, logger)
		}
	}
}

// backgroundSyncOnce runs a single drain, honoring lock state (no
// session while locked) and a per-tick timeout. Errors log Warn and the
// loop continues — a transient sync failure isn't fatal to the daemon.
//
// The drain holds a reference on the live session for its whole
// duration, so a concurrent Lock cancels it and waits for it instead
// of closing the session underneath it (the old nil-client crash).
func (r *Runtime) backgroundSyncOnce(ctx context.Context, logger *slog.Logger) {
	if locked, _ := r.Locked(); locked {
		return // resumes automatically after unlock
	}
	r.mu.RLock()
	ls := r.live
	st := r.Store
	r.mu.RUnlock()
	if ls == nil || st == nil {
		return
	}
	sctx, release, err := ls.acquire(ctx)
	if err != nil {
		return // locked between the check and the acquire
	}
	defer release()

	if r.syncFn != nil {
		r.syncFn(sctx, ls.sess, st, logger)
		return
	}
	r.syncSession(sctx, ls.sess, st, logger)
}

// syncSession is one mail + calendar drain against sess. ctx is
// cancelled on Lock and on Close.
func (r *Runtime) syncSession(ctx context.Context, sess *protonclient.Session, st *store.Store, logger *slog.Logger) {
	syncCtx, cancel := context.WithTimeout(ctx, backgroundSyncTimeout)
	defer cancel()
	res, err := syncpkg.RunOnce(syncCtx, sess, st)
	if err != nil {
		switch {
		case errors.Is(err, syncpkg.ErrRefreshRequested):
			r.maybeFullRefresh(ctx, sess, st, logger)
		case ctx.Err() != nil:
			// daemon locking or shutting down — not an error
		default:
			logger.Warn("background sync failed", "err", err.Error())
		}
		return
	}
	if res != nil && (res.MessagesUpserted > 0 || res.MessagesDeleted > 0 ||
		res.LabelsUpserted > 0 || res.LabelsDeleted > 0) {
		logger.Info("background sync",
			"messages_upserted", res.MessagesUpserted,
			"messages_deleted", res.MessagesDeleted,
			"labels_upserted", res.LabelsUpserted,
			"labels_deleted", res.LabelsDeleted)
	}

	// Calendar sync rides the same tick + lock gate but is a separate
	// poll (the event stream carries no calendar delta). A calendar
	// failure is logged and ignored — it must not abort the mail sync.
	calRes, calErr := syncpkg.RunCalendarOnce(syncCtx, sess, st)
	if calErr != nil {
		if ctx.Err() == nil {
			logger.Warn("background calendar sync failed", "err", calErr.Error())
		}
		return
	}
	if calRes != nil && (calRes.EventsUpserted > 0 || calRes.EventsDeleted > 0 || calRes.CalendarsDeleted > 0) {
		logger.Info("background calendar sync",
			"events_upserted", calRes.EventsUpserted,
			"events_deleted", calRes.EventsDeleted,
			"calendars_deleted", calRes.CalendarsDeleted)
	}
}

// fullRefreshMinInterval rate-limits the automatic backfill; a server
// that keeps demanding refreshes must not turn the daemon into a
// metadata re-download loop. fullRefreshTimeout bounds one run (a
// multi-year mailbox takes minutes).
const (
	fullRefreshMinInterval = time.Hour
	fullRefreshTimeout     = 30 * time.Minute
)

// maybeFullRefresh self-heals a "server requested a full refresh"
// event: re-run the metadata backfill (which re-seeds the event
// cursor) instead of leaving the mirror frozen until a human runs
// `protonmcp backfill`. At most once per fullRefreshMinInterval; the
// attempt is recorded before running so a failing backfill is rate
// limited too. Runs on the sync goroutine, under the session
// reference, so Lock cancels it like any other sync.
func (r *Runtime) maybeFullRefresh(ctx context.Context, sess *protonclient.Session, st *store.Store, logger *slog.Logger) {
	now := time.Now()
	if last := r.lastFullRefresh.Load(); last != 0 {
		if next := time.Unix(0, last).Add(fullRefreshMinInterval); now.Before(next) {
			logger.Warn("background sync: server requested a full refresh; automatic backfill ran recently",
				"next_attempt_in", time.Until(next).Round(time.Second).String())
			return
		}
	}
	r.lastFullRefresh.Store(now.UnixNano())
	logger.Warn("background sync: server requested a full refresh; running automatic backfill")

	rctx, cancel := context.WithTimeout(ctx, fullRefreshTimeout)
	defer cancel()
	refresh := r.fullRefreshFn
	if refresh == nil {
		refresh = func(ctx context.Context, sess *protonclient.Session, st *store.Store) (*syncpkg.BackfillResult, error) {
			return syncpkg.Backfill(ctx, sess, st, syncpkg.BackfillOptions{})
		}
	}
	res, err := refresh(rctx, sess, st)
	if err != nil {
		if ctx.Err() == nil {
			logger.Warn("automatic backfill failed; will retry after the rate limit",
				"err", err.Error(), "retry_after", fullRefreshMinInterval.String())
		}
		return
	}
	logger.Info("automatic backfill complete",
		"messages", res.Written,
		"labels", res.Labels,
		"elapsed", res.Elapsed.Round(time.Millisecond).String())
}

// Close tears down the runtime in reverse setup order. Safe to call
// once; idempotency past the first call is not guaranteed.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	if r.bgSyncCancel != nil {
		r.bgSyncCancel()
	}
	if r.lockwatchCancel != nil {
		r.lockwatchCancel()
	}
	if r.idleTracker != nil {
		r.idleTracker.close()
	}
	if r.hupStop != nil {
		close(r.hupStop)
	}

	// Retire the session and give in-flight users (cancelled above /
	// by retire) a bounded moment to let go before the store they
	// write to is closed.
	r.mu.Lock()
	ls := r.live
	legacy := r.Session
	legacyBundle := r.Bundle
	r.live = nil
	r.Session = nil
	r.Bundle = nil
	r.mu.Unlock()
	if ls != nil {
		waitDrained(ls.retire(), lockDrainTimeout)
	} else {
		if legacyBundle != nil {
			legacyBundle.Close()
		}
		if legacy != nil {
			legacy.Close()
		}
	}

	if r.Audit != nil {
		_ = r.Audit.Close()
	}
	if r.pidUnlink != nil {
		r.pidUnlink()
	}
	if r.Store != nil {
		_ = r.Store.Close()
	}
}
