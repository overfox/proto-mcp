package serve

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// idleTracker holds the most-recent tool-call timestamp (as Unix
// nanoseconds in an atomic int64) and runs a periodic check that
// locks the runtime if the configured idle threshold is exceeded.
//
// Phase 7/A — policy field idle_lock_minutes (default 0 = disabled,
// max 1440 = 24h). The runtime spawns one of these in Setup if the
// engine reports a non-zero idle threshold; on policy reload the
// threshold is re-read from the engine on every tick so a user can
// change the value without restarting the daemon.
//
// Concurrency: the timestamp is a single atomic.Int64; bumpActivity
// is called from the middleware hot path (must be lock-free). The
// poll goroutine reads atomically and may call Runtime.Lock — Lock
// has its own mutex, so the chain is safe.
type idleTracker struct {
	lastActivity atomic.Int64 // unix nanos
	stop         chan struct{}
}

func newIdleTracker() *idleTracker {
	t := &idleTracker{stop: make(chan struct{})}
	t.lastActivity.Store(time.Now().UnixNano())
	return t
}

// bumpActivity records "tool call happened just now." Lock-free.
// Wired into the mcp.Middleware via mcp.WithToolCallObserver, and
// called by Runtime.Unlock so an unlock counts as activity.
func (t *idleTracker) bumpActivity() {
	t.lastActivity.Store(time.Now().UnixNano())
}

// run polls every 30 seconds. minutesFn is called on each tick so
// policy reloads pick up new thresholds without restart. skipFn
// reports whether the check is moot this tick (runtime already locked,
// or Keep Alive on); lockFn is the (Keep-Alive-guarded) runtime Lock.
//
// 30s tick is the granularity / responsiveness trade-off: a user
// setting idle_lock_minutes=1 sees the lock fire 0–30s after the
// last activity, which is acceptable. A finer tick would burn CPU
// for no real gain.
func (t *idleTracker) run(ctx context.Context, minutesFn func() int, skipFn func() bool, lockFn func(reason string), logger *slog.Logger) {
	const tickInterval = 30 * time.Second
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.check(minutesFn, skipFn, lockFn, logger)
		}
	}
}

// check is one tick of run. Split out so tests can drive it without
// waiting on the 30s ticker.
//
// Skips entirely while skipFn says so (locked: there is nothing to
// lock; Keep Alive: the guard would veto it anyway). The old
// code logged "idle threshold exceeded" every tick for as long as the
// daemon stayed locked (13k lines overnight). Activity is reset by
// Runtime.Unlock, so the threshold restarts from the moment of unlock
// rather than from the last pre-lock tool call — previously a daemon
// re-locked within one tick of every unlock.
func (t *idleTracker) check(minutesFn func() int, skipFn func() bool, lockFn func(reason string), logger *slog.Logger) {
	if skipFn != nil && skipFn() {
		return
	}
	minutes := minutesFn()
	if minutes <= 0 {
		return
	}
	threshold := time.Duration(minutes) * time.Minute
	since := time.Since(time.Unix(0, t.lastActivity.Load()))
	if since >= threshold {
		logger.Info("idle threshold exceeded; locking daemon",
			"idle_minutes", int(since.Minutes()),
			"threshold_minutes", minutes)
		lockFn("idle_timeout")
	}
}

// close stops the poll goroutine. Idempotent.
func (t *idleTracker) close() {
	select {
	case <-t.stop:
		// already closed
	default:
		close(t.stop)
	}
}
