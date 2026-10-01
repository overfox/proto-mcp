package serve

import "log/slog"

// keepAliveGuard wraps the runtime's Lock for the AUTOMATIC lock
// triggers (screen lock, sleep, idle timer). While Keep Alive is on,
// those triggers are logged and ignored, so the session survives the
// Mac locking its screen or sleeping. keepAlive is consulted on every
// event, so toggling Keep Alive off restores auto-locking on the next
// trigger without a daemon restart.
//
// Manual locks never go through this guard: the menu's Lock Now,
// `protonmcp lock`, and the kill switch always take effect.
func keepAliveGuard(keepAlive func() bool, lock func(reason string), logger *slog.Logger) func(reason string) {
	return func(reason string) {
		if keepAlive() {
			logger.Info("keep alive on; ignoring auto-lock", "reason", reason)
			return
		}
		lock(reason)
	}
}
