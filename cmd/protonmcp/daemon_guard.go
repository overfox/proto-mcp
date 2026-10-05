package main

import (
	"fmt"
)

// daemonRunning reports whether protonmcpd is up, by dialing its
// socket. A var so tests can stub it.
var daemonRunning = func() bool {
	path, err := daemonSocketPath()
	if err != nil {
		return false
	}
	return socketReachable(path)
}

// refuseIfDaemonRunning guards the CLI commands that resume their own
// session from the Keychain (whoami, backfill, calendar-backfill, sync,
// read on a cache miss). Proton refresh tokens are single-use: a CLI
// resume that refreshes rotates the token the running daemon holds,
// and the daemon's next refresh then fails as if the session had been
// revoked. --force overrides for the rare case the user knows better.
//
// login / logout / daemon / lock / unlock / install / policy / search
// never resume a session from the Keychain and are not guarded.
func refuseIfDaemonRunning(cmd string, force bool) error {
	if force || !daemonRunning() {
		return nil
	}
	return fmt.Errorf("protonmcpd is running; `protonmcp %s` would resume its own Proton session and "+
		"rotate the refresh token out from under the daemon (forcing a re-login). "+
		"Use the daemon instead — the Proton tools in Claude (mail_sync, mail_read, account_whoami, ...) — "+
		"or stop it first with `protonmcp daemon stop`. Pass --force to run anyway", cmd)
}
