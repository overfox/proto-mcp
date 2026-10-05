package main

import (
	"strings"
	"testing"
)

func TestRefuseIfDaemonRunning(t *testing.T) {
	orig := daemonRunning
	defer func() { daemonRunning = orig }()

	daemonRunning = func() bool { return true }
	err := refuseIfDaemonRunning("sync", false)
	if err == nil || !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "protonmcp sync") {
		t.Fatalf("running daemon: err = %v, want a refusal mentioning the command and --force", err)
	}
	if err := refuseIfDaemonRunning("sync", true); err != nil {
		t.Fatalf("--force: err = %v, want nil", err)
	}
	daemonRunning = func() bool { return false }
	if err := refuseIfDaemonRunning("sync", false); err != nil {
		t.Fatalf("no daemon: err = %v, want nil", err)
	}
}

// Guarded commands refuse BEFORE touching the store or Keychain.
func TestGuardedCommandsRefuseWhenDaemonRunning(t *testing.T) {
	orig := daemonRunning
	defer func() { daemonRunning = orig }()
	daemonRunning = func() bool { return true }

	ctx := t.Context()
	db := t.TempDir() + "/never-created.db"
	cases := map[string]func() error{
		"whoami":            func() error { return runWhoami(ctx, nil) },
		"backfill":          func() error { return runBackfill(ctx, []string{"--db", db}) },
		"calendar-backfill": func() error { return runCalendarBackfill(ctx, []string{"--db", db}) },
		"sync":              func() error { return runSync(ctx, []string{"--db", db}) },
	}
	for name, run := range cases {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "protonmcpd is running") {
			t.Errorf("%s: err = %v, want daemon-running refusal", name, err)
		}
	}
}
