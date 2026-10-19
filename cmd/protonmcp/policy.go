package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// runPolicy is the `protonmcp policy {reload|show|validate}`
// subcommand entry point.
func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: protonmcp policy {reload|show|validate <path>}")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "reload":
		return runPolicyReload(ctx, rest)
	case "show":
		return runPolicyShow(ctx, rest)
	case "validate":
		return runPolicyValidate(ctx, rest)
	default:
		return fmt.Errorf("unknown policy subcommand: %s", sub)
	}
}

// runPolicyReload finds every live `protonmcp serve-stdio` process
// via pgrep and sends each one SIGHUP. The daemon's HUP handler calls
// policy.Engine.Reload(). Multiple processes (Claude Desktop + Claude
// Code running concurrently) all reload their independently-loaded
// policy snapshots.
//
// SECURITY D9: the previous PID-file-based approach was
// unauthenticated — any local process could write a PID file with
// its own PID and steal the SIGHUP. pgrep filters by process
// command line, so the signal goes to actual serve-stdio instances.
func runPolicyReload(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("policy reload takes no arguments; got %v", args)
	}
	pids, err := policy.FindRunningPIDs()
	if err != nil {
		if errors.Is(err, policy.ErrNotRunning) {
			return errors.New("no protonmcp serve-stdio appears to be running")
		}
		return err
	}
	for _, pid := range pids {
		p, err := os.FindProcess(pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: find pid %d: %v\n", pid, err)
			continue
		}
		if err := p.Signal(syscall.SIGHUP); err != nil {
			fmt.Fprintf(os.Stderr, "warning: signal pid %d: %v\n", pid, err)
			continue
		}
		fmt.Printf("sent SIGHUP to protonmcp serve-stdio pid %d\n", pid)
	}
	fmt.Printf("reload signal sent to %d instance(s) — check each daemon's logs for the outcome\n", len(pids))
	return nil
}

// runPolicyShow prints the currently-effective policy. Loads it the
// same way serve-stdio does (default + user override) so users see
// exactly what's in force.
func runPolicyShow(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("policy show takes no arguments; got %v", args)
	}
	overridePath, err := policy.DefaultOverridePath()
	if err != nil {
		return err
	}
	approvedPath, err := policy.DefaultApprovalPath()
	if err != nil {
		return err
	}
	store := policy.ApprovalStore{Path: approvedPath, Key: keystore.PolicyHMACKey}
	return showPolicy(ctx, os.Stdout, overridePath, store)
}

// showPolicy renders the policy a daemon would run with (H6): every
// field, then the override's loosenings vs the built-in defaults and
// whether they carry a valid Touch ID approval. It never prompts: an
// unapproved weakening is shown as pending and the effective policy as
// the built-in defaults (what a starting daemon falls back to if the
// prompt is declined).
func showPolicy(ctx context.Context, w io.Writer, overridePath string, store policy.ApprovalStore) error {
	ws, hash, aerr := policy.AnalyzeOverride(overridePath)
	approved := hash != "" && store.Approved(hash)
	gate := func(context.Context, []string, string) error {
		if approved {
			return nil
		}
		return policy.ErrWeakeningNotApproved
	}
	e, err := policy.NewWithGate(ctx, overridePath, slog.New(slog.NewTextHandler(io.Discard, nil)), gate)
	if err != nil {
		return err
	}
	out, err := e.SnapshotYAML()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "# effective policy (built-in defaults + %s)\n", overridePath)
	_, _ = w.Write(out)

	fmt.Fprintln(w)
	switch {
	case aerr != nil:
		fmt.Fprintf(w, "# override REJECTED (built-in defaults in force): %v\n", aerr)
	case len(ws) == 0:
		fmt.Fprintln(w, "# weakenings vs built-in defaults: none")
	default:
		status := "approved with Touch ID"
		if !approved {
			status = "NOT approved — not in force until approved with Touch ID at the Mac (`protonmcp policy reload`)"
		}
		fmt.Fprintf(w, "# weakenings vs built-in defaults (%s):\n", status)
		for _, x := range ws {
			fmt.Fprintf(w, "#   - %s\n", x)
		}
	}
	return nil
}

// runPolicyValidate parses a candidate YAML file the same way the
// engine would. Useful for "does my override file have a typo"
// before running `policy reload` against a daemon.
func runPolicyValidate(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: protonmcp policy validate <path>")
	}
	// Construct a candidate engine pointing at the user-supplied
	// path; Reload reads + parses without committing on error.
	e, err := policy.New(ctx, args[0], nil)
	if err != nil {
		return err
	}
	if err := e.Reload(); err != nil {
		return fmt.Errorf("policy %s is invalid: %w", args[0], err)
	}
	fmt.Printf("policy %s parses cleanly\n", args[0])
	if ws, _, err := policy.AnalyzeOverride(args[0]); err == nil && len(ws) > 0 {
		fmt.Println("it loosens the built-in defaults; the daemon will ask for Touch ID before applying it:")
		for _, w := range ws {
			fmt.Println("  -", w)
		}
	}
	return nil
}
