package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/cli"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// runBackfill drains the account's message metadata into the local
// SQLite mirror. It does not fetch or decrypt bodies — those are
// populated lazily on first read in Phase 2.
//
// The drain itself lives in internal/sync (syncpkg.Backfill) so the
// daemon can run the same code when the event stream demands a full
// refresh. This command adds the store open, session acquire, the
// large-mailbox confirmation, and progress output.
func runBackfill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backfill", flag.ContinueOnError)
	dbPath := fs.String("db", "", "SQLite store path (default: platform-standard data dir)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt for large mailboxes")
	limit := fs.Int("limit", 0, "stop after writing this many messages (0 = no limit; useful for spot-checks)")
	confirmThreshold := fs.Int("confirm-threshold", 5000, "prompt for confirmation when total message count exceeds this")
	force := fs.Bool("force", false, "run even though protonmcpd is running (rotates the daemon's refresh token)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := refuseIfDaemonRunning("backfill", *force); err != nil {
		return err
	}

	path := *dbPath
	if path == "" {
		p, err := store.DefaultPath()
		if err != nil {
			return err
		}
		path = p
	}
	fmt.Printf("Opening store at %s …\n", path)
	st, err := store.Open(path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	acquireCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	bundle, err := acquireSession(acquireCtx)
	if err != nil {
		return err
	}
	defer bundle.Close()
	defer bundle.Session.Close()

	res, err := syncpkg.Backfill(ctx, bundle.Session, st, syncpkg.BackfillOptions{
		Limit: *limit,
		Confirm: func(total int) (bool, error) {
			if total <= *confirmThreshold || *yes {
				return true, nil
			}
			ans, err := cli.PromptLine(ctx, fmt.Sprintf("Drain all %d into local store? [y/N]: ", total))
			if err != nil {
				return false, err
			}
			return strings.EqualFold(strings.TrimSpace(ans), "y"), nil
		},
		Logf: func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
		Warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
		},
	})
	if err != nil {
		if errors.Is(err, syncpkg.ErrBackfillAborted) {
			return errors.New("aborted")
		}
		return err
	}

	elapsed := res.Elapsed.Round(time.Millisecond)
	fmt.Printf("Backfill complete: %d messages in %s (avg %.0f msg/s).\n",
		res.Written, elapsed, float64(res.Written)/elapsed.Seconds())
	if res.LimitReached {
		fmt.Printf("Stopped early due to --limit %d.\n", *limit)
	}
	return nil
}
