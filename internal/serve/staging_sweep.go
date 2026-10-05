package serve

import (
	"context"
	"log/slog"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
)

// Decrypted-attachment staging retention (PROTO-135 follow-up).
//
// mail_download_attachment writes plaintext for large attachments to
// ~/Library/Application Support/protonmcp/attachment-staging/. The
// startup sweep (SweepStaleBodies) only clears files past the 30-day
// body-cache retention, and only when the daemon restarts — so on a
// long-running daemon decrypted PDFs lingered for weeks. Staging files
// are a hand-off to the MCP client, not a cache: once the client has
// read the path they have no further use. This ticker removes them
// after stagingRetention, checking every stagingSweepInterval.
const (
	stagingRetention     = 24 * time.Hour
	stagingSweepInterval = time.Hour
)

// stagingSweepFn is swapped in tests.
var stagingSweepFn = mcptools.SweepStagingOlderThan

// runStagingSweep sweeps once immediately, then every
// stagingSweepInterval until ctx is cancelled. Started from Setup on the
// background-sync context, so Runtime.Close stops it.
func runStagingSweep(ctx context.Context, logger *slog.Logger) {
	runStagingSweepEvery(ctx, logger, stagingSweepInterval, time.Now)
}

func runStagingSweepEvery(ctx context.Context, logger *slog.Logger, every time.Duration, now func() time.Time) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		sweepStagingOnce(logger, now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sweepStagingOnce(logger *slog.Logger, now time.Time) {
	n, err := stagingSweepFn(now.Add(-stagingRetention))
	if err != nil {
		logger.Warn("attachment staging sweep incomplete", "removed", n, "err", err.Error())
		return
	}
	if n > 0 {
		logger.Info("swept decrypted attachment staging files", "removed", n, "retention", stagingRetention.String())
	}
}
