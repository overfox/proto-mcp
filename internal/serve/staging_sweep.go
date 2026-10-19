package serve

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcptools"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
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
//
// The same ticker applies the attachment_cache retention (SECURITY M1:
// store.DefaultAttachmentRetention by age, then
// store.DefaultAttachmentCacheMaxBytes by size) once every
// attachmentCacheSweepInterval, to the store SweepStaleBodies
// registered at startup.
const (
	stagingRetention             = 24 * time.Hour
	stagingSweepInterval         = time.Hour
	attachmentCacheSweepInterval = 24 * time.Hour
)

// stagingSweepFn is swapped in tests.
var stagingSweepFn = mcptools.SweepStagingOlderThan

// attachmentCacheSweeper is the store whose attachment cache the
// ticker keeps within retention, and when it was last swept.
// SweepStaleBodies (the startup hook) registers it; the ticker
// goroutine starts after that hook in Setup.
var attachmentCacheSweeper struct {
	mu   sync.Mutex
	st   *store.Store
	last time.Time
}

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
		sweepAttachmentCacheIfDue(ctx, logger, now())
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

// registerAttachmentCacheSweep makes st the store the ticker sweeps
// and runs the first sweep now.
func registerAttachmentCacheSweep(ctx context.Context, logger *slog.Logger, st *store.Store, now time.Time) {
	attachmentCacheSweeper.mu.Lock()
	attachmentCacheSweeper.st = st
	attachmentCacheSweeper.last = time.Time{}
	attachmentCacheSweeper.mu.Unlock()
	sweepAttachmentCacheIfDue(ctx, logger, now)
}

// sweepAttachmentCacheIfDue runs the attachment_cache retention sweep
// when a store is registered and attachmentCacheSweepInterval has
// passed since the last one.
func sweepAttachmentCacheIfDue(ctx context.Context, logger *slog.Logger, now time.Time) {
	attachmentCacheSweeper.mu.Lock()
	defer attachmentCacheSweeper.mu.Unlock()
	st := attachmentCacheSweeper.st
	if st == nil {
		return
	}
	if !attachmentCacheSweeper.last.IsZero() && now.Sub(attachmentCacheSweeper.last) < attachmentCacheSweepInterval {
		return
	}
	attachmentCacheSweeper.last = now
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	stats, err := st.SweepAttachmentCache(ctx, now, store.DefaultAttachmentRetention, store.DefaultAttachmentCacheMaxBytes)
	if err != nil {
		logger.Warn("attachment cache retention sweep incomplete",
			"expired", stats.Expired, "evicted", stats.Evicted, "err", err.Error())
		return
	}
	if stats.Expired+stats.Evicted > 0 {
		logger.Info("swept decrypted attachment cache",
			"expired", stats.Expired, "evicted", stats.Evicted,
			"retention", store.DefaultAttachmentRetention.String(),
			"max_bytes", store.DefaultAttachmentCacheMaxBytes)
	}
}
