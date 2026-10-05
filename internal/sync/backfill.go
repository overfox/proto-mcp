package sync

import (
	"context"
	"errors"
	"fmt"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// BackfillOptions tunes Backfill. The zero value drains everything
// with no confirmation and no progress output — what the daemon uses
// when the event stream demands a full refresh.
type BackfillOptions struct {
	// Limit stops after this many messages (0 = no limit).
	Limit int

	// Confirm, if set, is asked once the message count is known.
	// Returning false aborts with ErrBackfillAborted before anything
	// is written (apart from the label seed).
	Confirm func(total int) (bool, error)

	// Logf / Warnf receive human-readable progress and non-fatal
	// warnings. nil → silent.
	Logf  func(format string, args ...any)
	Warnf func(format string, args ...any)
}

// BackfillResult summarizes a Backfill run.
type BackfillResult struct {
	Cursor       string // event cursor captured BEFORE the drain
	Total        int    // server-side message count
	Written      int    // messages upserted
	Labels       int    // labels/folders seeded
	LimitReached bool
	Elapsed      time.Duration
}

// ErrBackfillAborted is returned when BackfillOptions.Confirm declines.
var ErrBackfillAborted = errors.New("aborted")

// errLimitReached stops ForEachMessageMetadataPage when Limit is hit.
// Internal — Backfill swallows it and sets LimitReached.
var errLimitReached = errors.New("limit reached")

// Backfill drains the account's message metadata into the local
// mirror and re-seeds the event cursor. It does not fetch or decrypt
// bodies — those are populated lazily on first read.
//
// Shared by `protonmcp backfill` and the daemon's self-healing path
// (the event stream answering with Refresh != 0 used to freeze the
// mirror until a human ran the CLI).
//
// Order of operations is deliberately conservative:
//
//  1. Capture the latest event ID BEFORE the drain, so the sync loop
//     replays anything that changes mid-drain. Storing the cursor
//     after the drain would silently drop those events.
//  2. Seed labels/folders (non-fatal on failure).
//  3. Count messages, ask Confirm if set.
//  4. Page through metadata newest-first, upsert each row + its label
//     set.
//  5. Persist the captured cursor under sync_state.event_cursor.
func Backfill(ctx context.Context, sess *protonclient.Session, st *store.Store, opts BackfillOptions) (*BackfillResult, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	warnf := opts.Warnf
	if warnf == nil {
		warnf = func(string, ...any) {}
	}
	if sess.Closed() {
		return nil, protonclient.ErrSessionClosed
	}
	res := &BackfillResult{}

	cursor, err := sess.LatestEventID(ctx)
	if err != nil {
		return res, fmt.Errorf("capture event cursor: %w", err)
	}
	res.Cursor = cursor
	logf("Captured event cursor: %s", cursor)

	// SECURITY D32 — seed the local labels/folders mirror. Before
	// this, the labels table only populated via the sync event loop,
	// so pre-existing labels never landed unless the user changed
	// one. labels_list / folders_list both returned null on a freshly
	// backfilled mirror.
	if n, err := BackfillLabels(ctx, sess, st); err != nil {
		// Non-fatal — messages backfill is the main thing.
		warnf("label backfill failed (continuing): %v", err)
	} else {
		res.Labels = n
		logf("Seeded %d label(s)/folder(s) into the local mirror.", n)
	}

	total, err := sess.CountMessages(ctx)
	if err != nil {
		return res, fmt.Errorf("count messages: %w", err)
	}
	res.Total = total
	logf("Account has %d messages.", total)
	if opts.Confirm != nil {
		ok, err := opts.Confirm(total)
		if err != nil {
			return res, err
		}
		if !ok {
			return res, ErrBackfillAborted
		}
	}

	start := time.Now()
	lastReport := time.Now()
	const reportEvery = 2 * time.Second

	// Pull newest-first so recent mail lands in the local mirror in
	// the first few pages. A user backfilling a multi-year mailbox can
	// start using MCP after ~30 seconds even if the long historical
	// tail keeps grinding. (Proton's default sort is by Time;
	// Desc=true reverses it.)
	walkErr := sess.ForEachMessageMetadataPage(ctx, gpa.MessageFilter{Desc: gpa.Bool(true)}, func(batch []gpa.MessageMetadata) error {
		for _, m := range batch {
			row, err := protonclient.ToStoreMessage(m)
			if err != nil {
				return fmt.Errorf("translate %s: %w", m.ID, err)
			}
			if err := st.UpsertMessage(ctx, row); err != nil {
				return err
			}
			if err := st.SetMessageLabels(ctx, m.ID, m.LabelIDs); err != nil {
				return fmt.Errorf("labels for %s: %w", m.ID, err)
			}
			res.Written++
			if opts.Limit > 0 && res.Written >= opts.Limit {
				return errLimitReached
			}
		}
		if time.Since(lastReport) > reportEvery {
			rate := float64(res.Written) / time.Since(start).Seconds()
			logf("  ... %d / %d  (%.0f msg/s)", res.Written, total, rate)
			lastReport = time.Now()
		}
		return nil
	})
	res.Elapsed = time.Since(start)
	if walkErr != nil && !errors.Is(walkErr, errLimitReached) {
		return res, fmt.Errorf("walk messages: %w", walkErr)
	}
	res.LimitReached = errors.Is(walkErr, errLimitReached)

	if err := st.SetSyncState(ctx, cursorKey, cursor); err != nil {
		return res, fmt.Errorf("persist cursor: %w", err)
	}
	return res, nil
}

// BackfillLabels fetches every user-defined label and folder from
// Proton and upserts each into the local mirror's `labels` table.
// SECURITY D32: previously the labels table only populated via the
// sync event loop, so a freshly-backfilled mirror returned null from
// labels_list and folders_list until the user changed a label.
//
// We fetch both LabelTypeLabel (user labels) and LabelTypeFolder
// (user folders) — the schema column distinguishes them.
func BackfillLabels(ctx context.Context, sess *protonclient.Session, st *store.Store) (int, error) {
	if sess.Closed() {
		return 0, protonclient.ErrSessionClosed
	}
	labels, err := sess.Client.GetLabels(ctx, gpa.LabelTypeLabel, gpa.LabelTypeFolder)
	if err != nil {
		return 0, fmt.Errorf("fetch labels: %w", err)
	}
	n := 0
	for _, l := range labels {
		if err := st.UpsertLabel(ctx, store.Label{
			ID:    l.ID,
			Name:  l.Name,
			Color: l.Color,
			Type:  int(l.Type),
		}); err != nil {
			return n, fmt.Errorf("upsert label %s: %w", l.ID, err)
		}
		n++
	}
	return n, nil
}
