package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// calendarMaxEditPrefix + a calendar ID is the sync_state key holding the
// max LastEditTime we've mirrored for that calendar. The global event
// stream carries no calendar delta (gpa.Event has only Messages/Labels/
// Addresses), so calendar sync is a dedicated poll keyed on this
// high-water mark rather than the shared event_cursor.
const calendarMaxEditPrefix = "calendar_max_edit:"

// CalendarRecheckInterval bounds how often a session whose token lacks
// calendar scope (Proton code 9100) re-probes the event endpoint. Between
// probes RunCalendarOnce makes no API calls at all.
const CalendarRecheckInterval = 6 * time.Hour

// CalendarRunResult summarizes a RunCalendarOnce / RunCalendarBackfill pass.
type CalendarRunResult struct {
	CalendarsUpserted int
	CalendarsDeleted  int
	CalendarsFailed   int // calendars whose events couldn't be fetched/applied this pass
	EventsUpserted    int
	EventsDeleted     int
	EventsDecrypted   int // populated only by RunCalendarBackfill(decrypt=true)
	// Unavailable is true when the session's token lacks calendar scope
	// (Proton code 9100). The pass is then a quiet no-op and returns a nil
	// error: the condition is logged once (on transition) and surfaced to
	// callers by the calendar tools instead.
	Unavailable bool
	Elapsed     time.Duration
}

// nowFunc is swapped in tests.
var nowFunc = time.Now

// RunCalendarOnce polls every calendar and reconciles the local mirror.
// It writes envelope (plaintext metadata) only — decryption is deferred
// to first read (or `protonmcp calendar-backfill --decrypt`) to keep the
// per-tick cost off the PGP path. Change detection is per-calendar
// max(LastEditTime); deletions are handled by a full-set reconcile
// against the live event IDs (the calendar API has no delete cursor).
//
// A failure on one calendar is logged and skipped — it does not abort the
// pass; the per-calendar errors are joined into the returned error after
// every calendar has been attempted. A token-scope rejection (code 9100)
// instead marks calendar unavailable for the session (see
// CalendarRunResult.Unavailable) and stops polling until
// CalendarRecheckInterval has elapsed.
func RunCalendarOnce(ctx context.Context, sess *protonclient.Session, st *store.Store) (*CalendarRunResult, error) {
	start := nowFunc()
	res := &CalendarRunResult{}

	if sess == nil || sess.Client == nil {
		return res, errors.New("calendar sync: session is closed")
	}

	if !sess.CalendarRecheckDue(start, CalendarRecheckInterval) {
		res.Unavailable = true
		return res, nil
	}
	wasUnavailable := sess.CalendarUnavailable()

	cals, err := sess.Client.GetCalendars(ctx)
	if err != nil {
		if protonclient.IsCalendarScopeError(err) {
			markCalendarUnavailable(sess, res, start, err)
			return res, nil
		}
		return res, fmt.Errorf("get calendars: %w", err)
	}

	var calErrs []error
	liveCalIDs := make([]string, 0, len(cals))
	for _, c := range cals {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		liveCalIDs = append(liveCalIDs, c.ID)

		if err := st.UpsertCalendar(ctx, toStoreCalendar(c)); err != nil {
			return res, fmt.Errorf("upsert calendar %s: %w", c.ID, err)
		}
		res.CalendarsUpserted++

		events, err := sess.Client.GetAllCalendarEvents(ctx, c.ID, nil)
		if err != nil {
			if protonclient.IsCalendarScopeError(err) {
				// Token-wide condition: every other calendar would fail
				// identically, so stop here rather than hammer the API.
				markCalendarUnavailable(sess, res, start, err)
				return res, nil
			}
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			res.CalendarsFailed++
			slog.Warn("calendar sync: skipping calendar", "err", protonclient.RedactLogText(err.Error()))
			calErrs = append(calErrs, scrubbedErr(fmt.Errorf("get events for calendar %s: %w", c.ID, err)))
			continue
		}

		storedMax := readMaxEdit(ctx, st, c.ID)
		newMax, upserted, deleted, err := applyCalendarEvents(ctx, st, c.ID, events, storedMax)
		res.EventsUpserted += upserted
		res.EventsDeleted += deleted
		if err != nil {
			res.CalendarsFailed++
			slog.Warn("calendar sync: apply failed", "err", protonclient.RedactLogText(err.Error()))
			calErrs = append(calErrs, scrubbedErr(fmt.Errorf("apply events for calendar %s: %w", c.ID, err)))
			continue
		}

		if newMax > storedMax {
			if err := st.SetSyncState(ctx, calendarMaxEditPrefix+c.ID, strconv.FormatInt(newMax, 10)); err != nil {
				calErrs = append(calErrs, scrubbedErr(fmt.Errorf("save calendar high-water for %s: %w", c.ID, err)))
			}
		}
	}

	if wasUnavailable && sess.MarkCalendarAvailable(start) {
		slog.Info("calendar sync: Proton Calendar is accessible again; resuming event polling")
	} else if !wasUnavailable {
		// Record the successful probe time.
		sess.MarkCalendarAvailable(start)
	}

	// Reconcile calendars that disappeared server-side (their events
	// cascade-delete via the FK).
	deletedCals, err := reconcileCalendars(ctx, st, liveCalIDs)
	if err != nil {
		return res, err
	}
	res.CalendarsDeleted = deletedCals

	res.Elapsed = time.Since(start)
	if res.EventsUpserted > 0 || res.EventsDeleted > 0 || res.CalendarsDeleted > 0 || res.CalendarsFailed > 0 {
		slog.Info("calendar sync",
			"calendars", res.CalendarsUpserted,
			"calendars_failed", res.CalendarsFailed,
			"events_upserted", res.EventsUpserted,
			"events_deleted", res.EventsDeleted,
			"elapsed_ms", res.Elapsed.Milliseconds())
	}
	return res, errors.Join(calErrs...)
}

// scrubbedError keeps the wrapped chain (errors.Is/As still work) but
// renders without opaque calendar IDs / API URLs, since callers log
// Error() verbatim.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

func scrubbedErr(err error) error {
	return &scrubbedError{msg: protonclient.RedactLogText(err.Error()), err: err}
}

// markCalendarUnavailable flags the session and logs exactly once per
// available→unavailable transition (not on every 2-minute tick, and not
// on a failed 6-hourly re-check).
func markCalendarUnavailable(sess *protonclient.Session, res *CalendarRunResult, now time.Time, cause error) {
	res.Unavailable = true
	if sess.MarkCalendarUnavailable(now) {
		slog.Warn("calendar sync: Proton Calendar is not accessible with this login's token scope "+
			"(Proton code 9100); calendar tools disabled, re-checking every "+CalendarRecheckInterval.String(),
			"err", protonclient.RedactLogText(cause.Error()))
	} else {
		slog.Debug("calendar sync: re-check still lacks calendar scope", "err", protonclient.RedactLogText(cause.Error()))
	}
}

// RunCalendarBackfill seeds the mirror from scratch: it runs the normal
// envelope sync, then (if decrypt) eagerly decrypts every event and fills
// the decrypted columns so calendar_events FTS works immediately without
// waiting for lazy per-read warming. Decrypt failures warn and continue —
// one unreadable event must not abort the backfill. The CLI
// `protonmcp calendar-backfill` drives this.
func RunCalendarBackfill(ctx context.Context, sess *protonclient.Session, st *store.Store, decrypt bool) (*CalendarRunResult, error) {
	start := time.Now()
	res, err := RunCalendarOnce(ctx, sess, st)
	if res != nil && res.Unavailable {
		return res, protonclient.ErrCalendarUnavailable
	}
	if err != nil {
		return res, err
	}
	if !decrypt {
		return res, nil
	}

	cals, err := sess.Client.GetCalendars(ctx)
	if err != nil {
		return res, fmt.Errorf("get calendars: %w", err)
	}
	for _, c := range cals {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		events, err := sess.Client.GetAllCalendarEvents(ctx, c.ID, nil)
		if err != nil {
			if protonclient.IsCalendarScopeError(err) {
				sess.MarkCalendarUnavailable(time.Now())
				return res, fmt.Errorf("%w: %w", protonclient.ErrCalendarUnavailable, err)
			}
			slog.Warn("calendar backfill: skipping calendar", "err", protonclient.RedactLogText(err.Error()))
			continue
		}
		cache := protonclient.NewCalendarKeyCache()
		for _, ev := range events {
			detail, derr := sess.DecryptCalendarEvent(ctx, ev, cache)
			if derr != nil {
				slog.Warn("calendar backfill: decrypt failed", "event", ev.ID, "err", derr.Error())
				continue
			}
			if ferr := st.FillCalendarEventDecrypted(ctx, ev.ID, toStoreDecrypted(detail)); ferr != nil {
				slog.Warn("calendar backfill: fill failed", "event", ev.ID, "err", ferr.Error())
				continue
			}
			res.EventsDecrypted++
		}
		cache.Clear()
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// toStoreDecrypted maps a decrypted event detail to the store's decrypted
// column set (attendees flattened to JSON).
func toStoreDecrypted(d *protonclient.CalendarEventDetail) store.CalendarEventDecrypted {
	out := store.CalendarEventDecrypted{
		Summary:     d.Summary,
		Location:    d.Location,
		Description: d.Description,
		Organizer:   d.Organizer,
		Status:      d.Status,
		RRULE:       d.RRULE,
		IsRecurring: d.IsRecurring,
		RawICal:     d.RawICal,
	}
	if len(d.Attendees) > 0 {
		if b, err := json.Marshal(d.Attendees); err == nil {
			out.AttendeesJSON = string(b)
		}
	}
	return out
}

// applyCalendarEvents upserts events whose LastEditTime exceeds storedMax,
// reconciles deletions against the live set, and returns the new
// high-water mark plus counts. It is pure with respect to the network
// (takes already-fetched events) so it can be tested against an in-memory
// store, mirroring how applyEvent is tested.
func applyCalendarEvents(ctx context.Context, st *store.Store, calID string, events []gpa.CalendarEvent, storedMax int64) (newMax int64, upserted, deleted int, err error) {
	newMax = storedMax
	liveIDs := make([]string, 0, len(events))
	for _, ev := range events {
		liveIDs = append(liveIDs, ev.ID)
		if ev.LastEditTime > newMax {
			newMax = ev.LastEditTime
		}
		// Skip events we've already mirrored at this edit time.
		if ev.LastEditTime <= storedMax {
			continue
		}
		if err := st.UpsertCalendarEventEnvelope(ctx, toEnvelope(ev)); err != nil {
			return newMax, upserted, deleted, fmt.Errorf("upsert event %s: %w", ev.ID, err)
		}
		upserted++
	}

	n, err := st.ReconcileCalendarEvents(ctx, calID, liveIDs)
	if err != nil {
		return newMax, upserted, deleted, err
	}
	deleted = int(n)
	return newMax, upserted, deleted, nil
}

// reconcileCalendars deletes local calendars no longer present server-side.
func reconcileCalendars(ctx context.Context, st *store.Store, liveIDs []string) (int, error) {
	local, err := st.ListCalendars(ctx)
	if err != nil {
		return 0, fmt.Errorf("list calendars for reconcile: %w", err)
	}
	live := make(map[string]struct{}, len(liveIDs))
	for _, id := range liveIDs {
		live[id] = struct{}{}
	}
	deleted := 0
	for _, c := range local {
		if _, ok := live[c.ID]; ok {
			continue
		}
		if err := st.DeleteCalendar(ctx, c.ID); err != nil {
			return deleted, fmt.Errorf("delete vanished calendar %s: %w", c.ID, err)
		}
		deleted++
	}
	return deleted, nil
}

func readMaxEdit(ctx context.Context, st *store.Store, calID string) int64 {
	v, err := st.GetSyncState(ctx, calendarMaxEditPrefix+calID)
	if err != nil {
		return 0 // ErrNotFound (first run) or transient — treat as cold
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func toStoreCalendar(c gpa.Calendar) store.Calendar {
	return store.Calendar{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Color:       c.Color,
		Type:        int(c.Type),
		Active:      c.Flags&gpa.CalendarFlagActive != 0,
	}
}

func toEnvelope(ev gpa.CalendarEvent) store.CalendarEventEnvelope {
	return store.CalendarEventEnvelope{
		ID:          ev.ID,
		CalendarID:  ev.CalendarID,
		UID:         ev.UID,
		StartUnix:   ev.StartTime,
		StartTZ:     ev.StartTimezone,
		EndUnix:     ev.EndTime,
		EndTZ:       ev.EndTimezone,
		AllDay:      bool(ev.FullDay),
		Author:      ev.Author,
		CreatedUnix: ev.CreateTime,
		LastEdit:    ev.LastEditTime,
	}
}
