package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func icalFixture(lines ...string) string {
	return strings.Join(append(append([]string{
		"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//proto-mcp//test//EN",
	}, lines...), "END:VCALENDAR"), "\r\n") + "\r\n"
}

// Weekly Monday 09:00 Zurich series that began in January; the
// 2026-03-16 occurrence is EXDATE'd and the 2026-03-23 one was moved to
// Tuesday 14:00 — stored by Proton as a separate event with RECURRENCE-ID.
var (
	seriesMaster = icalFixture("BEGIN:VEVENT", "UID:series-1", "DTSTAMP:20260101T000000Z",
		"DTSTART;TZID=Europe/Zurich:20260105T090000", "DTEND;TZID=Europe/Zurich:20260105T093000",
		"RRULE:FREQ=WEEKLY;BYDAY=MO", "EXDATE;TZID=Europe/Zurich:20260316T090000",
		"SUMMARY:Standup", "END:VEVENT")
	seriesOverride = icalFixture("BEGIN:VEVENT", "UID:series-1", "DTSTAMP:20260101T000000Z",
		"RECURRENCE-ID;TZID=Europe/Zurich:20260323T090000",
		"DTSTART;TZID=Europe/Zurich:20260324T140000", "DTEND;TZID=Europe/Zurich:20260324T150000",
		"SUMMARY:Standup (moved)", "END:VEVENT")
)

func seedSeries(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	zrh, _ := time.LoadLocation("Europe/Zurich")
	mustCal(t, st, "cal-1", "Work")
	put := func(id string, start, end time.Time, raw string, recurring bool, summary string) {
		if err := st.UpsertCalendarEventEnvelope(ctx, store.CalendarEventEnvelope{
			ID: id, CalendarID: "cal-1", UID: "series-1",
			StartUnix: start.Unix(), EndUnix: end.Unix(), StartTZ: "Europe/Zurich", EndTZ: "Europe/Zurich", LastEdit: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if err := st.FillCalendarEventDecrypted(ctx, id, store.CalendarEventDecrypted{
			Summary: summary, RawICal: raw, IsRecurring: recurring,
			RRULE: map[bool]string{true: "FREQ=WEEKLY;BYDAY=MO"}[recurring],
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("ev-master", time.Date(2026, 1, 5, 9, 0, 0, 0, zrh), time.Date(2026, 1, 5, 9, 30, 0, 0, zrh), seriesMaster, true, "Standup")
	put("ev-moved", time.Date(2026, 3, 24, 14, 0, 0, 0, zrh), time.Date(2026, 3, 24, 15, 0, 0, 0, zrh), seriesOverride, false, "Standup (moved)")
	// An ordinary one-off event in the window.
	mustEnvelope(t, st, "ev-oneoff", "cal-1", time.Date(2026, 3, 18, 12, 0, 0, 0, zrh).Unix())
}

func runCalendarEvents(t *testing.T, deps Deps, args map[string]any) calendarEventsResult {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := calendarEvents(deps).Handler(mcp.Context{Std: context.Background()}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	out, ok := res.StructuredContent.(calendarEventsResult)
	if !ok {
		t.Fatalf("result type = %T", res.StructuredContent)
	}
	return out
}

func TestCalendarEvents_ExpandsRecurringSeries(t *testing.T) {
	st := calStore(t)
	seedSeries(t, st)
	zrh, _ := time.LoadLocation("Europe/Zurich")

	out := runCalendarEvents(t, Deps{Store: st}, map[string]any{"from": "2026-03-09", "to": "2026-04-01"})

	var got []string
	for _, e := range out.Events {
		got = append(got, e.EventID+"@"+time.Unix(e.StartUnix, 0).In(zrh).Format("01-02T15:04"))
	}
	want := []string{
		"ev-master@03-09T09:00",
		// 03-16 EXDATE'd
		"ev-oneoff@03-18T12:00",
		"ev-moved@03-24T14:00",  // stored override replaces the 03-23 slot
		"ev-master@03-30T09:00", // DST switched on 03-29; still 09:00 local
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}

	occ := out.Events[0]
	if !occ.Occurrence || occ.MasterEventID != "ev-master" || occ.EndUnix-occ.StartUnix != 1800 || occ.RecurrenceIDUnix != occ.StartUnix {
		t.Errorf("occurrence = %+v", occ)
	}
	moved := out.Events[2]
	if moved.MasterEventID != "ev-master" || !moved.Occurrence ||
		moved.RecurrenceIDUnix != time.Date(2026, 3, 23, 9, 0, 0, 0, zrh).Unix() {
		t.Errorf("override row = %+v", moved)
	}
	if out.Events[1].Occurrence || out.Events[1].MasterEventID != "" {
		t.Errorf("one-off must not be annotated: %+v", out.Events[1])
	}
}

func TestCalendarEvents_ExpandedPagination(t *testing.T) {
	st := calStore(t)
	seedSeries(t, st)
	args := map[string]any{"from": "2026-03-09", "to": "2026-04-01", "limit": 3}
	first := runCalendarEvents(t, Deps{Store: st}, args)
	if len(first.Events) != 3 || first.NextCursor == "" {
		t.Fatalf("page 1 = %d events, cursor %q", len(first.Events), first.NextCursor)
	}
	args["cursor"] = first.NextCursor
	second := runCalendarEvents(t, Deps{Store: st}, args)
	if len(second.Events) != 1 || second.NextCursor != "" {
		t.Fatalf("page 2 = %d events, cursor %q", len(second.Events), second.NextCursor)
	}
}
