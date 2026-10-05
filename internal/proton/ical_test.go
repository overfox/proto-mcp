package proton

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func icalDoc(lines ...string) string {
	return strings.Join(append(append([]string{
		"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//proto-mcp//test//EN",
	}, lines...), "END:VCALENDAR"), "\r\n") + "\r\n"
}

func mustUTC(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func starts(occ []Occurrence, loc *time.Location) []string {
	out := make([]string, 0, len(occ))
	for _, o := range occ {
		out = append(out, time.Unix(o.StartUnix, 0).In(loc).Format("2006-01-02T15:04"))
	}
	return out
}

// Proton splits one event across a signed-only clear part (UID, DTSTART,
// RRULE …) and an encrypted part (SUMMARY …). Both must be merged.
func TestParseICalEvent_MergesParts(t *testing.T) {
	clear := icalDoc(
		"BEGIN:VEVENT", "UID:u-1", "DTSTAMP:20260101T000000Z",
		"DTSTART;TZID=Europe/Zurich:20260302T090000", "DTEND;TZID=Europe/Zurich:20260302T093000",
		"RRULE:FREQ=WEEKLY;BYDAY=MO", "END:VEVENT")
	enc := icalDoc(
		"BEGIN:VEVENT", "UID:u-1", "DTSTAMP:20260101T000000Z",
		"SUMMARY:Weekly sync", "LOCATION:Room 1", "END:VEVENT")
	att := icalDoc(
		"BEGIN:VEVENT", "UID:u-1",
		"ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.com", "END:VEVENT")

	f, err := parseICalEvent(joinICalParts([]string{clear, enc, att}))
	if err != nil {
		t.Fatal(err)
	}
	if f.UID != "u-1" || f.Summary != "Weekly sync" || f.Location != "Room 1" {
		t.Errorf("merged fields = %+v", f)
	}
	if !f.IsRecurring || f.RRULE != "FREQ=WEEKLY;BYDAY=MO" {
		t.Errorf("recurrence = (%v, %q)", f.IsRecurring, f.RRULE)
	}
	if len(f.Attendees) != 1 || f.Attendees[0].Email != "bob@example.com" {
		t.Errorf("attendees = %+v", f.Attendees)
	}
	if f.RecurrenceID != 0 {
		t.Errorf("master RecurrenceID = %d, want 0", f.RecurrenceID)
	}
}

// Weekly series in Europe/Zurich crossing the March DST change, with an
// EXDATE and an in-payload RECURRENCE-ID override that moves one
// occurrence and renames it.
var weeklyZurich = icalDoc(
	"BEGIN:VEVENT", "UID:series-1", "DTSTAMP:20260101T000000Z",
	"DTSTART;TZID=Europe/Zurich:20260302T090000",
	"DTEND;TZID=Europe/Zurich:20260302T093000",
	"RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=8",
	"EXDATE;TZID=Europe/Zurich:20260316T090000",
	"SUMMARY:Standup", "END:VEVENT",
	"BEGIN:VEVENT", "UID:series-1", "DTSTAMP:20260101T000000Z",
	"RECURRENCE-ID;TZID=Europe/Zurich:20260323T090000",
	"DTSTART;TZID=Europe/Zurich:20260324T140000",
	"DTEND;TZID=Europe/Zurich:20260324T150000",
	"SUMMARY:Standup (moved)", "END:VEVENT",
)

func TestExpandOccurrences_WeeklyExdateOverrideDST(t *testing.T) {
	zrh, _ := time.LoadLocation("Europe/Zurich")
	in := ExpansionInput{RawICal: weeklyZurich, StartTZ: "Europe/Zurich"}
	occ, err := ExpandOccurrences(in, mustUTC(t, "2026-03-01T00:00:00Z"), mustUTC(t, "2026-04-30T00:00:00Z"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := starts(occ, zrh)
	want := []string{
		"2026-03-02T09:00", "2026-03-09T09:00",
		// 03-16 EXDATE'd
		"2026-03-24T14:00", // 03-23 slot moved by the override
		"2026-03-30T09:00", // after DST (UTC+2): still 09:00 wall clock
		"2026-04-06T09:00", "2026-04-13T09:00", "2026-04-20T09:00",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("occurrences\n got %v\nwant %v", got, want)
	}
	for _, o := range occ {
		if o.EndUnix <= o.StartUnix {
			t.Errorf("occurrence %d has end %d <= start", o.StartUnix, o.EndUnix)
		}
	}
	moved := occ[2]
	if !moved.Override || moved.Summary != "Standup (moved)" {
		t.Errorf("override occurrence = %+v", moved)
	}
	if moved.RecurrenceID != time.Date(2026, 3, 23, 9, 0, 0, 0, zrh).Unix() {
		t.Errorf("override RecurrenceID = %d", moved.RecurrenceID)
	}
	if moved.EndUnix-moved.StartUnix != 3600 {
		t.Errorf("override duration = %ds, want 3600", moved.EndUnix-moved.StartUnix)
	}
	if occ[0].EndUnix-occ[0].StartUnix != 1800 {
		t.Errorf("master duration = %ds, want 1800", occ[0].EndUnix-occ[0].StartUnix)
	}
}

func TestExpandOccurrences_WindowAndExclude(t *testing.T) {
	zrh, _ := time.LoadLocation("Europe/Zurich")
	excl := time.Date(2026, 4, 6, 9, 0, 0, 0, zrh).Unix()
	in := ExpansionInput{RawICal: weeklyZurich, StartTZ: "Europe/Zurich",
		ExcludeRecurrenceIDs: map[int64]bool{excl: true}}
	// [Mar 30, Apr 14): Mar 30, (Apr 6 excluded), Apr 13.
	occ, err := ExpandOccurrences(in, mustUTC(t, "2026-03-30T00:00:00Z"), mustUTC(t, "2026-04-14T00:00:00Z"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(starts(occ, zrh), ",")
	if got != "2026-03-30T09:00,2026-04-13T09:00" {
		t.Fatalf("got %s", got)
	}
}

// A UTC DTSTART must still repeat on the event's wall clock across DST.
func TestExpandOccurrences_UTCStartUsesEventTZ(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	raw := icalDoc("BEGIN:VEVENT", "UID:u", "DTSTAMP:20260101T000000Z",
		"DTSTART:20260302T140000Z", "DTEND:20260302T150000Z", // 09:00 EST
		"RRULE:FREQ=WEEKLY;COUNT=3", "END:VEVENT")
	occ, err := ExpandOccurrences(ExpansionInput{RawICal: raw, StartTZ: "America/New_York"},
		mustUTC(t, "2026-03-01T00:00:00Z"), mustUTC(t, "2026-04-01T00:00:00Z"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(starts(occ, ny), ",")
	if got != "2026-03-02T09:00,2026-03-09T09:00,2026-03-16T09:00" {
		t.Fatalf("got %s", got)
	}
}

func TestExpandOccurrences_AllDayDailyWithMultiExdate(t *testing.T) {
	raw := icalDoc("BEGIN:VEVENT", "UID:d", "DTSTAMP:20260101T000000Z",
		"DTSTART;VALUE=DATE:20260601", "DTEND;VALUE=DATE:20260602",
		"RRULE:FREQ=DAILY;UNTIL=20260607",
		"EXDATE;VALUE=DATE:20260603,20260605", "END:VEVENT")
	occ, err := ExpandOccurrences(ExpansionInput{RawICal: raw, StartTZ: "Europe/Zurich", AllDay: true},
		mustUTC(t, "2026-06-01T00:00:00Z"), mustUTC(t, "2026-07-01T00:00:00Z"), 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(starts(occ, time.UTC), ",")
	want := "2026-06-01T00:00,2026-06-02T00:00,2026-06-04T00:00,2026-06-06T00:00,2026-06-07T00:00"
	if got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	if occ[0].EndUnix-occ[0].StartUnix != 86400 {
		t.Errorf("all-day duration = %d", occ[0].EndUnix-occ[0].StartUnix)
	}
}

func TestExpandOccurrences_CancelledOverrideAndCap(t *testing.T) {
	raw := icalDoc("BEGIN:VEVENT", "UID:c", "DTSTAMP:20260101T000000Z",
		"DTSTART:20260101T100000Z", "DTEND:20260101T110000Z",
		"RRULE:FREQ=DAILY", "END:VEVENT",
		"BEGIN:VEVENT", "UID:c", "DTSTAMP:20260101T000000Z",
		"RECURRENCE-ID:20260102T100000Z", "DTSTART:20260102T100000Z",
		"STATUS:CANCELLED", "END:VEVENT")
	occ, err := ExpandOccurrences(ExpansionInput{RawICal: raw},
		mustUTC(t, "2026-01-01T00:00:00Z"), mustUTC(t, "2027-01-01T00:00:00Z"), 3)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(starts(occ, time.UTC), ",")
	if got != "2026-01-01T10:00,2026-01-03T10:00,2026-01-04T10:00" {
		t.Fatalf("got %s", got)
	}
}

func TestExpandOccurrences_NotRecurring(t *testing.T) {
	_, err := ExpandOccurrences(ExpansionInput{RawICal: icalDoc(
		"BEGIN:VEVENT", "UID:x", "DTSTART:20260101T100000Z", "END:VEVENT")},
		time.Unix(0, 0), time.Now(), 0)
	if !errors.Is(err, ErrNotRecurring) {
		t.Fatalf("err = %v, want ErrNotRecurring", err)
	}
}

func TestICalRecurrenceID(t *testing.T) {
	zrh, _ := time.LoadLocation("Europe/Zurich")
	override := icalDoc("BEGIN:VEVENT", "UID:series-1",
		"RECURRENCE-ID;TZID=Europe/Zurich:20260323T090000",
		"DTSTART;TZID=Europe/Zurich:20260324T140000", "END:VEVENT")
	if got, want := ICalRecurrenceID(override, "Europe/Zurich"), time.Date(2026, 3, 23, 9, 0, 0, 0, zrh).Unix(); got != want {
		t.Errorf("ICalRecurrenceID = %d, want %d", got, want)
	}
	if got := ICalRecurrenceID(weeklyZurich, "Europe/Zurich"); got != 0 {
		t.Errorf("master payload RecurrenceID = %d, want 0", got)
	}
	f, err := parseICalEvent(override)
	if err != nil {
		t.Fatal(err)
	}
	if f.RecurrenceID == 0 || f.IsRecurring {
		t.Errorf("standalone override fields = %+v", f)
	}
}

// Proton's SharedEvents is [signed-only clear part, encrypted part]. The
// old decryptSharedPart returned the first (clear) part and never
// decrypted SUMMARY/LOCATION; both must now come back and merge.
func TestDecryptSharedPart_ClearPlusEncrypted(t *testing.T) {
	calKR := newTestKeyRing(t, "calendar@proton.me")
	clear := icalDoc("BEGIN:VEVENT", "UID:u-2", "DTSTAMP:20260101T000000Z",
		"DTSTART:20260101T100000Z", "RRULE:FREQ=DAILY;COUNT=2", "END:VEVENT")
	enc := icalDoc("BEGIN:VEVENT", "UID:u-2", "DTSTAMP:20260101T000000Z", "SUMMARY:Secret title", "END:VEVENT")

	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPacket, err := calKR.EncryptSessionKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	data, err := sk.Encrypt(crypto.NewPlainMessageFromString(enc))
	if err != nil {
		t.Fatal(err)
	}
	parts := []gpa.CalendarEventPart{
		{Type: gpa.CalendarEventTypeSigned, Data: clear},
		{Type: gpa.CalendarEventTypeEncrypted | gpa.CalendarEventTypeSigned, Data: base64.StdEncoding.EncodeToString(data)},
	}
	raw, err := decryptSharedPart(calKR, base64.StdEncoding.EncodeToString(keyPacket), parts)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseICalEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Summary != "Secret title" || !f.IsRecurring {
		t.Errorf("merged = %+v", f)
	}
}
