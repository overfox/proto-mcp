package proton

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

// This file is the ONLY place go-ical / rrule-go are used. Calendar event
// payloads decrypt to iCalendar (RFC 5545) VEVENT text; everything
// downstream works with the structured icalFields / Occurrence values
// below, so the dependencies stay swappable and the RFC-5545 quirks (line
// folding, escaping, parameter quoting, RRULE expansion) are handled in
// well-tested libraries rather than by hand.
//
// A decrypted Proton event is usually SEVERAL VCALENDAR documents back to
// back — one per event part (signed-only clear part with UID/DTSTART/
// RRULE/EXDATE, encrypted part with SUMMARY/DESCRIPTION, attendee part,
// calendar part). decodeVEvents reads every document in the stream and
// merges VEVENTs that describe the same instance (same RECURRENCE-ID, or
// none for the series master) into one component.

// icalAttendee is one ATTENDEE line, flattened.
type icalAttendee struct {
	Email  string // mailto: prefix stripped
	Name   string // CN param, if present
	Status string // PARTSTAT param (NEEDS-ACTION/ACCEPTED/DECLINED/TENTATIVE)
	Role   string // ROLE param (REQ-PARTICIPANT/OPT-PARTICIPANT/CHAIR)
}

// icalFields is the subset of VEVENT properties we surface. Event times
// for the envelope are deliberately NOT parsed here — proto-mcp takes
// start/end/timezone from the SDK's plaintext CalendarEvent metadata,
// which is authoritative. Recurrence expansion (ExpandOccurrences) is the
// one place DTSTART/RRULE are interpreted.
type icalFields struct {
	UID          string
	Summary      string
	Description  string
	Location     string
	Organizer    string
	Status       string
	RRULE        string
	IsRecurring  bool
	RecurrenceID int64 // unix; non-zero when this payload is a RECURRENCE-ID override
	Attendees    []icalAttendee
}

// multiValuedProps may legitimately repeat within one VEVENT; when
// merging parts their values are appended rather than first-wins.
var multiValuedProps = map[string]bool{
	ical.PropAttendee:        true,
	ical.PropExceptionDates:  true,
	ical.PropRecurrenceDates: true,
	ical.PropCategories:      true,
	ical.PropComment:         true,
	ical.PropContact:         true,
	ical.PropAttach:          true,
}

// decodeVEvents decodes every VCALENDAR in text and returns the merged
// VEVENTs: the series master (no RECURRENCE-ID) if present, and any
// RECURRENCE-ID overrides in first-seen order.
func decodeVEvents(text string) (master *ical.Component, overrides []*ical.Component, err error) {
	dec := ical.NewDecoder(strings.NewReader(text))
	merged := map[string]*ical.Component{}
	var order []string
	ncal := 0
	for {
		cal, derr := dec.Decode()
		if errors.Is(derr, io.EOF) {
			break
		}
		if derr != nil {
			if ncal > 0 {
				break // trailing garbage after a valid document — keep what we have
			}
			return nil, nil, fmt.Errorf("parse ical: %w", derr)
		}
		ncal++
		for _, ev := range cal.Events() {
			key := ""
			if p := ev.Props.Get(ical.PropRecurrenceID); p != nil {
				key = strings.TrimSpace(p.Value)
			}
			dst, ok := merged[key]
			if !ok {
				dst = ical.NewComponent(ical.CompEvent)
				merged[key] = dst
				order = append(order, key)
			}
			mergeProps(dst, ev.Component)
		}
	}
	if len(order) == 0 {
		return nil, nil, fmt.Errorf("ical payload has no VEVENT")
	}
	for _, k := range order {
		if k == "" {
			master = merged[k]
		} else {
			overrides = append(overrides, merged[k])
		}
	}
	return master, overrides, nil
}

// mergeProps copies src's properties into dst: single-valued properties
// are first-wins, multi-valued ones accumulate.
func mergeProps(dst, src *ical.Component) {
	for name, vals := range src.Props {
		if _, have := dst.Props[name]; have && !multiValuedProps[name] {
			continue
		}
		dst.Props[name] = append(dst.Props[name], vals...)
	}
	dst.Children = append(dst.Children, src.Children...)
}

// parseICalEvent decodes a decrypted VEVENT stream and extracts the text
// fields we expose from the series master (or, for a standalone
// RECURRENCE-ID override payload, from that override).
func parseICalEvent(text string) (icalFields, error) {
	var f icalFields

	master, overrides, err := decodeVEvents(text)
	if err != nil {
		return f, err
	}
	ev := master
	if ev == nil {
		ev = overrides[0]
		f.RecurrenceID = recurrenceIDUnix(ev, nil)
	}

	f.UID = propText(ev.Props, "UID")
	f.Summary = propText(ev.Props, "SUMMARY")
	f.Description = propText(ev.Props, "DESCRIPTION")
	f.Location = propText(ev.Props, "LOCATION")
	f.Status = propText(ev.Props, "STATUS")

	if p := ev.Props.Get("ORGANIZER"); p != nil {
		f.Organizer = stripMailto(p.Value)
		if cn := paramFirst(p, "CN"); cn != "" && f.Organizer == "" {
			f.Organizer = cn
		}
	}

	if p := ev.Props.Get("RRULE"); p != nil && strings.TrimSpace(p.Value) != "" {
		f.RRULE = strings.TrimSpace(p.Value)
		f.IsRecurring = true
	}
	if len(ev.Props.Values(ical.PropRecurrenceDates)) > 0 {
		f.IsRecurring = true
	}

	for _, p := range ev.Props.Values("ATTENDEE") {
		email := stripMailto(p.Value)
		if email == "" {
			continue
		}
		f.Attendees = append(f.Attendees, icalAttendee{
			Email:  email,
			Name:   paramFirst(&p, "CN"),
			Status: paramFirst(&p, "PARTSTAT"),
			Role:   paramFirst(&p, "ROLE"),
		})
	}

	return f, nil
}

// ICalRecurrenceID returns the RECURRENCE-ID (unix seconds) of a stored
// decrypted payload that is a standalone override of a recurring series
// (Proton stores a modified single occurrence as its own event sharing
// the series UID), or 0 if the payload has a series master / none.
func ICalRecurrenceID(raw string, tz string) int64 {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	master, overrides, err := decodeVEvents(raw)
	if err != nil || master != nil || len(overrides) == 0 {
		return 0
	}
	return recurrenceIDUnix(overrides[0], loadLocation(tz))
}

// Occurrence is one expanded instance of a recurring series.
type Occurrence struct {
	StartUnix    int64
	EndUnix      int64
	RecurrenceID int64 // original (unmodified) slot start; equals StartUnix unless Override
	Override     bool  // true when an in-payload RECURRENCE-ID VEVENT replaced the slot

	// Populated only for overrides; empty means "inherit from master".
	Summary  string
	Location string
	Status   string
}

// ExpansionInput describes one recurring master for ExpandOccurrences.
type ExpansionInput struct {
	RawICal   string
	StartTZ   string // envelope timezone; used for floating times and DST-correct wall-clock repetition
	AllDay    bool
	StartUnix int64 // envelope start/end — fallback when DTSTART/DTEND are unusable
	EndUnix   int64

	// ExcludeRecurrenceIDs are slots overridden by separately stored
	// events (same UID, own RECURRENCE-ID). They are dropped from the
	// expansion; the override events are listed on their own.
	ExcludeRecurrenceIDs map[int64]bool
}

// ErrNotRecurring is returned by ExpandOccurrences for a payload with no
// RRULE/RDATE on its series master.
var ErrNotRecurring = errors.New("ical: event is not recurring")

// ExpandOccurrences expands a recurring master's RRULE/RDATE (minus
// EXDATEs, minus excluded slots, with in-payload RECURRENCE-ID overrides
// applied) into concrete occurrences whose start lies in [from, to).
// Results are sorted by start and capped at max (max<=0 → 1000).
func ExpandOccurrences(in ExpansionInput, from, to time.Time, max int) ([]Occurrence, error) {
	if max <= 0 {
		max = 1000
	}
	master, overrides, err := decodeVEvents(in.RawICal)
	if err != nil {
		return nil, err
	}
	if master == nil {
		return nil, ErrNotRecurring
	}
	rr := master.Props.Get(ical.PropRecurrenceRule)
	rdates := master.Props.Values(ical.PropRecurrenceDates)
	if (rr == nil || strings.TrimSpace(rr.Value) == "") && len(rdates) == 0 {
		return nil, ErrNotRecurring
	}

	tzLoc := loadLocation(in.StartTZ)
	allDay := in.AllDay
	if p := master.Props.Get(ical.PropDateTimeStart); p != nil && isDateValue(p) {
		allDay = true
	}
	// All-day dates are anchored at UTC midnight — the same convention
	// as Proton's plaintext StartTime for full-day events.
	loc := tzLoc
	if allDay {
		loc = time.UTC
	}

	dtstart, err := propTime(master.Props.Get(ical.PropDateTimeStart), loc)
	if err != nil || dtstart.IsZero() {
		dtstart = time.Unix(in.StartUnix, 0).In(loc)
	}
	// Repeat in the event's wall clock (DST-correct): a UTC DTSTART on a
	// timed event is re-expressed in the envelope timezone first.
	if !allDay {
		dtstart = dtstart.In(tzLoc)
	}

	dur := time.Duration(in.EndUnix-in.StartUnix) * time.Second
	if end, eerr := (&ical.Event{Component: master}).DateTimeEnd(loc); eerr == nil && !end.IsZero() && end.After(dtstart) {
		dur = end.Sub(dtstart)
	}
	if dur < 0 {
		dur = 0
	}

	set := &rrule.Set{}
	if rr != nil && strings.TrimSpace(rr.Value) != "" {
		opt, err := rrule.StrToROptionInLocation(strings.TrimSpace(rr.Value), dtstart.Location())
		if err != nil {
			return nil, fmt.Errorf("parse rrule: %w", err)
		}
		opt.Dtstart = dtstart
		rule, err := rrule.NewRRule(*opt)
		if err != nil {
			return nil, fmt.Errorf("build rrule: %w", err)
		}
		set.RRule(rule)
	} else {
		// RDATE-only series: DTSTART itself is the first instance.
		set.RDate(dtstart)
	}
	set.DTStart(dtstart)
	for _, p := range rdates {
		for _, t := range propTimes(&p, dtstart.Location()) {
			set.RDate(t)
		}
	}
	for _, p := range master.Props.Values(ical.PropExceptionDates) {
		for _, t := range propTimes(&p, dtstart.Location()) {
			set.ExDate(t)
		}
	}

	// In-payload overrides, keyed by the slot they replace.
	type ovr struct {
		comp *ical.Component
		rid  int64
	}
	ovByRID := map[int64]ovr{}
	for _, o := range overrides {
		rid := recurrenceIDUnix(o, dtstart.Location())
		if rid != 0 {
			ovByRID[rid] = ovr{comp: o, rid: rid}
		}
	}

	var out []Occurrence
	next := set.Iterator()
	for len(out) < max {
		t, ok := next()
		if !ok || !t.Before(to) {
			break
		}
		slot := t.Unix()
		if in.ExcludeRecurrenceIDs[slot] {
			continue
		}
		if _, overridden := ovByRID[slot]; overridden {
			continue // emitted below from the override's own times
		}
		if t.Before(from) {
			continue
		}
		out = append(out, Occurrence{StartUnix: slot, EndUnix: t.Add(dur).Unix(), RecurrenceID: slot})
	}

	for _, o := range ovByRID {
		if in.ExcludeRecurrenceIDs[o.rid] {
			continue
		}
		if strings.EqualFold(propText(o.comp.Props, "STATUS"), "CANCELLED") {
			continue
		}
		start, err := propTime(o.comp.Props.Get(ical.PropDateTimeStart), loc)
		if err != nil || start.IsZero() {
			start = time.Unix(o.rid, 0)
		}
		end, err := (&ical.Event{Component: o.comp}).DateTimeEnd(loc)
		if err != nil || !end.After(start) {
			end = start.Add(dur)
		}
		if start.Before(from) || !start.Before(to) {
			continue
		}
		out = append(out, Occurrence{
			StartUnix:    start.Unix(),
			EndUnix:      end.Unix(),
			RecurrenceID: o.rid,
			Override:     true,
			Summary:      propText(o.comp.Props, "SUMMARY"),
			Location:     propText(o.comp.Props, "LOCATION"),
			Status:       propText(o.comp.Props, "STATUS"),
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].StartUnix < out[j].StartUnix })
	if len(out) > max {
		out = out[:max]
	}
	return out, nil
}

// recurrenceIDUnix parses a component's RECURRENCE-ID, or 0.
func recurrenceIDUnix(c *ical.Component, loc *time.Location) int64 {
	p := c.Props.Get(ical.PropRecurrenceID)
	if p == nil {
		return 0
	}
	if isDateValue(p) {
		loc = time.UTC
	}
	t, err := propTime(p, loc)
	if err != nil || t.IsZero() {
		return 0
	}
	return t.Unix()
}

// isDateValue reports whether a date-ish property holds a DATE (all-day)
// rather than a DATE-TIME.
func isDateValue(p *ical.Prop) bool {
	if p.ValueType() == ical.ValueDate {
		return true
	}
	return len(strings.TrimSpace(strings.SplitN(p.Value, ",", 2)[0])) == len("20060102")
}

// propTime parses a single DATE / DATE-TIME property (TZID honored;
// floating times use loc; DATE values use UTC midnight).
func propTime(p *ical.Prop, loc *time.Location) (time.Time, error) {
	if p == nil {
		return time.Time{}, errors.New("missing property")
	}
	if isDateValue(p) {
		return p.DateTime(time.UTC)
	}
	return p.DateTime(loc)
}

// propTimes parses a possibly comma-separated EXDATE/RDATE list. go-ical's
// Prop.DateTime handles one value only, so each value is parsed through a
// single-valued copy of the property. Unparseable entries are skipped.
func propTimes(p *ical.Prop, loc *time.Location) []time.Time {
	var out []time.Time
	for _, v := range strings.Split(p.Value, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		cp := *p
		cp.Value = v
		if t, err := propTime(&cp, loc); err == nil {
			out = append(out, t)
		}
	}
	return out
}

// loadLocation resolves an IANA zone name, falling back to UTC.
func loadLocation(tz string) *time.Location {
	if tz = strings.TrimSpace(tz); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			return l
		}
	}
	return time.UTC
}

// propText returns a property's text value, or "" if absent. Props.Text
// resolves go-ical's value escaping (\n, \, , \;).
func propText(props ical.Props, name string) string {
	v, err := props.Text(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// paramFirst returns the first value of a property parameter (e.g. CN,
// PARTSTAT, ROLE), or "".
func paramFirst(p *ical.Prop, name string) string {
	if p == nil {
		return ""
	}
	if vals, ok := p.Params[name]; ok && len(vals) > 0 {
		return strings.TrimSpace(vals[0])
	}
	return ""
}

// stripMailto removes a leading "mailto:" (case-insensitive) from a
// CAL-ADDRESS value and trims it.
func stripMailto(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 7 && strings.EqualFold(v[:7], "mailto:") {
		return strings.TrimSpace(v[7:])
	}
	return v
}
