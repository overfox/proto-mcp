package sync

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	stdsync "sync"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// fakeCalendarAPI serves just enough of /calendar/v1 for RunCalendarOnce.
// eventsHandler decides the response for a calendar's /events calls.
type fakeCalendarAPI struct {
	mu         stdsync.Mutex
	calIDs     []string
	eventCalls int
	events     func(calID string) (status int, body string)
}

func (f *fakeCalendarAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
	path := strings.TrimPrefix(r.URL.Path, "/calendar/v1")
	if path == "" || path == "/" {
		var parts []string
		for _, id := range f.calIDs {
			parts = append(parts, fmt.Sprintf(`{"ID":%q,"Name":"C","Flags":1}`, id))
		}
		fmt.Fprintf(w, `{"Code":1000,"Calendars":[%s]}`, strings.Join(parts, ","))
		return
	}
	calID, rest, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if rest != "events" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	f.eventCalls++
	f.mu.Unlock()
	status, body := f.events(calID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *fakeCalendarAPI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.eventCalls
}

func fakeSession(t *testing.T, h http.Handler) *protonclient.Session {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	m := gpa.New(gpa.WithHostURL(srv.URL), gpa.WithRetryCount(0))
	t.Cleanup(m.Close)
	c := m.NewClient("uid", "acc", "ref")
	return &protonclient.Session{Client: c}
}

func calOpen(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

const scopeBody = `{"Code":9100,"Error":"Access token does not have sufficient scope"}`

func TestRunCalendarOnce_ScopeErrorMarksUnavailable(t *testing.T) {
	api := &fakeCalendarAPI{calIDs: []string{"cal-a", "cal-b"},
		events: func(string) (int, string) { return http.StatusForbidden, scopeBody }}
	sess := fakeSession(t, api)
	st := calOpen(t)
	ctx := context.Background()

	t0 := time.Unix(1_800_000_000, 0)
	nowFunc = func() time.Time { return t0 }
	t.Cleanup(func() { nowFunc = time.Now })

	res, err := RunCalendarOnce(ctx, sess, st)
	if err != nil {
		t.Fatalf("scope error must not surface as a sync error (would WARN every tick): %v", err)
	}
	if !res.Unavailable || !sess.CalendarUnavailable() {
		t.Fatalf("session not marked unavailable: %+v", res)
	}
	if got := api.calls(); got != 1 {
		t.Errorf("event endpoint calls = %d, want 1 (stop after first scope rejection)", got)
	}

	// Subsequent ticks inside the re-check interval make no API calls.
	nowFunc = func() time.Time { return t0.Add(2 * time.Minute) }
	res, err = RunCalendarOnce(ctx, sess, st)
	if err != nil || !res.Unavailable {
		t.Fatalf("second pass: res=%+v err=%v", res, err)
	}
	if got := api.calls(); got != 1 {
		t.Errorf("event calls after quiet tick = %d, want 1", got)
	}

	// After the interval it probes again; once scope is granted it recovers.
	api.events = func(string) (int, string) { return http.StatusOK, `{"Code":1000,"Total":0,"Events":[]}` }
	nowFunc = func() time.Time { return t0.Add(CalendarRecheckInterval) }
	res, err = RunCalendarOnce(ctx, sess, st)
	if err != nil || res.Unavailable || sess.CalendarUnavailable() {
		t.Fatalf("recovery pass: res=%+v err=%v unavailable=%v", res, err, sess.CalendarUnavailable())
	}

	// Backfill reports the condition explicitly.
	api.events = func(string) (int, string) { return http.StatusForbidden, scopeBody }
	if _, err := RunCalendarBackfill(ctx, sess, st, false); !errors.Is(err, protonclient.ErrCalendarUnavailable) {
		t.Errorf("backfill err = %v, want ErrCalendarUnavailable", err)
	}
}

func TestRunCalendarOnce_OneCalendarFailureDoesNotAbortPass(t *testing.T) {
	api := &fakeCalendarAPI{calIDs: []string{"cal-a", "cal-bad", "cal-c"},
		events: func(calID string) (int, string) {
			if calID == "cal-bad" {
				return http.StatusUnprocessableEntity, `{"Code":2501,"Error":"Calendar does not exist"}`
			}
			return http.StatusOK, fmt.Sprintf(`{"Code":1000,"Total":1,"Events":[{"ID":"ev-%s","CalendarID":%q,"UID":"u","StartTime":100,"EndTime":200,"LastEditTime":5}]}`, calID, calID)
		}}
	sess := fakeSession(t, api)
	st := calOpen(t)

	res, err := RunCalendarOnce(context.Background(), sess, st)
	if err == nil || !strings.Contains(err.Error(), "get events for calendar cal-bad") {
		t.Fatalf("expected joined per-calendar error naming cal-bad, got %v", err)
	}
	if res.CalendarsUpserted != 3 || res.CalendarsFailed != 1 || res.EventsUpserted != 2 {
		t.Errorf("result = %+v, want 3 calendars, 1 failed, 2 events", res)
	}
	if res.Unavailable || sess.CalendarUnavailable() {
		t.Error("non-scope failure must not mark calendar unavailable")
	}
	for _, id := range []string{"ev-cal-a", "ev-cal-c"} {
		if _, err := st.GetCalendarEvent(context.Background(), id); err != nil {
			t.Errorf("event %s not mirrored: %v", id, err)
		}
	}
}
