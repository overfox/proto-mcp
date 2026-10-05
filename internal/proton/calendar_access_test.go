package proton

import (
	"errors"
	"fmt"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
)

func TestIsCalendarScopeError(t *testing.T) {
	scope := fmt.Errorf("get events: %w", fmt.Errorf("403 GET /calendar/v1/x/events: %w",
		&gpa.APIError{Status: 403, Code: 9100, Message: "Access token does not have sufficient scope"}))
	if !IsCalendarScopeError(scope) {
		t.Error("code 9100 not detected")
	}
	msg403 := &gpa.APIError{Status: 403, Code: 0, Message: "Insufficient scope"}
	if !IsCalendarScopeError(msg403) {
		t.Error("403 + 'scope' message not detected")
	}
	for _, e := range []error{
		nil,
		errors.New("network down"),
		&gpa.APIError{Status: 403, Code: 2011, Message: "Permission denied"},
		&gpa.APIError{Status: 401, Code: 401, Message: "Invalid access token"},
	} {
		if IsCalendarScopeError(e) {
			t.Errorf("false positive for %v", e)
		}
	}
	if !IsCalendarScopeError(fmt.Errorf("x: %w", ErrCalendarUnavailable)) {
		t.Error("ErrCalendarUnavailable not recognized")
	}
}

func TestCalendarAvailabilityState(t *testing.T) {
	s := &Session{}
	other := &Session{}
	now := time.Unix(1_000_000, 0)

	if s.CalendarUnavailable() || !s.CalendarRecheckDue(now, time.Hour) {
		t.Fatal("fresh session should be available and always due")
	}
	if !s.MarkCalendarUnavailable(now) {
		t.Error("first mark should report the transition")
	}
	if s.MarkCalendarUnavailable(now) {
		t.Error("second mark must not report a transition (log once)")
	}
	if !s.CalendarUnavailable() || other.CalendarUnavailable() {
		t.Error("state must be per-session")
	}
	if s.CalendarRecheckDue(now.Add(5*time.Hour), 6*time.Hour) {
		t.Error("recheck should not be due before the interval")
	}
	if !s.CalendarRecheckDue(now.Add(6*time.Hour), 6*time.Hour) {
		t.Error("recheck should be due after the interval")
	}
	if !s.MarkCalendarAvailable(now) || s.CalendarUnavailable() {
		t.Error("MarkCalendarAvailable should clear and report prior state")
	}
	var nilSess *Session
	if nilSess.CalendarUnavailable() || nilSess.MarkCalendarUnavailable(now) {
		t.Error("nil session must be a no-op")
	}
}

// A lock/unlock cycle resumes the same login (same auth UID) into a new
// *Session; the unavailable verdict must carry over so the daemon doesn't
// re-probe and re-warn after every screen unlock.
func TestCalendarAvailabilityState_SharedAcrossResume(t *testing.T) {
	before := &Session{UID: "uid-resume-test"}
	before.MarkCalendarUnavailable(time.Now())
	after := &Session{UID: "uid-resume-test"}
	if !after.CalendarUnavailable() {
		t.Error("resumed session (same UID) should inherit the unavailable state")
	}
	if (&Session{UID: "uid-other-login"}).CalendarUnavailable() {
		t.Error("a different login must start fresh")
	}
}
