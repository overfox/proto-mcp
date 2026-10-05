package proton

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

const liveCalID = "GXgp_Vn8DZe5tRFnt1SSLqUL5b4M9vv5KIos5c0EtRTYaDYmY6vyyGEsPTBSlm7ZHpuFAJFv0gOZQss_vmow4w=="

func TestRedactLogText_URLIDs(t *testing.T) {
	in := "403 GET https://mail-api.proton.me/calendar/v1/" + liveCalID +
		"/events?Page=0&PageSize=150: Access token does not have sufficient scope (Code=9100, Status=403)"
	got := RedactLogText(in)
	want := "403 GET https://mail-api.proton.me/calendar/v1/:id/events: Access token does not have sufficient scope (Code=9100, Status=403)"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	// A bare ID outside a URL is scrubbed too, with no "==" residue.
	got = RedactLogText("get events for calendar " + liveCalID + ": boom")
	if strings.Contains(got, "GXgp") || strings.Contains(got, "==") {
		t.Errorf("bare ID leaked: %q", got)
	}
	// Ordinary text is untouched.
	plain := "lockwatch helper exited cleanly; attachment-staging ErrCalendarUnavailable"
	if got := RedactLogText(plain); got != plain {
		t.Errorf("over-redacted: %q", got)
	}
}

func captureSlog(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestSlogRestyLogger_LevelsAndRedaction(t *testing.T) {
	buf := captureSlog(t, slog.LevelInfo)
	l := slogRestyLogger{}
	url := "https://mail-api.proton.me/calendar/v1/" + liveCalID + "/events"
	l.Warnf("%v, Attempt %v", "403 GET "+url+": scope", 1)
	l.Errorf("%v", "403 GET "+url+": scope")
	if buf.Len() != 0 {
		t.Fatalf("per-request retry/failure lines must be DEBUG, got at INFO: %s", buf.String())
	}

	buf = captureSlog(t, slog.LevelDebug)
	l.Warnf("%v, Attempt %v", "403 GET "+url+": scope", 1)
	l.Warnf("Cannot unmarshal response body: %s", "bad json")
	out := buf.String()
	if strings.Contains(out, "GXgp") {
		t.Errorf("calendar ID leaked: %s", out)
	}
	if !strings.Contains(out, "calendar/v1/:id/events") {
		t.Errorf("expected scrubbed URL, got %s", out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "Cannot unmarshal") {
		t.Errorf("non-request warning should stay WARN: %s", out)
	}
}

func TestLogrusBridge(t *testing.T) {
	buf := captureSlog(t, slog.LevelInfo)
	_ = loggingOption() // installs the bridge (idempotent)
	logrus.WithField("pkg", "gpa").WithField("KeyID", liveCalID).Warn("Cannot unlock key")
	out := buf.String()
	if !strings.Contains(out, "Cannot unlock key") || !strings.Contains(out, "level=WARN") {
		t.Fatalf("logrus entry not bridged to slog: %q", out)
	}
	if strings.Contains(out, "GXgp") {
		t.Errorf("key ID leaked: %s", out)
	}
}
