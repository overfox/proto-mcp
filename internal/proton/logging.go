package proton

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"

	"github.com/just-an-oldsalt/proto-mcp/internal/redact"
)

// go-proton-api logs through two side channels that bypass slog — and
// therefore internal/redact — entirely:
//
//   - resty's default logger, which writes "WARN RESTY 403 GET
//     https://mail-api.proton.me/calendar/v1/<calendarID>/events: …"
//     straight to stderr (= daemon.log), one WARN per retry attempt plus
//     an ERROR for the final failure;
//   - the package-level logrus logger (`pkg=gpa`), which logs key IDs
//     and the like.
//
// This file routes both through slog.Default() (whose handler applies
// redact.Attr), scrubs opaque Proton IDs out of URL paths first, and
// downgrades the noisy per-attempt / per-request lines to DEBUG: every
// request failure is also returned to the caller, which logs it once
// with context.

// loggingOption returns the gpa.Option that installs the slog-backed
// resty logger, and (once per process) bridges go-proton-api's logrus
// output into slog. NewManager appends it to its option list.
func loggingOption() gpa.Option {
	bridgeLogrusOnce.Do(bridgeLogrus)
	return gpa.WithLogger(slogRestyLogger{})
}

// slogRestyLogger implements resty.Logger on top of slog.Default().
type slogRestyLogger struct{}

var _ resty.Logger = slogRestyLogger{}

func (slogRestyLogger) Errorf(format string, v ...any) {
	msg := RedactLogText(fmt.Sprintf(format, v...))
	// resty's Errorf fires for the final failure of every request — the
	// same error is returned to (and logged by) our caller.
	if looksLikeRequestLine(msg) {
		logResty(slog.LevelDebug, msg)
		return
	}
	logResty(slog.LevelWarn, msg)
}

func (slogRestyLogger) Warnf(format string, v ...any) {
	msg := RedactLogText(fmt.Sprintf(format, v...))
	// "…, Attempt N" — per-retry chatter. The outcome is reported once
	// by the caller (or by Errorf above).
	if strings.Contains(msg, ", Attempt ") || looksLikeRequestLine(msg) {
		logResty(slog.LevelDebug, msg)
		return
	}
	logResty(slog.LevelWarn, msg)
}

func (slogRestyLogger) Debugf(format string, v ...any) {
	logResty(slog.LevelDebug, RedactLogText(fmt.Sprintf(format, v...)))
}

func logResty(level slog.Level, msg string) {
	slog.Default().Log(context.Background(), level, "proton http", "component", "resty", "detail", msg)
}

// looksLikeRequestLine reports whether a resty message is a per-request
// outcome ("403 GET https://…: …", `Get "https://…": dial tcp …`).
func looksLikeRequestLine(msg string) bool {
	return strings.Contains(msg, "http://") || strings.Contains(msg, "https://")
}

// ----- logrus bridge -----

var bridgeLogrusOnce sync.Once

// bridgeLogrus silences logrus's own stderr writer and forwards every
// entry to slog via a hook. go-proton-api uses the logrus standard
// logger (`logrus.WithField("pkg", "gpa")`); nothing else in proto-mcp
// uses logrus, so taking over the standard logger is safe.
func bridgeLogrus() {
	std := logrus.StandardLogger()
	std.SetOutput(io.Discard)
	std.AddHook(logrusSlogHook{})
}

type logrusSlogHook struct{}

func (logrusSlogHook) Levels() []logrus.Level { return logrus.AllLevels }

func (logrusSlogHook) Fire(e *logrus.Entry) error {
	level := slog.LevelDebug
	switch {
	case e.Level <= logrus.ErrorLevel: // panic, fatal, error
		level = slog.LevelError
	case e.Level == logrus.WarnLevel:
		level = slog.LevelWarn
	case e.Level == logrus.InfoLevel:
		level = slog.LevelInfo
	}
	attrs := make([]any, 0, 2*len(e.Data)+2)
	attrs = append(attrs, "component", "gpa")
	for k, v := range e.Data {
		if k == "pkg" {
			continue
		}
		val := fmt.Sprint(v)
		if err, ok := v.(error); ok {
			val = err.Error()
		}
		attrs = append(attrs, k, RedactLogText(val))
	}
	slog.Default().Log(context.Background(), level, RedactLogText(e.Message), attrs...)
	return nil
}

// ----- text scrubbing -----

// urlRE matches http(s) URLs embedded in free text.
var urlRE = regexp.MustCompile(`https?://[^\s"'<>]+`)

// protonIDRE matches Proton's opaque base64url IDs (calendar, event,
// message, key IDs — typically 88 chars ending in "=="). 20+ chars of
// the base64url alphabet with optional '=' padding.
var protonIDRE = regexp.MustCompile(`[A-Za-z0-9_-]{20,}={0,2}`)

// RedactLogText scrubs a free-form log/error string: opaque IDs in URL
// path segments become ":id" and the query string is dropped (so
// "https://mail-api.proton.me/calendar/v1/<id>/events?Page=0" becomes
// "https://mail-api.proton.me/calendar/v1/:id/events"), then any
// remaining Proton-ID-shaped run is replaced with "[ID]" and the result
// goes through redact.Error for tokens. Exported so sync/tool code can
// scrub SDK errors before logging them.
func RedactLogText(s string) string {
	s = urlRE.ReplaceAllStringFunc(s, redactURL)
	s = protonIDRE.ReplaceAllStringFunc(s, func(m string) string {
		if !isOpaqueID(m) {
			return m
		}
		return "[ID]"
	})
	return redact.Error(s)
}

func redactURL(raw string) string {
	trail := ""
	// Keep trailing punctuation that is part of the sentence, not the URL.
	for len(raw) > 0 && strings.ContainsRune(`:,.;)`, rune(raw[len(raw)-1])) {
		trail = raw[len(raw)-1:] + trail
		raw = raw[:len(raw)-1]
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[URL]" + trail
	}
	segs := strings.Split(u.EscapedPath(), "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		if dec, err := url.PathUnescape(seg); err == nil {
			seg = dec
		}
		if isOpaqueID(seg) {
			segs[i] = ":id"
		}
	}
	return u.Scheme + "://" + u.Host + strings.Join(segs, "/") + trail
}

// isOpaqueID reports whether s is shaped like a Proton opaque ID: a
// single 20+ char base64url run (optional '=' padding) mixing upper case,
// lower case and digits. Route segments ("attachment-staging") and Go
// identifiers ("ErrCalendarUnavailable") don't qualify.
func isOpaqueID(s string) bool {
	if !protonIDRE.MatchString(s) || protonIDRE.FindString(s) != s {
		return false
	}
	var upper, lower, digit bool
	for _, r := range strings.TrimRight(s, "=") {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}
