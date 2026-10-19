package mcp

import (
	"strings"
	"testing"
)

// SECURITY D21 / D23 — NSAlert prompt content sanitization.

func TestSanitizePromptText_StripsControlChars(t *testing.T) {
	// \x07 BEL, \x1b ESC (terminal escape),  APC (C1 range).
	//  is intentionally written as a Unicode escape so the
	// string is valid UTF-8; raw \x9f would be an invalid byte
	// that NFKC replaces with U+FFFD before we get to it.
	in := "alice@example.com\x07\x1bevil"
	got := SanitizePromptText(in, 1000)
	for _, bad := range []rune{0x07, 0x1b, 0x9f} {
		if strings.ContainsRune(got, bad) {
			t.Errorf("control char %U not stripped: %q", bad, got)
		}
	}
}

func TestSanitizePromptText_StripsBidiOverride(t *testing.T) {
	// U+202E RIGHT-TO-LEFT OVERRIDE — used to spoof email addresses
	// by flipping rendering ("alice@example.com" ←→ "moc.elpmaxe@ecila").
	in := "alice@‮example.com"
	got := SanitizePromptText(in, 1000)
	if strings.ContainsRune(got, '‮') {
		t.Errorf("RLO not stripped: %q (codepoints: %v)", got, []rune(got))
	}
	if !strings.Contains(got, "alice@example.com") {
		t.Errorf("visible content damaged: %q", got)
	}
}

func TestSanitizePromptText_StripsZeroWidth(t *testing.T) {
	// U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM. The BOM
	// must be source-encoded as a Go rune literal — embedding the
	// raw codepoint at the top of the file would be parsed as a
	// byte-order mark by the Go scanner.
	for _, zw := range []rune{'​', '‌', '‍', '\ufeff'} {
		in := "a" + string(zw) + "b"
		got := SanitizePromptText(in, 1000)
		if strings.ContainsRune(got, zw) {
			t.Errorf("zero-width %U not stripped: %q", zw, got)
		}
		if got != "ab" {
			t.Errorf("expected \"ab\", got %q", got)
		}
	}
}

func TestSanitizePromptText_PreservesNewlineTab(t *testing.T) {
	in := "line one\nline two\tcol b"
	got := SanitizePromptText(in, 1000)
	if !strings.Contains(got, "\n") || !strings.Contains(got, "\t") {
		t.Errorf("newline/tab lost: %q", got)
	}
}

func TestSanitizePromptText_LengthCap(t *testing.T) {
	in := strings.Repeat("a", 10_000)
	got := SanitizePromptText(in, 200)
	r := []rune(got)
	if len(r) > 200+len([]rune("…[truncated]"))+1 {
		t.Errorf("not truncated; len = %d", len(r))
	}
	if !strings.HasSuffix(got, "…[truncated]") {
		t.Errorf("truncation marker missing: %q", got[len(got)-30:])
	}
}

func TestSanitizePromptText_NFKCNormalization(t *testing.T) {
	// Fullwidth Latin "ＡＢＣ" (U+FF21..) normalizes to "ABC" under NFKC.
	in := "ＡＢＣ"
	got := SanitizePromptText(in, 1000)
	if got != "ABC" {
		t.Errorf("NFKC didn't fold fullwidth: %q", got)
	}
}

// M3: U+2028 / U+2029 / U+0085 render as line breaks in AppKit but used
// to survive, letting a subject paint a fake "BCC:" line. They become
// spaces; every Cf format char and the tag block are dropped.
func TestSanitizePromptText_UnicodeLineSeparators(t *testing.T) {
	for _, sep := range []rune{0x2028, 0x2029, 0x0085, 0x000b, 0x000c} {
		in := "Subject: hi" + string(sep) + "BCC: evil@x.com"
		got := SanitizePromptText(in, 1000)
		if got != "Subject: hi BCC: evil@x.com" {
			t.Errorf("U+%04X: got %q", sep, got)
		}
	}
	invisible := []rune{0x200b, 0x200e, 0x202e, 0x2060, 0x2064, 0x2066, 0xfeff, 0x180e, 0x00ad, 0xe0001, 0xe0041, 0xe007f}
	for _, r := range invisible {
		if got := SanitizePromptText("a"+string(r)+"b", 100); got != "ab" {
			t.Errorf("U+%04X not stripped: %q", r, got)
		}
	}
}

// M6 round 2: blank-looking fillers are dropped and runs of Unicode
// spaces collapse, so a field can't be padded until a forged line
// wraps into view. Plain ASCII runs (our layout) and a single emoji
// presentation selector after a symbol ("⚠️") are kept.
func TestSanitizePromptText_PaddingFillers(t *testing.T) {
	for _, r := range []rune{0x2800, 0x3164, 0x1160, 0x115f, 0xffa0, 0x034f, 0x17b4, 0x180b, 0xfe00, 0x1d159, 0xe0100} {
		if got := SanitizePromptText("a"+strings.Repeat(string(r), 40)+"b", 1000); got != "ab" {
			t.Errorf("U+%04X not stripped: %q", r, got)
		}
	}
	if got := SanitizePromptText("Q3 　　   Body: x", 1000); got != "Q3 Body: x" {
		t.Errorf("unicode space run = %q", got)
	}
	if got := SanitizePromptText("To:  a\n\tb", 1000); got != "To:  a\n\tb" {
		t.Errorf("ASCII layout changed: %q", got)
	}
	if got := SanitizePromptText("⚠️ warn", 1000); got != "⚠️ warn" {
		t.Errorf("emoji selector lost: %q", got)
	}
	if got := SanitizePromptText("a️️️b", 1000); got != "ab" {
		t.Errorf("stray selectors kept: %q", got)
	}
	invisible := []rune{0x2800, 0x3164}
	for _, r := range invisible {
		if got := SanitizePromptText("a"+string(r)+"b", 100); got != "ab" {
			t.Errorf("U+%04X not stripped: %q", r, got)
		}
	}
}
