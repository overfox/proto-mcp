package sanitize

import (
	"bytes"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// Invisible / line-breaking characters (assessment M3 + M6).
//
// Two classes of code point let sender-controlled text lie to a human
// or a model:
//
//   - Characters that render as nothing: every format character
//     (Unicode category Cf — bidi embeddings/overrides/isolates
//     U+202A–U+202E / U+2066–U+2069, LRM/RLM/ALM, zero-width space/
//     joiners U+200B–U+200D, word joiner and invisible operators
//     U+2060–U+2064, BOM U+FEFF, U+180E, soft hyphen, the tag block
//     U+E0000–U+E007F "ASCII smuggling"), every other
//     Default_Ignorable_Code_Point (combining grapheme joiner U+034F,
//     Hangul fillers U+115F/U+1160/U+3164/U+FFA0, Khmer U+17B4/U+17B5,
//     variation selectors U+180B–U+180F, U+FE00–U+FE0F,
//     U+E0100–U+E01EF), and blank-looking fillers that are formally
//     "visible" (braille blank U+2800, musical null notehead
//     U+1D159). They hide text, pad a dialog line until a forged line
//     wraps into view, reorder text visually, or split keywords so
//     filters miss them.
//   - Line separators other than '\n' — U+2028 LINE SEPARATOR,
//     U+2029 PARAGRAPH SEPARATOR, U+0085 NEXT LINE, VT, FF — are
//     rendered as a line break by AppKit (the Touch ID dialog) but
//     survive "\n"-only sanitizers, so a subject or filename carrying
//     one could paint a fake "BCC:" line into an approval dialog.
//
// IsInvisible / IsLineSeparator are the shared predicates; every
// sanitizer in this package and internal/mcp.SanitizePromptText uses
// them so the sets can't drift apart.

// IsInvisible reports whether r renders as nothing (or as blank
// filler) and should be dropped from display / LLM text: Unicode Cf,
// Default_Ignorable_Code_Point, and the blank fillers listed above.
func IsInvisible(r rune) bool {
	switch {
	case r < 0xAD:
		return false
	case r >= 0xE0000 && r <= 0xE0FFF:
		// Tag block, variation selectors supplement and the rest of
		// the reserved default-ignorable plane-14 range.
		return true
	case unicode.Is(unicode.Cf, r),
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r),
		unicode.Is(unicode.Variation_Selector, r):
		return true
	}
	switch r {
	case 0x2800, // BRAILLE PATTERN BLANK
		0x1D159: // MUSICAL SYMBOL NULL NOTEHEAD
		return true
	}
	return false
}

// IsLineSeparator reports whether r is a line or paragraph break other
// than '\n' (and other than '\r', which callers handle as a C0
// control). Callers map these to a plain space.
func IsLineSeparator(r rune) bool {
	switch r {
	case 0x2028, 0x2029, 0x0085, 0x000b, 0x000c:
		return true
	}
	return false
}

// IsBlank reports whether r is any kind of whitespace — ASCII or
// Unicode (\p{Z}: NBSP, en/em/ideographic spaces, …). Dialog fields
// collapse runs of these to one space so padding can't push text
// around (M6).
func IsBlank(r rune) bool {
	return unicode.IsSpace(r) || unicode.Is(unicode.Z, r)
}

// IsEmojiBase reports whether r is a symbol that a following U+FE0F
// (emoji presentation selector) legitimately modifies ("⚠️", "✔️").
// Callers that want emoji to keep their look may keep a single FE0F
// after such a rune; anywhere else it is invisible filler.
func IsEmojiBase(r rune) bool {
	return unicode.Is(unicode.So, r)
}

// CollapseUnicodeSpaceRuns replaces each run of spaces that contains
// a non-ASCII space separator (\p{Z} other than U+0020 — NBSP,
// U+2000–U+200A, U+3000 …) with one ASCII space. Runs of plain ASCII
// spaces, '\n' and '\t' are left alone.
func CollapseUnicodeSpaceRuns(s string) string {
	wide := func(r rune) bool { return r > 0x7f && unicode.Is(unicode.Z, r) }
	if !strings.ContainsFunc(s, wide) {
		return s
	}
	rs := []rune(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(rs); {
		if rs[i] != ' ' && !wide(rs[i]) {
			b.WriteRune(rs[i])
			i++
			continue
		}
		j, hasWide := i, false
		for j < len(rs) && (rs[j] == ' ' || wide(rs[j])) {
			hasWide = hasWide || wide(rs[j])
			j++
		}
		if hasWide {
			b.WriteByte(' ')
		} else {
			b.WriteString(string(rs[i:j]))
		}
		i = j
	}
	return b.String()
}

// StripInvisible drops IsInvisible runes and maps IsLineSeparator
// runes to a space. Other characters (including '\n') pass through.
func StripInvisible(s string) string {
	clean := true
	for _, r := range s {
		if IsInvisible(r) || IsLineSeparator(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case IsInvisible(r):
		case IsLineSeparator(r):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// CollapseBlanks drops invisible characters and maps every run of
// whitespace (IsBlank, line separators included) to a single ASCII
// space. For one-line display fields.
func CollapseBlanks(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		switch {
		case IsInvisible(r):
			continue
		case IsBlank(r) || IsLineSeparator(r):
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// --- hidden HTML elements ------------------------------------------

// stripHiddenElements removes what a mail client would not show —
// comments, non-rendered elements, and elements / text hidden by
// attributes or CSS (see visible.go) — before HTML() hands the markup
// to bluemonday, which would otherwise drop the style attributes and
// make invisible text visible to the LLM.
//
// When nothing is removed the input is returned unchanged (byte for
// byte). Otherwise the pruned tree is re-rendered. Markup the parser
// refuses (nesting deeper than its 512-element limit) fails closed:
// only a notice is returned, never the unpruned input.
func stripHiddenElements(input string) string {
	if !strings.Contains(input, "<") {
		return input
	}
	d, ok := parseVisible(input)
	if !ok {
		return unparseableNotice
	}
	if !d.changed {
		return input
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, d.root); err != nil {
		return input
	}
	return buf.String()
}
