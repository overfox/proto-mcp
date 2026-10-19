// Package sanitize is the single audited surface for turning
// Proton-Mail message bodies into LLM-safe payloads.
//
// Two outputs:
//
//   - HTML(input) — minimal-allowlist HTML stripped of scripts,
//     iframes, remote-image refs, and any markup not on the
//     allowlist below. Designed for an LLM prompt: rich enough to
//     preserve sentence structure / links / lists, narrow enough
//     that prompt-injection embedded in exotic markup has nowhere
//     to hide.
//
//   - Text(input) — the visible text only (M6: nothing a reader
//     wouldn't see), one line per block, quoted-reply markers
//     trimmed and whitespace collapsed. Source for mail_read text
//     bodies, snippets and the FTS5 body_text column.
//
// SECURITY Foundational #7 + Phase-2 plan Q1 (strict policy).
package sanitize

import (
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

// AllowedHTMLTags is the closed allowlist used by HTML(). Anything not
// in this list gets stripped (content kept, surrounding tags removed
// by bluemonday). Kept narrow on purpose — every additional tag is a
// new place for exotic HTML to hide a prompt-injection vector.
//
// Block-level structure (p, br, headings, lists, blockquote) preserves
// the visual rhythm of an email so the LLM can tell paragraphs apart.
// Inline emphasis (b, strong, i, em) carries semantic weight. Anchors
// are allowed but their href is stripped — the LLM sees the link text
// and never the underlying URL, which neutralizes the "click here for
// reset" embed-attack class.
var AllowedHTMLTags = []string{
	"p", "br",
	"b", "strong", "i", "em",
	"ul", "ol", "li",
	"h1", "h2", "h3", "h4",
	"blockquote",
}

// Note: <a> is intentionally NOT on the allowlist. bluemonday strips
// the element when no attrs are allowed on it but preserves the link
// text as surrounding content — so the LLM sees "click here" with no
// surrounding URL. Letting href through would give an attacker a free
// string the LLM can be tricked by; dropping it is the right safety.

// htmlPolicy is built once and reused. bluemonday.Policy is safe for
// concurrent use, so a single package-level value is fine.
var htmlPolicy = buildHTMLPolicy()

func buildHTMLPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements(AllowedHTMLTags...)
	// Anchors are on the allowlist but their href is NOT — we keep
	// the visible link text and drop the URL the LLM would otherwise
	// see. This is the deliberate "prompt-injection via crafted href"
	// mitigation; the user can always re-fetch the message via the
	// Proton web UI if they want the actual link.
	//
	// Note: not calling AllowAttrs(...) at all = strip everything.
	return p
}

// HTML returns a sanitized copy of input. Always safe to call;
// returns "" for empty input.
func HTML(input string) string {
	if input == "" {
		return ""
	}
	// M6: comments, non-rendered elements and everything hidden from
	// the reader (attributes, inline styles, <style> rules) go first —
	// bluemonday drops the style attribute, which would otherwise make
	// invisible text visible to the LLM.
	return StripInvisible(htmlPolicy.Sanitize(stripHiddenElements(input)))
}

// Outbound sanitizes LLM-supplied HTML before it's encrypted and
// shipped to recipients. Same allowlist as HTML() — every reason
// that policy was the right answer for INBOUND mail (scripts /
// tracking pixels / remote-image refs hidden in exotic markup) is
// equally a reason to enforce it OUTBOUND. The LLM should not be
// able to send what we wouldn't accept from a stranger.
//
// Why an alias: the inbound and outbound use cases are different
// enough that a future tightening on one shouldn't surprise the
// other. Today Outbound is HTML(); if outbound ever needs different
// rules (e.g. allow <a href> for explicit hyperlinks the LLM was
// told to include), this is the seam.
func Outbound(input string) string {
	return HTML(input)
}

// quotedReplyLine matches lines that are pure quoted-reply markers
// ("> something" or "> > something"). Used by Text() to drop the
// in-line reply history — for snippets we want the new content,
// not the email-thread tail.
var quotedReplyLine = regexp.MustCompile(`^\s*(>+\s?)+`)

// Text extracts the plain text a reader of input would see — for the
// LLM (mail_read text bodies, HTML attachments), snippets and FTS5
// indexing.
//
// Steps:
//
//  1. Parse input with the HTML5 algorithm (golang.org/x/net/html)
//     and drop everything that doesn't render: comments (Outlook
//     conditional comments included), script / style / template /
//     noscript / title / head / svg / … content, attribute values,
//     and elements or text hidden by attributes or CSS (inline styles
//     and simple <style> rules) — M6, see visible.go. D42: <style>
//     and <script> content never leaks.
//  2. Emit text nodes only, entities decoded as displayed; block
//     elements and <br> start a new line; whitespace inside a line is
//     collapsed as a browser would (outside <pre>). Plain-text input
//     (no markup at all) keeps its own line breaks.
//  3. Drop control characters and invisible / default-ignorable
//     characters (Unicode line separators become spaces).
//  4. Drop lines that are entirely quoted-reply markers.
//  5. Collapse whitespace runs inside each line to one space, trim
//     each line and drop blank ones.
//
// Link text is kept; hrefs (like every other attribute) are not.
func Text(input string) string {
	if input == "" {
		return ""
	}
	out := input
	if strings.ContainsAny(input, "<&") {
		d, ok := parseVisible(input)
		if !ok {
			return unparseableNotice
		}
		out = extractText(d)
	}
	out = stripControlChars(out)

	lines := strings.Split(out, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if quotedReplyLine.MatchString(line) {
			continue
		}
		line = strings.TrimSpace(collapseBlankRuns(line))
		if line == "" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// collapseBlankRuns maps each run of whitespace (ASCII or Unicode
// \p{Z}) in one line to a single space.
func collapseBlankRuns(s string) string {
	if !strings.ContainsFunc(s, IsBlank) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if IsBlank(r) {
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

// stripControlChars drops C0 (< 0x20, excluding \n and \t) and C1
// (0x80–0x9F) control bytes from s, plus invisible format characters
// (IsInvisible: zero-width, bidi, tag block); Unicode line/paragraph
// separators become a space (M3/M6). SECURITY C-2: terminal escape
// sequences and zero-width control bytes embedded in mail bodies
// can corrupt LLM output, hide content from human reviewers, or
// break terminal rendering when the body is dumped to stdout via
// CLI tools. The few control chars we keep (\n, \t) carry real
// structure; everything else is at best invisible and at worst
// adversarial.
func stripControlChars(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case IsLineSeparator(r):
			b.WriteByte(' ')
		case r < 0x20:
			// C0 control char — drop.
		case r >= 0x7f && r <= 0x9f:
			// DEL (0x7f) and C1 control range — drop.
		case IsInvisible(r):
			// Zero-width / bidi / tag / default-ignorable — drop.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Snippet returns up to maxRunes runes from Text(input) on one line
// (line breaks become spaces), suitable for the message-list preview.
// maxRunes <= 0 falls back to 200.
//
// Runes (not bytes) so a snippet doesn't slice a multibyte character
// in half — important for emoji-heavy email and any non-ASCII content.
func Snippet(input string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 200
	}
	text := strings.ReplaceAll(Text(input), "\n", " ")
	r := []rune(text)
	if len(r) <= maxRunes {
		return text
	}
	return string(r[:maxRunes]) + "…"
}
