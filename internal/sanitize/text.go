package sanitize

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

// Invisible / line-breaking characters (assessment M3 + M6).
//
// Two classes of code point let sender-controlled text lie to a human
// or a model:
//
//   - Format characters (Unicode category Cf) render as nothing: bidi
//     embeddings/overrides/isolates (U+202A–U+202E, U+2066–U+2069),
//     LRM/RLM/ALM, zero-width space/joiners (U+200B–U+200D), word
//     joiner and invisible operators (U+2060–U+2064), BOM (U+FEFF),
//     the Mongolian vowel separator (U+180E), soft hyphen, and the
//     tag block (U+E0000–U+E007F, "ASCII smuggling"). They hide text,
//     reorder it visually, or split keywords so filters miss them.
//   - Line separators other than '\n' — U+2028 LINE SEPARATOR,
//     U+2029 PARAGRAPH SEPARATOR, U+0085 NEXT LINE, VT, FF — are
//     rendered as a line break by AppKit (the Touch ID dialog) but
//     survive "\n"-only sanitizers, so a subject or filename carrying
//     one could paint a fake "BCC:" line into an approval dialog.
//
// IsInvisible / IsLineSeparator are the shared predicates; every
// sanitizer in this package and internal/mcp.SanitizePromptText uses
// them so the sets can't drift apart.

// IsInvisible reports whether r is an invisible formatting character
// that should be dropped from display / LLM text: any Unicode Cf code
// point plus the whole tag block.
func IsInvisible(r rune) bool {
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	return unicode.Is(unicode.Cf, r)
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

// --- hidden HTML elements ------------------------------------------

// stripHiddenElements removes elements a mail client would not show —
// the `hidden` attribute, or an inline style with display:none,
// visibility:hidden|collapse, font-size:0, opacity:0, or a zero
// (max-)height/width combined with overflow:hidden — together with
// everything inside them. Senders use these to put instructions in
// front of an LLM that the human reading the same mail never sees.
//
// The input is parsed with the HTML5 algorithm (golang.org/x/net/html)
// so the "inside" relation matches what a browser builds, even for
// malformed markup — a regex or tokenizer could be made to end the
// hidden region early with a stray end tag the browser ignores.
//
// When nothing is hidden the input is returned unchanged (byte for
// byte), so ordinary mail keeps its existing text / entity handling.
// Otherwise the pruned tree is re-rendered.
func stripHiddenElements(input string) string {
	if !strings.Contains(input, "<") {
		return input
	}
	doc, err := html.Parse(strings.NewReader(input))
	if err != nil {
		return input
	}
	if !pruneHidden(doc) {
		return input
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return input
	}
	return buf.String()
}

// pruneHidden removes hidden element subtrees under n; reports whether
// anything was removed.
func pruneHidden(n *html.Node) bool {
	removed := false
	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		if c.Type == html.ElementNode && elementHidden(c) {
			n.RemoveChild(c)
			removed = true
		} else if pruneHidden(c) {
			removed = true
		}
		c = next
	}
	return removed
}

func elementHidden(n *html.Node) bool {
	for _, a := range n.Attr {
		switch strings.ToLower(a.Key) {
		case "hidden":
			return true
		case "style":
			if styleHides(a.Val) {
				return true
			}
		}
	}
	return false
}

// styleHides reports whether an inline style declaration list hides
// its element. Property names/values are normalized first: CSS
// comments removed, backslash escapes decoded, case folded, whitespace
// and !important dropped — so "DISPLAY : n\6f ne" still counts.
func styleHides(style string) bool {
	decls := map[string]string{}
	for _, d := range strings.Split(normalizeCSS(style), ";") {
		k, v, ok := strings.Cut(d, ":")
		if !ok {
			continue
		}
		decls[k] = strings.TrimSuffix(v, "!important")
	}
	switch decls["display"] {
	case "none":
		return true
	}
	switch decls["visibility"] {
	case "hidden", "collapse":
		return true
	}
	if v, ok := decls["font-size"]; ok && cssZero(v) {
		return true
	}
	if v, ok := decls["opacity"]; ok && cssZero(v) {
		return true
	}
	if decls["overflow"] == "hidden" || decls["overflow-y"] == "hidden" || decls["overflow-x"] == "hidden" {
		for _, k := range []string{"max-height", "height", "max-width", "width"} {
			if v, ok := decls[k]; ok && cssZero(v) {
				return true
			}
		}
	}
	return false
}

// cssZero reports whether a CSS length / number is zero (0, 0px,
// 0.0em, 0%, -0, …).
func cssZero(v string) bool {
	num := strings.TrimRightFunc(v, func(r rune) bool { return unicode.IsLetter(r) || r == '%' })
	if num == "" {
		return false
	}
	f, err := strconv.ParseFloat(num, 64)
	return err == nil && f == 0
}

// normalizeCSS lower-cases s, drops /* comments */, decodes CSS
// escapes (\XX hex up to 6 digits, or \c) and removes all whitespace.
func normalizeCSS(s string) string {
	for {
		i := strings.Index(s, "/*")
		if i < 0 {
			break
		}
		j := strings.Index(s[i+2:], "*/")
		if j < 0 {
			s = s[:i]
			break
		}
		s = s[:i] + s[i+2+j+2:]
	}
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if r == '\\' && i+1 < len(rs) {
			j := i + 1
			for j < len(rs) && j < i+7 && isHex(rs[j]) {
				j++
			}
			if j > i+1 {
				if v, err := strconv.ParseUint(string(rs[i+1:j]), 16, 32); err == nil {
					b.WriteRune(rune(v))
				}
				i = j - 1
				if i+1 < len(rs) && unicode.IsSpace(rs[i+1]) {
					i++ // one whitespace terminates a hex escape
				}
				continue
			}
			b.WriteRune(rs[j])
			i = j
			continue
		}
		if unicode.IsSpace(r) || IsInvisible(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
