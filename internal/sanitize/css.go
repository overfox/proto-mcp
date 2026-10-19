package sanitize

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// CSS helpers for the hidden-content pass (assessment M6).
//
// This is NOT a CSS engine. It understands just enough of inline
// style="" declarations and simple <style> rules to answer one
// question conservatively: "would a person reading this mail see this
// text?". When in doubt it errs towards "hidden" for the declarations
// below (dropping a little legitimate text is cheaper than handing the
// model an instruction the user never saw), and towards "visible" for
// values it can't evaluate (calc(), var(), unknown units).

// --- declarations ------------------------------------------------------

// cssDecls is one declaration list: lower-cased property → value with
// whitespace collapsed and !important removed. Later declarations of
// the same property win, as in a browser.
type cssDecls map[string]string

// parseDecls parses a style="" attribute value or a rule body.
func parseDecls(s string) cssDecls {
	return parseNormalizedDecls(normalizeCSS(s))
}

// parseNormalizedDecls parses a declaration list that has already been
// through normalizeCSS.
func parseNormalizedDecls(s string) cssDecls {
	d := cssDecls{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if i := strings.LastIndex(v, "!"); i >= 0 && strings.TrimSpace(v[i+1:]) == "important" {
			v = strings.TrimSpace(v[:i])
		}
		if k == "" {
			continue
		}
		d[k] = v
	}
	return d
}

// normalizeCSS lower-cases s, drops /* comments */, decodes CSS
// escapes (\XX hex up to 6 digits, or \c), drops invisible format
// characters and collapses whitespace runs to one space — so
// "DISPLAY : n\6f ne" still reads as "display : none".
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
		// Dropped without a gap: "dis/**/play" reads as "display"
		// (a browser would ignore it; hiding more is the safe side).
		s = s[:i] + s[i+2+j+2:]
	}
	var b strings.Builder
	b.Grow(len(s))
	rs := []rune(s)
	space := false
	emit := func(r rune) {
		if unicode.IsSpace(r) {
			space = true
			return
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(unicode.ToLower(r))
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if r == '\\' && i+1 < len(rs) {
			j := i + 1
			for j < len(rs) && j < i+7 && isHex(rs[j]) {
				j++
			}
			if j > i+1 {
				if v, err := strconv.ParseUint(string(rs[i+1:j]), 16, 32); err == nil && !IsInvisible(rune(v)) {
					emit(rune(v))
				}
				i = j - 1
				if i+1 < len(rs) && unicode.IsSpace(rs[i+1]) {
					i++ // one whitespace terminates a hex escape
				}
				continue
			}
			emit(rs[j])
			i = j
			continue
		}
		if IsInvisible(r) {
			continue
		}
		emit(r)
	}
	return b.String()
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// --- lengths -------------------------------------------------------------

// cssLength parses a CSS length into CSS pixels. base is what 1em
// (and, divided by 100, 1%) resolves to. ok is false for anything it
// can't evaluate (calc(), var(), keywords, viewport units).
func cssLength(v string, base float64) (px float64, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	i := 0
	for i < len(v) && (v[i] == '+' || v[i] == '-' || v[i] == '.' || (v[i] >= '0' && v[i] <= '9') || ((v[i] == 'e') && i > 0 && i+1 < len(v) && (v[i+1] >= '0' && v[i+1] <= '9' || v[i+1] == '-' || v[i+1] == '+'))) {
		i++
	}
	num, unit := v[:i], v[i:]
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	switch unit {
	case "", "px":
		// Unitless non-zero lengths are invalid CSS, but quirks mode
		// (most mail has no doctype) reads them as px; so do we.
		return f, true
	case "pt":
		return f * 4 / 3, true
	case "pc":
		return f * 16, true
	case "in":
		return f * 96, true
	case "cm":
		return f * 96 / 2.54, true
	case "mm":
		return f * 96 / 25.4, true
	case "q":
		return f * 96 / 101.6, true
	case "em":
		return f * base, true
	case "rem":
		return f * 16, true
	case "ex", "ch":
		return f * base / 2, true
	case "%":
		return f * base / 100, true
	}
	if f == 0 {
		return 0, true // 0vw, 0vh … are still zero
	}
	return 0, false
}

// cssAtMost reports whether v is a length ≤ max px (with 1em = 16px).
func cssAtMost(v string, max float64) bool {
	px, ok := cssLength(v, 16)
	return ok && px <= max
}

// cssNumber parses a plain number (opacity, scale factors).
func cssNumber(v string) (float64, bool) {
	v = strings.TrimSpace(v)
	pct := strings.HasSuffix(v, "%")
	v = strings.TrimSuffix(v, "%")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(f) {
		return 0, false
	}
	if pct {
		f /= 100
	}
	return f, true
}

// fontSizePx resolves a font-size value against the parent size.
func fontSizePx(v string, parent float64) (float64, bool) {
	switch v {
	case "xx-small":
		return 9, true
	case "x-small":
		return 10, true
	case "small":
		return 13, true
	case "medium":
		return 16, true
	case "large":
		return 18, true
	case "x-large":
		return 24, true
	case "xx-large":
		return 32, true
	case "xxx-large":
		return 48, true
	case "smaller":
		return parent / 1.2, true
	case "larger":
		return parent * 1.2, true
	}
	return cssLength(v, parent)
}

// fontShorthandSize extracts the size from a `font:` shorthand
// ("italic bold 0/0 a", "12px arial", "0/0 a" …).
func fontShorthandSize(v string) (string, bool) {
	for _, tok := range strings.Fields(v) {
		size, _, _ := strings.Cut(tok, "/")
		switch size {
		case "0", "xx-small", "x-small", "small", "medium", "large", "x-large", "xx-large", "xxx-large", "smaller", "larger":
			return size, true
		case "":
			continue
		}
		if !(size[0] >= '0' && size[0] <= '9' || size[0] == '.') {
			continue // style / variant / weight keyword or family
		}
		if _, err := strconv.ParseFloat(size, 64); err == nil {
			continue // unitless number = font-weight, not a size
		}
		return size, true
	}
	return "", false
}

// --- colors --------------------------------------------------------------

// rgba is a parsed color; a is 0..1.
type rgba struct {
	r, g, b float64
	a       float64
}

var namedColors = map[string]rgba{
	"white": {255, 255, 255, 1}, "black": {0, 0, 0, 1}, "red": {255, 0, 0, 1},
	"green": {0, 128, 0, 1}, "blue": {0, 0, 255, 1}, "yellow": {255, 255, 0, 1},
	"gray": {128, 128, 128, 1}, "grey": {128, 128, 128, 1}, "silver": {192, 192, 192, 1},
	"whitesmoke": {245, 245, 245, 1}, "snow": {255, 250, 250, 1}, "ivory": {255, 255, 240, 1},
	"ghostwhite": {248, 248, 255, 1}, "floralwhite": {255, 250, 240, 1}, "azure": {240, 255, 255, 1},
	"mintcream": {245, 255, 250, 1}, "aliceblue": {240, 248, 255, 1}, "seashell": {255, 245, 238, 1},
	"linen": {250, 240, 230, 1}, "honeydew": {240, 255, 240, 1}, "lavenderblush": {255, 240, 245, 1},
	"oldlace": {253, 245, 230, 1}, "beige": {245, 245, 220, 1}, "lightyellow": {255, 255, 224, 1},
	"cornsilk": {255, 248, 220, 1}, "gainsboro": {220, 220, 220, 1}, "lightgray": {211, 211, 211, 1},
	"lightgrey": {211, 211, 211, 1}, "navy": {0, 0, 128, 1}, "maroon": {128, 0, 0, 1},
	"purple": {128, 0, 128, 1}, "teal": {0, 128, 128, 1}, "olive": {128, 128, 0, 1},
	"lime": {0, 255, 0, 1}, "aqua": {0, 255, 255, 1}, "cyan": {0, 255, 255, 1},
	"fuchsia": {255, 0, 255, 1}, "magenta": {255, 0, 255, 1}, "orange": {255, 165, 0, 1},
	"transparent": {0, 0, 0, 0},
}

// parseColor parses #rgb, #rgba, #rrggbb, #rrggbbaa, rgb()/rgba(),
// hsl()/hsla() and a set of named colors. Anything else (currentcolor,
// var(), inherit …) is "unknown" (ok=false).
func parseColor(v string) (rgba, bool) {
	v = strings.TrimSpace(v)
	if c, ok := namedColors[v]; ok {
		return c, true
	}
	if strings.HasPrefix(v, "#") {
		return parseHexColor(v[1:])
	}
	open := strings.IndexByte(v, '(')
	if open < 0 || !strings.HasSuffix(v, ")") {
		// Quirks mode accepts a bare hex triplet ("fff", "ffffff").
		if len(v) == 3 || len(v) == 6 {
			return parseHexColor(v)
		}
		return rgba{}, false
	}
	fn := v[:open]
	args := splitArgs(v[open+1 : len(v)-1])
	switch fn {
	case "rgb", "rgba":
		if len(args) < 3 {
			return rgba{}, false
		}
		var c [3]float64
		for i := 0; i < 3; i++ {
			a := args[i]
			if strings.HasSuffix(a, "%") {
				f, ok := cssNumber(a)
				if !ok {
					return rgba{}, false
				}
				c[i] = f * 255
				continue
			}
			f, err := strconv.ParseFloat(a, 64)
			if err != nil {
				return rgba{}, false
			}
			c[i] = f
		}
		alpha := 1.0
		if len(args) >= 4 {
			f, ok := cssNumber(args[3])
			if !ok {
				return rgba{}, false
			}
			alpha = f
		}
		return rgba{clamp255(c[0]), clamp255(c[1]), clamp255(c[2]), clamp01(alpha)}, true
	case "hsl", "hsla":
		if len(args) < 3 {
			return rgba{}, false
		}
		h, err := strconv.ParseFloat(strings.TrimSuffix(args[0], "deg"), 64)
		s, ok1 := cssNumber(args[1])
		l, ok2 := cssNumber(args[2])
		if err != nil || !ok1 || !ok2 {
			return rgba{}, false
		}
		alpha := 1.0
		if len(args) >= 4 {
			f, ok := cssNumber(args[3])
			if !ok {
				return rgba{}, false
			}
			alpha = f
		}
		r, g, b := hslToRGB(h, clamp01(s), clamp01(l))
		return rgba{r, g, b, clamp01(alpha)}, true
	}
	return rgba{}, false
}

func parseHexColor(h string) (rgba, bool) {
	for _, c := range h {
		if !isHex(c) {
			return rgba{}, false
		}
	}
	x := func(s string) float64 {
		n, _ := strconv.ParseUint(s, 16, 8)
		return float64(n)
	}
	switch len(h) {
	case 3, 4:
		c := rgba{x(h[0:1]) * 17, x(h[1:2]) * 17, x(h[2:3]) * 17, 1}
		if len(h) == 4 {
			c.a = x(h[3:4]) * 17 / 255
		}
		return c, true
	case 6, 8:
		c := rgba{x(h[0:2]), x(h[2:4]), x(h[4:6]), 1}
		if len(h) == 8 {
			c.a = x(h[6:8]) / 255
		}
		return c, true
	}
	return rgba{}, false
}

func hslToRGB(h, s, l float64) (float64, float64, float64) {
	h = math.Mod(math.Mod(h, 360)+360, 360) / 360
	if s == 0 {
		return l * 255, l * 255, l * 255
	}
	q := l * (1 + s)
	if l >= 0.5 {
		q = l + s - l*s
	}
	p := 2*l - q
	hue := func(t float64) float64 {
		if t < 0 {
			t++
		}
		if t > 1 {
			t--
		}
		switch {
		case t < 1.0/6:
			return p + (q-p)*6*t
		case t < 0.5:
			return q
		case t < 2.0/3:
			return p + (q-p)*(2.0/3-t)*6
		}
		return p
	}
	return hue(h+1.0/3) * 255, hue(h) * 255, hue(h-1.0/3) * 255
}

func clamp255(f float64) float64 { return math.Max(0, math.Min(255, f)) }
func clamp01(f float64) float64  { return math.Max(0, math.Min(1, f)) }

// splitArgs splits a CSS function's arguments on commas, slashes and
// spaces ("0,0,0,0", "0 0 0 / 0", "255, 255, 255, 0").
func splitArgs(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '/' || r == ' ' })
}

// colorTooFaint: alpha this low is invisible whatever is underneath.
const colorTooFaint = 0.1

// colorsIndistinguishable reports whether text in fg can't be told
// apart from a bg background (white-on-white and near misses such as
// #fefefe on #fff).
func colorsIndistinguishable(fg, bg rgba) bool {
	const tol = 10
	return math.Abs(fg.r-bg.r) <= tol && math.Abs(fg.g-bg.g) <= tol && math.Abs(fg.b-bg.b) <= tol
}

// backgroundOf returns the background a declaration list paints:
// set=false when it declares none (or only a transparent one), known=
// false when it paints something we can't evaluate (an image, a
// gradient, a semi-transparent color).
func backgroundOf(d cssDecls) (c rgba, set, known bool) {
	for _, k := range []string{"background", "background-color", "background-image"} {
		v, ok := d[k]
		if !ok {
			continue
		}
		if strings.Contains(v, "url(") || strings.Contains(v, "gradient(") || strings.Contains(v, "image(") {
			return rgba{}, true, false
		}
	}
	v, ok := d["background-color"]
	if !ok {
		bgv, ok2 := d["background"]
		if !ok2 {
			return rgba{}, false, false
		}
		// Find a color token in the shorthand.
		found := false
		for _, tok := range splitTopLevel(bgv) {
			if _, ok := parseColor(tok); ok {
				v, found = tok, true
				break
			}
		}
		if !found {
			return rgba{}, false, false
		}
	}
	col, ok := parseColor(v)
	switch {
	case !ok:
		return rgba{}, true, false
	case col.a < colorTooFaint:
		return rgba{}, false, false
	case col.a < 0.9:
		return rgba{}, true, false
	}
	return col, true, true
}

// splitTopLevel splits on spaces outside parentheses.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ' ':
			if depth == 0 {
				if i > start {
					out = append(out, s[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// --- the hiding checks ---------------------------------------------------

// offscreenPx: an element pushed further than this out of its box is
// treated as off-screen.
const offscreenPx = 500

// declsHide reports whether a declaration list hides its element (and
// everything inside it) outright. Text color and font size are
// inherited — a child can undo them — so they are evaluated per text
// node instead (see visible.go).
func declsHide(d cssDecls) bool {
	if len(d) == 0 {
		return false
	}
	if d["display"] == "none" {
		return true
	}
	switch d["visibility"] {
	case "hidden", "collapse":
		return true
	}
	if d["content-visibility"] == "hidden" {
		return true
	}
	if v, ok := d["opacity"]; ok {
		if f, ok := cssNumber(v); ok && f <= 0.05 {
			return true
		}
	}

	clipped := false
	for _, k := range []string{"overflow", "overflow-x", "overflow-y"} {
		for _, tok := range strings.Fields(d[k]) {
			if tok == "hidden" || tok == "clip" {
				clipped = true
			}
		}
	}
	zeroBox := false
	for _, k := range []string{"max-height", "height", "max-width", "width"} {
		if v, ok := d[k]; ok && cssAtMost(v, 1) {
			zeroBox = true
		}
	}
	lineZero := false
	if v, ok := d["line-height"]; ok && cssAtMost(v, 0) {
		lineZero = true
	}
	if clipped && (zeroBox || lineZero) {
		return true
	}
	if lineZero && (cssAtMostKey(d, "max-height", 0) || cssAtMostKey(d, "height", 0)) {
		return true
	}

	if v, ok := d["text-indent"]; ok {
		if px, ok := cssLength(v, 16*10); ok && px <= -100 {
			return true
		}
	}
	switch d["position"] {
	case "absolute", "fixed":
		for _, k := range []string{"left", "top", "right", "bottom"} {
			if px, ok := cssLength(d[k], 16*10); ok && (px <= -offscreenPx || px >= 10*offscreenPx) {
				return true
			}
		}
		if v, ok := d["clip"]; ok && clipRectHides(v) {
			return true
		}
	}
	for _, k := range []string{"margin-left", "margin-top", "margin-right"} {
		if px, ok := cssLength(d[k], 16*10); ok && px <= -offscreenPx {
			return true
		}
	}
	if v, ok := d["margin"]; ok {
		for _, tok := range strings.Fields(v) {
			if px, ok := cssLength(tok, 16*10); ok && px <= -offscreenPx {
				return true
			}
		}
	}
	if v, ok := d["clip-path"]; ok && clipPathHides(v) {
		return true
	}
	if v, ok := d["transform"]; ok && transformHides(v) {
		return true
	}
	if v, ok := d["scale"]; ok {
		for _, tok := range strings.Fields(v) {
			if f, ok := cssNumber(tok); ok && f == 0 {
				return true
			}
		}
	}
	return false
}

func cssAtMostKey(d cssDecls, k string, max float64) bool {
	v, ok := d[k]
	return ok && cssAtMost(v, max)
}

// clipRectHides: clip:rect(0,0,0,0) / rect(1px 1px 1px 1px) — every
// edge within a pixel, or a box with no area.
func clipRectHides(v string) bool {
	if !strings.HasPrefix(v, "rect(") || !strings.HasSuffix(v, ")") {
		return false
	}
	args := splitArgs(v[5 : len(v)-1])
	if len(args) != 4 {
		return false
	}
	var px [4]float64
	for i, a := range args {
		if a == "auto" {
			return false
		}
		f, ok := cssLength(a, 16)
		if !ok {
			return false
		}
		px[i] = f
	}
	// rect(top, right, bottom, left)
	return px[2]-px[0] <= 1 || px[1]-px[3] <= 1
}

// clipPathHides: inset(≥50%), circle(0)/ellipse(0 0), a polygon whose
// points are all the same.
func clipPathHides(v string) bool {
	open := strings.IndexByte(v, '(')
	if open < 0 || !strings.HasSuffix(v, ")") {
		return false
	}
	fn, inner := v[:open], v[open+1:len(v)-1]
	if i := strings.Index(inner, " at "); i >= 0 {
		inner = inner[:i]
	}
	if i := strings.Index(inner, "round"); i >= 0 {
		inner = inner[:i]
	}
	args := splitArgs(inner)
	switch fn {
	case "inset":
		for _, a := range args {
			if strings.HasSuffix(a, "%") {
				if f, ok := cssNumber(a); ok && f >= 0.5 {
					return true
				}
			}
		}
	case "circle", "ellipse":
		if len(args) == 0 {
			return false
		}
		for _, a := range args {
			if !cssAtMost(a, 0.5) {
				return false
			}
		}
		return true
	case "polygon":
		if len(args) == 0 {
			return false
		}
		first := ""
		for _, a := range args {
			if a == "nonzero" || a == "evenodd" {
				continue
			}
			if first == "" {
				first = a
			}
			if a != first {
				return false
			}
		}
		return true
	}
	return false
}

// transformHides: any scale*() with a zero factor, a degenerate
// matrix, or a translate far off-screen.
func transformHides(v string) bool {
	for v != "" {
		open := strings.IndexByte(v, '(')
		if open < 0 {
			return false
		}
		closeIdx := strings.IndexByte(v[open:], ')')
		if closeIdx < 0 {
			return false
		}
		fn := strings.TrimSpace(v[:open])
		args := splitArgs(v[open+1 : open+closeIdx])
		v = v[open+closeIdx+1:]
		switch fn {
		case "scale", "scalex", "scaley", "scale3d":
			for _, a := range args {
				if f, ok := cssNumber(a); ok && f == 0 {
					return true
				}
			}
		case "matrix", "matrix3d":
			nums := make([]float64, 0, len(args))
			for _, a := range args {
				f, err := strconv.ParseFloat(a, 64)
				if err != nil {
					break
				}
				nums = append(nums, f)
			}
			if fn == "matrix" && len(nums) == 6 && (nums[0] == 0 && nums[1] == 0 || nums[2] == 0 && nums[3] == 0) {
				return true
			}
			if fn == "matrix3d" && len(nums) == 16 && (nums[0] == 0 && nums[1] == 0 || nums[4] == 0 && nums[5] == 0) {
				return true
			}
		case "translate", "translatex", "translatey", "translate3d":
			for _, a := range args {
				if px, ok := cssLength(a, 16*10); ok && (px <= -offscreenPx || px >= 10*offscreenPx) {
					return true
				}
			}
		}
	}
	return false
}

// --- <style> blocks -------------------------------------------------------

// cssRule is one simple-selector rule from a <style> block. Only the
// selector's subject (its last compound: tag, #id, .class …) is kept
// — see parseStylesheet.
type cssRule struct {
	order   int
	tag     string
	id      string
	classes []string
	decls   cssDecls
}

// stylesheet indexes rules by their most selective key.
type stylesheet struct {
	byKey map[string][]*cssRule
	n     int
}

const (
	maxStylesheetBytes = 1 << 20
	maxStylesheetRules = 5000
)

// parseStylesheet adds the rules of one <style> block to ss.
//
// Supported: rules whose selectors (comma lists allowed) end in a
// simple compound — tag, .class, #id, tag.class, .a.b, tag#id. A
// selector with combinators ("div > .x", ".a .b") is matched on its
// subject compound alone, ignoring the ancestors: that may hide a
// little more than a browser would, never less. Selectors whose
// subject uses attribute selectors, pseudo-classes/elements or the
// universal selector are ignored, as is any rule past the size caps.
//
// At-rules: @media / @supports / @container / @layer / @document
// blocks are descended into and their rules treated as always
// applying (conservative — content hidden on any viewport is dropped).
// Other at-rules (@font-face, @keyframes, @import …) are skipped.
func (ss *stylesheet) parse(css string) {
	if len(css) > maxStylesheetBytes {
		css = css[:maxStylesheetBytes]
	}
	css = strings.NewReplacer("<!--", " ", "-->", " ").Replace(css)
	ss.parseNormalized(normalizeCSS(css), 0)
}

func (ss *stylesheet) parseNormalized(s string, depth int) {
	if depth > 8 {
		return
	}
	for len(s) > 0 && ss.n < maxStylesheetRules {
		s = strings.TrimLeft(s, " ;}")
		if s == "" {
			return
		}
		brace := strings.IndexByte(s, '{')
		if s[0] == '@' {
			semi := strings.IndexByte(s, ';')
			if brace < 0 || (semi >= 0 && semi < brace) {
				if semi < 0 {
					return
				}
				s = s[semi+1:]
				continue
			}
			name := strings.Fields(s[1:brace])
			end := matchBrace(s, brace)
			body := s[brace+1 : end]
			if len(name) > 0 {
				switch strings.TrimPrefix(strings.TrimPrefix(name[0], "-moz-"), "-webkit-") {
				case "media", "supports", "container", "layer", "document", "scope":
					ss.parseNormalized(body, depth+1)
				}
			}
			if end >= len(s) {
				return
			}
			s = s[end+1:]
			continue
		}
		if brace < 0 {
			return
		}
		end := matchBrace(s, brace)
		selectors := s[:brace]
		body := s[brace+1 : end]
		if end >= len(s) {
			s = ""
		} else {
			s = s[end+1:]
		}
		// Nested blocks (CSS nesting) are ignored.
		if strings.ContainsRune(body, '{') {
			body = stripNestedBlocks(body)
		}
		decls := parseNormalizedDecls(body)
		if len(decls) == 0 {
			continue
		}
		for _, sel := range strings.Split(selectors, ",") {
			ss.add(sel, decls)
		}
	}
}

// matchBrace returns the index of the '}' matching s[open] ('{'), or
// len(s) when unbalanced.
func matchBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(s)
}

func stripNestedBlocks(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
			continue
		case '}':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth == 0 {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func (ss *stylesheet) add(sel string, decls cssDecls) {
	sel = strings.NewReplacer(">", " ", "+", " ", "~", " ").Replace(sel)
	parts := strings.Fields(sel)
	if len(parts) == 0 {
		return
	}
	subj := parts[len(parts)-1]
	if strings.ContainsAny(subj, ":[]*()|\\\"'") {
		return
	}
	r := &cssRule{order: ss.n, decls: decls}
	i := 0
	for i < len(subj) && subj[i] != '.' && subj[i] != '#' {
		i++
	}
	r.tag = subj[:i]
	rest := subj[i:]
	for rest != "" {
		kind := rest[0]
		j := 1
		for j < len(rest) && rest[j] != '.' && rest[j] != '#' {
			j++
		}
		name := rest[1:j]
		rest = rest[j:]
		if name == "" {
			return
		}
		if kind == '#' {
			if r.id != "" && r.id != name {
				return // can never match
			}
			r.id = name
		} else {
			r.classes = append(r.classes, name)
		}
	}
	key := ""
	switch {
	case r.id != "":
		key = "#" + r.id
	case len(r.classes) > 0:
		key = "." + r.classes[0]
	case r.tag != "":
		key = r.tag
	default:
		return
	}
	if ss.byKey == nil {
		ss.byKey = map[string][]*cssRule{}
	}
	ss.byKey[key] = append(ss.byKey[key], r)
	ss.n++
}

// maxClassesLooked bounds per-element work for a class="…" with
// thousands of names.
const maxClassesLooked = 64

// match returns the declarations of the rules matching an element, in
// source order (later rules win on conflicts, ignoring specificity).
// nil when nothing matches.
func (ss *stylesheet) match(tag, id string, classes []string) cssDecls {
	if ss == nil || ss.n == 0 {
		return nil
	}
	var cands []*cssRule
	cands = append(cands, ss.byKey[tag]...)
	if id != "" {
		cands = append(cands, ss.byKey["#"+id]...)
	}
	if len(classes) > maxClassesLooked {
		classes = classes[:maxClassesLooked]
	}
	for _, c := range classes {
		cands = append(cands, ss.byKey["."+c]...)
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].order < cands[j].order })
	var out cssDecls
	last := -1
	for _, r := range cands {
		if r.order == last {
			continue // listed under two keys
		}
		last = r.order
		if r.tag != "" && r.tag != tag {
			continue
		}
		if r.id != "" && r.id != id {
			continue
		}
		ok := true
		for _, want := range r.classes {
			found := false
			for _, c := range classes {
				if c == want {
					found = true
					break
				}
			}
			if !found {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if out == nil {
			out = cssDecls{}
		}
		for k, v := range r.decls {
			out[k] = v
		}
	}
	return out
}
