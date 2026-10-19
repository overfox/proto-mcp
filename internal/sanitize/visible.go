package sanitize

import (
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Visible-text extraction (assessment M6).
//
// Text handed to the model must be text a person reading the mail
// would actually see. The input is parsed with the HTML5 algorithm
// (golang.org/x/net/html) so element nesting matches what a browser
// builds, even for malformed markup; then pruneInvisible removes, with
// everything inside them:
//
//   - comments (incl. Outlook conditional comments "<!--[if mso]>")
//     — downlevel-revealed "<![if !mso]>" markers are bogus comments
//     whose following content is ordinary, visible markup;
//   - elements that never render text: script, style, template,
//     noscript, title, head, iframe, object, embed, svg, math, …;
//   - elements hidden by attribute (hidden, aria-hidden="true",
//     <font size="0">, a closed <dialog>, the non-summary part of a
//     closed <details>);
//   - elements hidden by CSS — inline style="" plus simple <style>
//     rules (see stylesheet.parse): display:none, visibility:hidden,
//     opacity:0, zero-size / zero line-height boxes with overflow
//     hidden, large negative text-indent, off-screen positioning or
//     margins, clip / clip-path that leave nothing, transform scale(0)
//     (declsHide);
//   - text nodes whose effective (inherited) style makes them
//     invisible: transparent or near-transparent color, a color
//     indistinguishable from the nearest declared background (default
//     white), or a font size of 1px or less.
//
// Attribute values (alt, title, value, href …) are never emitted.

// nonRendered elements never put their contents on screen in a mail
// client.
var nonRendered = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Template: true, atom.Noscript: true,
	atom.Title: true, atom.Head: true, atom.Iframe: true, atom.Object: true,
	atom.Embed: true, atom.Svg: true, atom.Math: true, atom.Noembed: true,
	atom.Noframes: true, atom.Frameset: true, atom.Frame: true, atom.Audio: true,
	atom.Video: true, atom.Canvas: true, atom.Applet: true, atom.Param: true,
	atom.Source: true, atom.Track: true, atom.Datalist: true, atom.Meta: true,
	atom.Link: true, atom.Base: true,
}

// blockElements start and end a line in the extracted text.
var blockElements = map[atom.Atom]bool{
	atom.Address: true, atom.Article: true, atom.Aside: true, atom.Blockquote: true,
	atom.Body: true, atom.Center: true, atom.Dd: true, atom.Details: true,
	atom.Dialog: true, atom.Dir: true, atom.Div: true, atom.Dl: true, atom.Dt: true,
	atom.Fieldset: true, atom.Figcaption: true, atom.Figure: true, atom.Footer: true,
	atom.Form: true, atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true,
	atom.H5: true, atom.H6: true, atom.Header: true, atom.Hgroup: true, atom.Hr: true,
	atom.Html: true, atom.Legend: true, atom.Li: true, atom.Main: true, atom.Menu: true,
	atom.Nav: true, atom.Ol: true, atom.P: true, atom.Pre: true, atom.Section: true,
	atom.Summary: true, atom.Table: true, atom.Tbody: true, atom.Thead: true,
	atom.Tfoot: true, atom.Tr: true, atom.Caption: true, atom.Ul: true,
	atom.Option: true, atom.Optgroup: true, atom.Textarea: true, atom.Select: true,
	atom.Listing: true, atom.Plaintext: true, atom.Xmp: true,
}

// preformatted elements keep their whitespace.
var preformatted = map[atom.Atom]bool{
	atom.Pre: true, atom.Textarea: true, atom.Listing: true, atom.Plaintext: true, atom.Xmp: true,
}

// visCtx is the inherited rendering state at a node.
type visCtx struct {
	color      rgba
	colorKnown bool
	bg         rgba
	bgKnown    bool
	fontPx     float64
	fontKnown  bool
}

// rootCtx: black text on a white page at 16px — what a mail client
// shows when the message declares nothing.
var rootCtx = visCtx{
	color: rgba{0, 0, 0, 1}, colorKnown: true,
	bg: rgba{255, 255, 255, 1}, bgKnown: true,
	fontPx: 16, fontKnown: true,
}

// textVisible reports whether text rendered in ctx can be seen.
func (c visCtx) textVisible() bool {
	if c.colorKnown {
		if c.color.a < colorTooFaint {
			return false
		}
		if c.bgKnown && colorsIndistinguishable(c.color, c.bg) {
			return false
		}
	}
	if c.fontKnown && c.fontPx <= 1 {
		return false
	}
	return true
}

// unparseableNotice replaces a body the HTML parser rejects (it caps
// element nesting at 512). Failing closed: without a tree we can't
// tell visible from hidden text.
const unparseableNotice = "[message HTML could not be parsed safely (nesting too deep); open it in Proton Mail to read it]"

// parsedDoc is a parsed, pruned document.
type parsedDoc struct {
	root *html.Node
	// markup is false when the input was plain text (no elements
	// beyond the implied html/head/body): its newlines are kept.
	markup bool
	// changed reports whether pruning removed anything.
	changed bool
}

// parseVisible parses input and removes everything a reader wouldn't
// see. ok=false when the parser fails (it practically never does).
func parseVisible(input string) (parsedDoc, bool) {
	root, err := html.Parse(strings.NewReader(input))
	if err != nil {
		return parsedDoc{}, false
	}
	d := parsedDoc{root: root}
	ss := collectStyles(root)
	d.changed, d.markup = pruneInvisible(root, ss)
	return d, true
}

// collectStyles gathers every <style> element's rules (not those
// inside an inert <template>).
func collectStyles(root *html.Node) *stylesheet {
	ss := &stylesheet{}
	stack := []*html.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Type == html.ElementNode {
			switch n.DataAtom {
			case atom.Template:
				continue
			case atom.Style:
				var b strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						b.WriteString(c.Data)
					}
				}
				ss.parse(b.String())
				continue
			}
		}
		for c := n.LastChild; c != nil; c = c.PrevSibling {
			stack = append(stack, c)
		}
	}
	return ss
}

// pruneInvisible removes invisible content under root (iteratively —
// adversarial mail can nest hundreds of thousands of elements).
// Reports whether anything was removed and whether the document has
// any real markup.
func pruneInvisible(root *html.Node, ss *stylesheet) (changed, markup bool) {
	type item struct {
		n   *html.Node
		ctx visCtx
	}
	stack := []item{{root, rootCtx}}
	remove := func(n *html.Node) {
		if n.Parent != nil {
			n.Parent.RemoveChild(n)
			changed = true
		}
	}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n, ctx := it.n, it.ctx
		switch n.Type {
		case html.CommentNode, html.DoctypeNode:
			remove(n)
			continue
		case html.TextNode:
			if !ctx.textVisible() && strings.TrimSpace(n.Data) != "" {
				remove(n)
			}
			continue
		case html.ElementNode:
			switch n.DataAtom {
			case atom.Html, atom.Body:
			case atom.Head:
				if n.FirstChild == nil {
					continue // the parser's implied, empty <head>
				}
			default:
				markup = true
			}
			if nonRendered[n.DataAtom] || n.Namespace != "" {
				remove(n)
				continue
			}
			var hide bool
			ctx, hide = elementCtx(n, ctx, ss)
			if hide {
				remove(n)
				continue
			}
			if n.DataAtom == atom.Details && !hasAttr(n, "open") {
				pruneClosedDetails(n)
				changed = true
			}
		}
		for c := n.LastChild; c != nil; c = c.PrevSibling {
			stack = append(stack, item{c, ctx})
		}
	}
	return changed, markup
}

// pruneClosedDetails keeps only the first <summary> of a closed
// <details> — the rest isn't shown until the reader opens it.
func pruneClosedDetails(n *html.Node) {
	var keep *html.Node
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.DataAtom == atom.Summary {
			keep = c
			break
		}
	}
	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		if c != keep {
			n.RemoveChild(c)
		}
		c = next
	}
}

func hasAttr(n *html.Node, key string) bool {
	_, ok := attr(n, key)
	return ok
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Namespace == "" && strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

// fontSizeAttr maps <font size="N"> (absolute 1–7, or relative ±N
// from 3) to pixels; px<=0 means "size 0" — treated as hidden.
func fontSizeAttr(v string) (px float64, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(v, "+"))
	if err != nil {
		return 0, false
	}
	if v[0] == '+' || v[0] == '-' {
		n += 3
	}
	sizes := []float64{0, 10, 13, 16, 18, 24, 32, 48}
	switch {
	case n <= 0:
		return 0, true
	case n >= len(sizes):
		return 48, true
	}
	return sizes[n], true
}

// elementCtx decides whether element n is hidden and, if not, the
// rendering state its children inherit.
func elementCtx(n *html.Node, parent visCtx, ss *stylesheet) (visCtx, bool) {
	if hasAttr(n, "hidden") {
		return parent, true
	}
	if v, ok := attr(n, "aria-hidden"); ok && strings.EqualFold(strings.TrimSpace(v), "true") {
		return parent, true
	}
	if n.DataAtom == atom.Dialog && !hasAttr(n, "open") {
		return parent, true
	}
	ctx := parent

	// Presentational attributes.
	switch n.DataAtom {
	case atom.Font:
		if v, ok := attr(n, "size"); ok {
			if px, ok := fontSizeAttr(v); ok {
				if px <= 0 {
					return parent, true
				}
				ctx.fontPx, ctx.fontKnown = px, true
			}
		}
		if v, ok := attr(n, "color"); ok {
			ctx.color, ctx.colorKnown = parseColor(normalizeCSS(v))
		}
	case atom.A:
		// Links don't inherit the text color.
		ctx.color, ctx.colorKnown = rgba{0, 0, 238, 1}, true
	}
	if v, ok := attr(n, "bgcolor"); ok {
		if c, ok := parseColor(normalizeCSS(v)); ok {
			if c.a >= 0.9 {
				ctx.bg, ctx.bgKnown = c, true
			} else if c.a >= colorTooFaint {
				ctx.bgKnown = false
			}
		} else {
			ctx.bgKnown = false
		}
	}
	if v, ok := attr(n, "background"); ok && strings.TrimSpace(v) != "" {
		ctx.bgKnown = false
	}

	// CSS: matching <style> rules, then the inline style attribute.
	var classes []string
	if v, ok := attr(n, "class"); ok {
		classes = strings.Fields(strings.ToLower(v))
	}
	id, _ := attr(n, "id")
	rules := ss.match(n.Data, strings.ToLower(strings.TrimSpace(id)), classes)
	decls := rules
	if v, ok := attr(n, "style"); ok {
		inline := parseDecls(v)
		if len(rules) > 0 {
			merged := make(cssDecls, len(rules)+len(inline))
			for k, v := range rules {
				merged[k] = v
			}
			for k, v := range inline {
				merged[k] = v
			}
			decls = merged
		} else {
			decls = inline
		}
	}
	// A <style> rule that hides counts even if an inline style seems
	// to undo it (we don't model !important / specificity).
	if declsHide(rules) || declsHide(decls) {
		return parent, true
	}
	if len(decls) == 0 {
		return ctx, false
	}
	if c, set, known := backgroundOf(decls); set {
		ctx.bg, ctx.bgKnown = c, known
	}
	colorVal, hasColor := decls["-webkit-text-fill-color"]
	if !hasColor {
		colorVal, hasColor = decls["color"]
	}
	if hasColor {
		switch colorVal {
		case "inherit", "currentcolor":
		default:
			ctx.color, ctx.colorKnown = parseColor(colorVal)
		}
	}
	size, hasSize := decls["font-size"]
	if !hasSize {
		if f, ok := decls["font"]; ok {
			size, hasSize = fontShorthandSize(f)
		}
	}
	if hasSize && size != "inherit" {
		if px, ok := fontSizePx(size, parent.fontPx); ok && (parent.fontKnown || !relativeFontSize(size)) {
			ctx.fontPx, ctx.fontKnown = px, true
		} else {
			ctx.fontKnown = false
		}
	}
	return ctx, false
}

// relativeFontSize reports whether a font-size value depends on the
// parent's size.
func relativeFontSize(v string) bool {
	switch {
	case strings.HasSuffix(v, "rem"):
		return false
	case strings.HasSuffix(v, "em"), strings.HasSuffix(v, "ex"), strings.HasSuffix(v, "ch"),
		strings.HasSuffix(v, "%"), v == "smaller", v == "larger":
		return true
	}
	return false
}

// extractText renders a pruned document as text: text nodes only,
// block elements on their own lines, whitespace collapsed outside
// preformatted elements (for plain-text input newlines are kept).
func extractText(d parsedDoc) string {
	var b strings.Builder
	newline := func() {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteByte('\n')
		}
	}
	type item struct {
		n    *html.Node
		exit bool
		pre  bool
	}
	stack := []item{{n: d.root}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := it.n
		if it.exit {
			if blockElements[n.DataAtom] {
				newline()
			}
			continue
		}
		switch n.Type {
		case html.TextNode:
			switch {
			case it.pre || !d.markup:
				b.WriteString(n.Data)
			default:
				b.WriteString(collapseSpace(n.Data))
			}
			continue
		case html.ElementNode:
			switch n.DataAtom {
			case atom.Br:
				b.WriteByte('\n')
				continue
			case atom.Td, atom.Th, atom.Img:
				b.WriteByte(' ')
			}
			if blockElements[n.DataAtom] {
				newline()
			}
		}
		pre := it.pre || (n.Type == html.ElementNode && preformatted[n.DataAtom])
		stack = append(stack, item{n: n, exit: true})
		for c := n.LastChild; c != nil; c = c.PrevSibling {
			stack = append(stack, item{n: c, pre: pre})
		}
	}
	return b.String()
}

// collapseSpace maps each run of whitespace to one space, as HTML
// rendering does outside <pre>.
func collapseSpace(s string) string {
	if !strings.ContainsFunc(s, unicode.IsSpace) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
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
