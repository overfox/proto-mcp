package store

import (
	"strings"
	"time"
)

// Search DSL v2.
//
// A query is a boolean expression over leaf criteria:
//
//	from:alice              sender address OR display name contains "alice"
//	to:bob  cc:carol        recipient lists contain the value
//	subject:"gear list"     subject contains the (quoted) phrase
//	in:inbox                folder (in:all / any / all_mail / * = no filter)
//	label:<name-or-id>      has the label
//	has:attachment          has attachments
//	is:unread / is:read / is:starred
//	before:/until:  after:/since:   YYYY-MM-DD date bounds
//	bare terms / "quoted phrases"   full-text (subject, sender, recipients, body)
//
// Operators:
//
//	a b           implicit AND
//	a OR b        either (upper-case OR only; lower-case "or" is a term)
//	-a            negation (works on any leaf or group: -from:x, -label:y, -(a OR b))
//	( ... )       grouping
//
// Precedence follows Gmail: OR binds tighter than the implicit AND, so
// `from:a OR from:b subject:x` means (from:a OR from:b) AND subject:x.
// Repeated prefixes AND together (`from:a from:b` requires both) —
// v1 kept only the last one.
//
// Every leaf compiles to a fixed SQL fragment with its value bound as a
// parameter; user input never reaches the SQL text. Full-text leaves
// are phrase-quoted (SECURITY C-9) so FTS5 operators inside a term are
// matched literally.

// queryNode is one node in the parsed expression tree. Exactly one of
// the shapes is used per kind.
type queryNode struct {
	kind     nodeKind
	children []*queryNode // and / or
	child    *queryNode   // not
	leaf     leaf         // leaf
}

type nodeKind int

const (
	nodeAnd nodeKind = iota
	nodeOr
	nodeNot
	nodeLeaf
)

// leafKind enumerates the criteria a leaf can test.
type leafKind int

const (
	leafFTS leafKind = iota
	leafFrom
	leafTo
	leafCc
	leafSubject
	leafFolder
	leafLabel
	leafHasAttachment
	leafUnread
	leafRead
	leafStarred
	leafBefore
	leafAfter
)

type leaf struct {
	kind  leafKind
	value string    // text value (FTS term, LIKE substring, folder, label)
	date  time.Time // before / after
}

// Parser limits. Queries come from an LLM tool call; these bound the
// work (and the SQL size) a pathological query can cause.
const (
	maxQueryTokens = 200
	maxQueryDepth  = 16
)

// queryToken is one lexical token. quoted tokens are always literal
// (a quoted "OR" or "-x" is a search term, not an operator).
type queryToken struct {
	text   string
	quoted bool
	paren  byte // '(' or ')' for grouping tokens, else 0
}

// parseQuery parses the DSL into an expression tree. Returns nil for
// an empty query (no criteria). Parsing is lenient by design: unknown
// prefixes become full-text terms, unparsable dates are dropped,
// unbalanced parentheses are tolerated.
func parseQuery(input string) *queryNode {
	toks := tokenizeQuery(input)
	if len(toks) > maxQueryTokens {
		toks = toks[:maxQueryTokens]
	}
	p := &queryParser{toks: toks}
	n := p.parseAnd(0)
	return simplify(n)
}

type queryParser struct {
	toks []queryToken
	pos  int
}

func (p *queryParser) peek() (queryToken, bool) {
	if p.pos >= len(p.toks) {
		return queryToken{}, false
	}
	return p.toks[p.pos], true
}

func isOr(t queryToken) bool { return !t.quoted && t.paren == 0 && t.text == "OR" }

// parseAnd: or-expr+ until end or a closing paren.
func (p *queryParser) parseAnd(depth int) *queryNode {
	and := &queryNode{kind: nodeAnd}
	for {
		t, ok := p.peek()
		if !ok {
			break
		}
		if t.paren == ')' {
			if depth > 0 {
				break
			}
			p.pos++ // stray ')' at top level: ignore
			continue
		}
		if isOr(t) {
			p.pos++ // dangling OR with no left operand: ignore
			continue
		}
		if n := p.parseOr(depth); n != nil {
			and.children = append(and.children, n)
		}
	}
	return and
}

// parseOr: unary ("OR" unary)*
func (p *queryParser) parseOr(depth int) *queryNode {
	first := p.parseUnary(depth)
	or := &queryNode{kind: nodeOr}
	if first != nil {
		or.children = append(or.children, first)
	}
	for {
		t, ok := p.peek()
		if !ok || !isOr(t) {
			break
		}
		p.pos++
		if next := p.parseUnary(depth); next != nil {
			or.children = append(or.children, next)
		}
	}
	switch len(or.children) {
	case 0:
		return nil
	case 1:
		return or.children[0]
	}
	return or
}

// parseUnary: "-" unary | "(" and ")" | leaf
func (p *queryParser) parseUnary(depth int) *queryNode {
	t, ok := p.peek()
	if !ok || t.paren == ')' || isOr(t) {
		return nil
	}
	p.pos++

	if t.paren == '(' {
		if depth >= maxQueryDepth {
			// Too deep: treat the group's contents as part of the
			// enclosing expression rather than recursing further.
			return nil
		}
		inner := p.parseAnd(depth + 1)
		if nt, ok := p.peek(); ok && nt.paren == ')' {
			p.pos++
		}
		return inner
	}

	if !t.quoted && strings.HasPrefix(t.text, "-") {
		rest := strings.TrimPrefix(t.text, "-")
		var target *queryNode
		if rest == "" {
			// "-" followed by a separate token / group: "- (a b)".
			if depth >= maxQueryDepth {
				return nil
			}
			target = p.parseUnary(depth + 1)
		} else {
			target = leafNode(queryToken{text: rest})
		}
		if target == nil {
			return nil
		}
		return &queryNode{kind: nodeNot, child: target}
	}
	return leafNode(t)
}

// leafNode maps a single token to a leaf. Returns nil when the token
// carries no criterion (e.g. an unparsable date, in:all).
func leafNode(t queryToken) *queryNode {
	mk := func(l leaf) *queryNode { return &queryNode{kind: nodeLeaf, leaf: l} }
	if t.quoted {
		if t.text == "" {
			return nil
		}
		return mk(leaf{kind: leafFTS, value: t.text})
	}
	key, val, hasColon := splitPrefix(t.text)
	if !hasColon {
		if t.text == "" {
			return nil
		}
		return mk(leaf{kind: leafFTS, value: t.text})
	}
	if val == "" {
		// "from:" with nothing after it — no criterion.
		return nil
	}
	switch strings.ToLower(key) {
	case "from":
		return mk(leaf{kind: leafFrom, value: val})
	case "to":
		return mk(leaf{kind: leafTo, value: val})
	case "cc":
		return mk(leaf{kind: leafCc, value: val})
	case "subject":
		return mk(leaf{kind: leafSubject, value: val})
	case "in":
		lower := strings.ToLower(val)
		// D1/D2: "in:all" is the DSL form of folder="all" — no filter.
		switch lower {
		case "all", "any", "all_mail", "*":
			return nil
		}
		return mk(leaf{kind: leafFolder, value: lower})
	case "label":
		// label_id OR label name (case-insensitive), resolved in SQL.
		return mk(leaf{kind: leafLabel, value: val})
	case "has":
		if strings.EqualFold(val, "attachment") || strings.EqualFold(val, "attachments") {
			return mk(leaf{kind: leafHasAttachment})
		}
	case "is":
		switch strings.ToLower(val) {
		case "unread":
			return mk(leaf{kind: leafUnread})
		case "read":
			return mk(leaf{kind: leafRead})
		case "starred":
			return mk(leaf{kind: leafStarred})
		}
	case "before", "until":
		// D3: "until" aliases "before".
		if d, ok := parseSearchDate(val); ok {
			return mk(leaf{kind: leafBefore, date: d})
		}
		return nil
	case "after", "since":
		// D3: "since" aliases "after".
		if d, ok := parseSearchDate(val); ok {
			return mk(leaf{kind: leafAfter, date: d})
		}
		return nil
	}
	// Unknown prefix (or unknown has:/is: value) → the whole token is
	// a full-text term. Better UX than silently dropping.
	return mk(leaf{kind: leafFTS, value: t.text})
}

// simplify flattens single-child groups and drops empty ones. Returns
// nil when nothing is left.
func simplify(n *queryNode) *queryNode {
	if n == nil {
		return nil
	}
	switch n.kind {
	case nodeAnd, nodeOr:
		kept := n.children[:0]
		for _, c := range n.children {
			if c = simplify(c); c != nil {
				kept = append(kept, c)
			}
		}
		n.children = kept
		switch len(kept) {
		case 0:
			return nil
		case 1:
			return kept[0]
		}
		return n
	case nodeNot:
		n.child = simplify(n.child)
		if n.child == nil {
			return nil
		}
		return n
	}
	return n
}

// compiledQuery is the SQL form of a parsed query.
type compiledQuery struct {
	where string // "" = no criteria
	args  []any
	// rankTerms are the phrase-quoted positive full-text terms (not
	// under a NOT), OR-joined into one MATCH for bm25 ordering.
	rankTerms []string
}

// compileQuery turns the tree into a WHERE fragment over `messages`.
func compileQuery(n *queryNode) compiledQuery {
	var c compiledQuery
	if n == nil {
		return c
	}
	c.where = c.compile(n, false)
	return c
}

func (c *compiledQuery) compile(n *queryNode, negated bool) string {
	switch n.kind {
	case nodeAnd, nodeOr:
		op := " AND "
		if n.kind == nodeOr {
			op = " OR "
		}
		parts := make([]string, 0, len(n.children))
		for _, ch := range n.children {
			parts = append(parts, c.compile(ch, negated))
		}
		return "(" + strings.Join(parts, op) + ")"
	case nodeNot:
		return "(NOT " + c.compile(n.child, !negated) + ")"
	}
	l := n.leaf
	switch l.kind {
	case leafFTS:
		q := ftsQuote(l.value)
		if !negated {
			c.rankTerms = append(c.rankTerms, q)
		}
		c.args = append(c.args, q)
		return "messages.id IN (SELECT message_id FROM messages_fts WHERE messages_fts MATCH ?)"
	case leafFrom:
		v := likeContains(l.value)
		c.args = append(c.args, v, v)
		return `(COALESCE(messages.from_address, '') LIKE ? ESCAPE '\' OR COALESCE(messages.from_name, '') LIKE ? ESCAPE '\')`
	case leafTo:
		c.args = append(c.args, likeContains(l.value))
		return `COALESCE(messages.to_json, '') LIKE ? ESCAPE '\'`
	case leafCc:
		c.args = append(c.args, likeContains(l.value))
		return `COALESCE(messages.cc_json, '') LIKE ? ESCAPE '\'`
	case leafSubject:
		c.args = append(c.args, likeContains(l.value))
		return `COALESCE(messages.subject, '') LIKE ? ESCAPE '\'`
	case leafFolder:
		c.args = append(c.args, l.value)
		return "COALESCE(messages.folder, '') = ?"
	case leafLabel:
		c.args = append(c.args, l.value, l.value)
		return `messages.id IN (
			SELECT message_id FROM message_labels
			 WHERE label_id = ?
			    OR label_id IN (SELECT id FROM labels WHERE LOWER(name) = LOWER(?)))`
	case leafHasAttachment:
		return "messages.has_attachments = 1"
	case leafUnread:
		return "messages.unread = 1"
	case leafRead:
		return "messages.unread = 0"
	case leafStarred:
		return "messages.starred = 1"
	case leafBefore:
		c.args = append(c.args, l.date.Unix())
		return "messages.date < ?"
	case leafAfter:
		c.args = append(c.args, l.date.Unix())
		return "messages.date >= ?"
	}
	return "1=1"
}

// likeContains wraps v for a substring LIKE, escaping the LIKE
// wildcards so "50%" or "a_b" match literally (paired with
// ESCAPE '\' in every fragment).
func likeContains(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(v) + "%"
}

// ftsQuote wraps a term in FTS5 phrase-form, escaping embedded
// double-quotes per the FTS5 syntax (a literal " inside a phrase
// is doubled: "" → ").
//
// SECURITY C-9. Phrase-wrapping every term means FTS5 metachars
// (NEAR, ^, *, parentheses, AND/OR/NOT) lose their operator meaning.
// Boolean logic is expressed by the DSL and compiled to SQL instead,
// never passed through to FTS5. Defense-in-depth against query-
// injection-class DoS like `NEAR/0 "a" "b"` against a large corpus.
func ftsQuote(term string) string {
	return `"` + strings.ReplaceAll(term, `"`, `""`) + `"`
}

// tokenizeQuery splits the input on whitespace, respecting double-
// quoted phrases (`subject:"gear list"` is one token, value
// `gear list`; a standalone "quoted phrase" is a quoted token) and
// emitting ( and ) outside quotes as grouping tokens.
func tokenizeQuery(input string) []queryToken {
	var out []queryToken
	var cur strings.Builder
	inQuote := false
	// quotedWhole tracks whether the current token began with a quote
	// (a standalone phrase) — prefix:"x" tokens are not "quoted".
	quotedWhole := false
	flush := func() {
		if cur.Len() > 0 || quotedWhole {
			out = append(out, queryToken{text: cur.String(), quoted: quotedWhole})
		}
		cur.Reset()
		quotedWhole = false
	}
	for _, r := range input {
		switch {
		case r == '"':
			if !inQuote && cur.Len() == 0 {
				quotedWhole = true
			}
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		case !inQuote && (r == '(' || r == ')'):
			flush()
			out = append(out, queryToken{paren: byte(r)})
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// splitPrefix returns (key, value, hasColon). For "from:alice"
// → ("from", "alice", true). For "alice" → ("", "alice", false).
// The split only happens on the FIRST colon so `before:2026-01-01`
// keeps the rest of the date intact.
func splitPrefix(tok string) (string, string, bool) {
	idx := strings.IndexByte(tok, ':')
	if idx <= 0 {
		return "", tok, false
	}
	return tok[:idx], tok[idx+1:], true
}

// parseSearchDate accepts YYYY-MM-DD and a few common alternatives.
// Returns midnight UTC of the given day. Anything unparsable returns
// (zero, false).
func parseSearchDate(s string) (time.Time, bool) {
	for _, layout := range []string{
		"2006-01-02",
		"2006/01/02",
		"2006-1-2",
	} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
