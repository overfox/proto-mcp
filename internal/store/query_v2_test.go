package store

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// seedV2 is a richer fixture for DSL v2: names vs addresses, cc lists,
// unread/starred flags, labels.
func seedV2(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	rows := []Message{
		{ID: "jb1", ThreadID: "jb1", Subject: "Portfolio statement Q3",
			FromAddress: "noreply@juliusbaer.com", FromName: "Julius Baer",
			ToJSON: `[{"name":"Farid","address":"farid@proton.me"}]`,
			CcJSON: `[{"name":"Advisor","address":"advisor@juliusbaer.com"}]`,
			Date:   time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Folder: "inbox",
			Unread: true, HasAttachments: true},
		{ID: "jb2", ThreadID: "jb2", Subject: "Trade confirmation 50% allocation",
			FromAddress: "ops@juliusbaer.com", FromName: "JB Operations",
			ToJSON: `[{"name":"Farid","address":"farid@proton.me"}]`,
			Date:   time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC), Folder: "archive",
			Starred: true},
		{ID: "law1", ThreadID: "law1", Subject: "Arbitration hearing schedule",
			FromAddress: "clerk@lawfirm.ch", FromName: "Court Clerk",
			ToJSON: `[{"name":"Farid","address":"farid@proton.me"}]`,
			CcJSON: `[{"name":"Counsel","address":"counsel@lawfirm.ch"}]`,
			Date:   time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), Folder: "inbox",
			Unread: true, Starred: true},
		{ID: "news", ThreadID: "news", Subject: "Weekly newsletter",
			FromAddress: "news@example.com", FromName: "Example News",
			ToJSON: `[{"name":"Farid","address":"farid@proton.me"}]`,
			Date:   time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC), Folder: "inbox"},
		{ID: "co1", ThreadID: "co1", Subject: "Board minutes a_b",
			FromAddress: "secretary@company.example", FromName: "Company Secretary",
			ToJSON: `[{"name":"Farid","address":"farid@proton.me"}]`,
			Date:   time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC), Folder: ""},
	}
	for _, m := range rows {
		if err := s.UpsertMessage(ctx, m); err != nil {
			t.Fatalf("seed %s: %v", m.ID, err)
		}
	}
	if err := s.UpsertLabel(ctx, Label{ID: "L-legal", Name: "Legal", Type: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertLabel(ctx, Label{ID: "L-bank", Name: "Bank", Type: 1}); err != nil {
		t.Fatal(err)
	}
	for id, labels := range map[string][]string{
		"jb1": {"L-bank"}, "jb2": {"L-bank"}, "law1": {"L-legal"},
	} {
		if err := s.SetMessageLabels(ctx, id, labels); err != nil {
			t.Fatal(err)
		}
	}
	// Bodies for FTS.
	for id, body := range map[string]string{
		"jb1":  "Your quarterly statement is ready.",
		"law1": "The tribunal has fixed the hearing for October.",
		"news": "This week: markets, statement season and more.",
	} {
		if err := s.SetCachedBody(ctx, id, CachedBody{Text: body}); err != nil {
			t.Fatal(err)
		}
	}
}

func hitIDs(hits []SearchHit) string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.MessageID)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestSearchDSLv2(t *testing.T) {
	s := mustOpen(t)
	seedV2(t, s)
	ctx := context.Background()

	cases := []struct {
		query string
		want  string // sorted, comma-joined ids
	}{
		// from: matches address OR display name.
		{"from:juliusbaer", "jb1,jb2"},
		{"from:\"Julius Baer\"", "jb1"},
		{"from:clerk", "law1"},
		{"from:\"court clerk\"", "law1"},
		// Repeated prefixes AND together (v1 kept only the last).
		{"from:juliusbaer from:ops", "jb2"},
		{"from:juliusbaer from:clerk", ""},
		// OR between prefixes and groups.
		{"from:juliusbaer OR from:lawfirm", "jb1,jb2,law1"},
		{"(from:ops OR from:clerk) is:starred", "jb2,law1"},
		// OR binds tighter than implicit AND (Gmail precedence).
		{"from:ops OR from:clerk is:unread", "law1"},
		// Lower-case "or" is a term, not an operator.
		{"from:ops or", ""},
		// Negation.
		{"-from:juliusbaer", "co1,law1,news"},
		{"in:inbox -label:legal", "jb1,news"},
		{"-label:Bank -label:legal", "co1,news"},
		{"statement -newsletter", "jb1"},
		{"-(from:juliusbaer OR from:lawfirm)", "co1,news"},
		{"- (in:inbox)", "co1,jb2"},
		// is: flags.
		{"is:unread", "jb1,law1"},
		{"is:read", "co1,jb2,news"},
		{"is:starred", "jb2,law1"},
		{"is:starred -is:unread", "jb2"},
		{"is:unread OR is:starred", "jb1,jb2,law1"},
		// cc:
		{"cc:advisor", "jb1"},
		{"cc:lawfirm", "law1"},
		{"-cc:lawfirm cc:juliusbaer", "jb1"},
		// label by name (case-insensitive) or id.
		{"label:legal", "law1"},
		{"label:L-bank", "jb1,jb2"},
		{"label:bank OR label:legal", "jb1,jb2,law1"},
		// Full text, phrase, OR between bare terms.
		{"statement", "jb1,news"},
		{"tribunal OR quarterly", "jb1,law1"},
		{"\"fixed the hearing\"", "law1"},
		// Dates combined with OR groups.
		{"after:2026-09-05 (from:ops OR from:clerk)", "jb2,law1"},
		{"since:2026-09-10 until:2026-09-13", "law1,news"},
		// LIKE wildcards are literal.
		{"subject:50%", "jb2"},
		{"subject:a_b", "co1"},
		{"subject:%", "jb2"}, // literal %, not "match everything"
		// in:all is no filter; unknown prefix is a term.
		{"in:all is:starred", "jb2,law1"},
		// Empty / degenerate input.
		{"", "co1,jb1,jb2,law1,news"},
		{"OR", "co1,jb1,jb2,law1,news"},
		{"()", "co1,jb1,jb2,law1,news"},
		{"from:", "co1,jb1,jb2,law1,news"},
		{"before:not-a-date", "co1,jb1,jb2,law1,news"},
		{"((is:starred", "jb2,law1"},
		{"is:starred))", "jb2,law1"},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			hits, err := s.Search(ctx, tc.query, SearchOpts{Limit: 200})
			if err != nil {
				t.Fatalf("Search(%q): %v", tc.query, err)
			}
			if got := hitIDs(hits); got != tc.want {
				t.Errorf("Search(%q) = [%s], want [%s]", tc.query, got, tc.want)
			}
		})
	}
}

// SECURITY C-9: FTS5 operators inside terms must stay literal, and
// nothing in the query reaches SQL text. These must not error.
func TestSearchDSLv2_InjectionStaysLiteral(t *testing.T) {
	s := mustOpen(t)
	seedV2(t, s)
	ctx := context.Background()
	for _, q := range []string{
		`NEAR/0 "a" "b"`,
		`statement*`,
		`"a" AND "b"`,
		`'; DROP TABLE messages; --`,
		`from:x' OR '1'='1`,
		`subject:"\"quoted\""`,
		`label:') OR 1=1 --`,
		`-"-"`,
		strings.Repeat("(", 100) + "statement" + strings.Repeat(")", 100),
		strings.Repeat("a OR ", 300) + "b",
	} {
		if _, err := s.Search(ctx, q, SearchOpts{}); err != nil {
			t.Errorf("Search(%q) errored: %v", q, err)
		}
	}
	// The table survived.
	if hits, _ := s.Search(ctx, "", SearchOpts{}); len(hits) != 5 {
		t.Errorf("fixture damaged: %d rows", len(hits))
	}
}

func TestSearchDSLv2_StarredAndRankOrder(t *testing.T) {
	s := mustOpen(t)
	seedV2(t, s)
	hits, err := s.Search(context.Background(), "is:starred", SearchOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if !h.Starred {
			t.Errorf("%s: Starred not populated", h.MessageID)
		}
	}
	// A full-text match ranks ahead of rows matched only via a
	// structured OR branch.
	hits, err = s.Search(context.Background(), "tribunal OR from:secretary", SearchOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 2 || hits[0].MessageID != "law1" {
		t.Errorf("rank order: %+v", hits)
	}
}

func TestParseQueryTree(t *testing.T) {
	// Spot-check structure: OR inside AND, negated leaf.
	n := parseQuery(`from:a OR from:b -label:x`)
	if n == nil || n.kind != nodeAnd || len(n.children) != 2 {
		t.Fatalf("want AND of 2, got %+v", n)
	}
	if n.children[0].kind != nodeOr || len(n.children[0].children) != 2 {
		t.Errorf("first child should be OR of 2")
	}
	if n.children[1].kind != nodeNot || n.children[1].child.leaf.kind != leafLabel {
		t.Errorf("second child should be NOT label")
	}
	// Quoted operator tokens are literal terms.
	n = parseQuery(`"OR" "-x"`)
	if n == nil || n.kind != nodeAnd || n.children[0].leaf.value != "OR" || n.children[1].leaf.value != "-x" {
		t.Errorf("quoted tokens should be literal FTS terms: %+v", n)
	}
	if parseQuery("   ") != nil {
		t.Error("blank query should parse to nil")
	}
}
