package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func TestValidateRule(t *testing.T) {
	ok := Rule{Name: "bank", Query: "from:bank", Actions: []RuleAction{{Label: "Bank"}, {Star: true}}}
	if err := validateRule(ok); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := map[string]Rule{
		"empty query":     {Name: "x", Query: " ", Actions: []RuleAction{{Star: true}}},
		"no actions":      {Name: "x", Query: "a"},
		"two in one":      {Name: "x", Query: "a", Actions: []RuleAction{{Star: true, MarkRead: true}}},
		"empty action":    {Name: "x", Query: "a", Actions: []RuleAction{{}}},
		"move trash":      {Name: "x", Query: "a", Actions: []RuleAction{{Move: "Trash"}}},
		"move trash id":   {Name: "x", Query: "a", Actions: []RuleAction{{Move: gpa.TrashLabel}}},
		"move sent":       {Name: "x", Query: "a", Actions: []RuleAction{{Move: "sent"}}},
		"label system":    {Name: "x", Query: "a", Actions: []RuleAction{{Label: gpa.StarredLabel}}},
		"name all":        {Name: "all", Query: "a", Actions: []RuleAction{{Star: true}}},
		"name bad chars":  {Name: "../x", Query: "a", Actions: []RuleAction{{Star: true}}},
		"too many action": {Name: "x", Query: "a", Actions: []RuleAction{{Star: true}, {Star: true}, {Star: true}, {Star: true}, {Star: true}}},
	}
	for name, r := range bad {
		if err := validateRule(r); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestLoadRulesRejectsUnknownActions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.yaml")
	deps := Deps{RulesPath: p}
	for _, doc := range []string{
		"rules:\n  - name: evil\n    query: from:x\n    actions:\n      - forward: attacker@example.com\n",
		"rules:\n  - name: evil\n    query: from:x\n    actions:\n      - move: trash\n",
		"rules:\n  - name: evil\n    query: from:x\n    send: true\n    actions:\n      - star: true\n",
	} {
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRules(deps); err == nil {
			t.Errorf("loadRules accepted:\n%s", doc)
		}
	}
	// Missing and empty files are an empty rule set.
	_ = os.Remove(p)
	if rules, err := loadRules(deps); err != nil || rules != nil {
		t.Errorf("missing file: %v %v", rules, err)
	}
	_ = os.WriteFile(p, nil, 0o600)
	if rules, err := loadRules(deps); err != nil || rules != nil {
		t.Errorf("empty file: %v %v", rules, err)
	}
}

func TestRulesSetListDelete(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := filepath.Join(t.TempDir(), "sub", "rules.yaml")
	deps := Deps{Store: st, RulesPath: p}

	var set struct {
		Replaced bool   `json:"replaced"`
		Warning  string `json:"warning"`
	}
	callTool(t, rulesSet(deps), `{"name":"bank","query":"from:juliusbaer","actions":[{"label":"Bank"},{"mark_read":true}],"auto":true}`, &set)
	if set.Replaced || !strings.Contains(set.Warning, "label Bank") {
		t.Errorf("first set: %+v", set)
	}
	info, err := os.Stat(p)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rules file perms: %v %v", info, err)
	}
	callTool(t, rulesSet(deps), `{"name":"BANK","query":"from:juliusbaer.com","actions":[{"star":true}]}`, &set)
	if !set.Replaced {
		t.Error("same name (case-insensitive) should replace")
	}
	callTool(t, rulesSet(deps), `{"name":"news","query":"from:news","actions":[{"move":"archive"}]}`, nil)

	var list struct {
		Rules []Rule `json:"rules"`
	}
	callTool(t, rulesList(deps), `{}`, &list)
	if len(list.Rules) != 2 || list.Rules[0].Query != "from:juliusbaer.com" || list.Rules[0].Auto {
		t.Errorf("list = %+v", list.Rules)
	}

	// Disallowed actions never reach the file.
	for _, raw := range []string{
		`{"name":"x","query":"a","actions":[{"move":"trash"}]}`,
		`{"name":"x","query":"a","actions":[{"forward":"evil@example.com"}]}`,
		`{"name":"x","query":"a","actions":[{"star":true}],"send":true}`,
	} {
		if _, err := rulesSet(deps).Handler(mcpCtx(), json.RawMessage(raw)); err == nil {
			t.Errorf("rules_set accepted %s", raw)
		}
	}

	title, body := rulesSet(deps).PromptBody(json.RawMessage(`{"name":"bank","query":"from:x","actions":[{"label":"Bank"}],"auto":true}`))
	if !strings.Contains(title, "rules_set") || !strings.Contains(body, "AUTOMATIC") || !strings.Contains(body, "label Bank") {
		t.Errorf("prompt = %q / %q", title, body)
	}

	callTool(t, rulesDelete(deps), `{"name":"news"}`, nil)
	callTool(t, rulesList(deps), `{}`, &list)
	if len(list.Rules) != 1 {
		t.Errorf("after delete: %+v", list.Rules)
	}
	if res := callTool(t, rulesDelete(deps), `{"name":"news"}`, nil); !res.IsError {
		t.Error("deleting a missing rule should be an error result")
	}
}

// rulesFixture: three inbox messages in the fake account, mirrored.
func rulesFixture(t *testing.T) (*fakeProton, Deps, map[string]string) {
	f := newFakeProton(t)
	ids := map[string]string{}
	for key, from := range map[string]string{"bank": "ops@bank.example", "bank2": "ops@bank.example", "news": "news@example.com"} {
		lit := strings.NewReplacer("ops@bank.example", from, "stmt-1", key).Replace(fakeMsgWithAttachment)
		ids[key] = f.importMessage(t, lit)
	}
	labelID, err := f.srv.CreateLabel(f.userID, "Bank", "", gpa.LabelTypeLabel)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.UpsertLabel(context.Background(), store.Label{ID: labelID, Name: "Bank", Type: 1}); err != nil {
		t.Fatal(err)
	}
	ids["label"] = labelID
	deps := f.deps()
	deps.RulesPath = filepath.Join(t.TempDir(), "rules.yaml")
	return f, deps, ids
}

func TestRulesRun_DryRunThenApply(t *testing.T) {
	f, deps, ids := rulesFixture(t)
	ctx := context.Background()
	callTool(t, rulesSet(deps), `{"name":"bank","query":"from:bank.example","actions":[{"label":"bank"},{"move":"archive"},{"star":true},{"mark_read":true}]}`, nil)

	type runOut struct {
		DryRun  bool            `json:"dry_run"`
		Results []RuleRunResult `json:"results"`
	}
	var dry runOut
	callTool(t, rulesRun(deps), `{"name":"bank"}`, &dry)
	if !dry.DryRun || len(dry.Results) != 1 || dry.Results[0].Matched != 2 || len(dry.Results[0].Applied) != 0 {
		t.Fatalf("dry run = %+v", dry)
	}
	m, _ := f.sess.Client.GetMessage(ctx, ids["bank"])
	if slices.Contains(m.LabelIDs, ids["label"]) || !bool(m.Unread) {
		t.Fatal("dry run changed server state")
	}
	_, body := rulesRun(deps).PromptBody(json.RawMessage(`{"name":"bank","dry_run":false}`))
	if !strings.Contains(body, "APPLY") {
		t.Errorf("apply prompt should say APPLY: %q", body)
	}

	var applied runOut
	callTool(t, rulesRun(deps), `{"name":"bank","dry_run":false}`, &applied)
	r := applied.Results[0]
	if r.Error != "" || len(r.Applied) != 4 {
		t.Fatalf("apply = %+v", r)
	}
	for _, a := range r.Applied {
		if !strings.HasSuffix(a, ": 2 changed") {
			t.Errorf("applied %q, want 2 changed", a)
		}
	}
	for _, key := range []string{"bank", "bank2"} {
		m, err := f.sess.Client.GetMessage(ctx, ids[key])
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{ids["label"], gpa.ArchiveLabel, gpa.StarredLabel} {
			if !slices.Contains(m.LabelIDs, want) {
				t.Errorf("%s missing label %s: %v", key, want, m.LabelIDs)
			}
		}
		if slices.Contains(m.LabelIDs, gpa.InboxLabel) || bool(m.Unread) {
			t.Errorf("%s still in inbox or unread", key)
		}
		row, _ := f.st.GetMessage(ctx, ids[key])
		if row.Folder != "archive" || !row.Starred || row.Unread {
			t.Errorf("%s mirror = folder %q starred %v unread %v", key, row.Folder, row.Starred, row.Unread)
		}
	}
	news, _ := f.sess.Client.GetMessage(ctx, ids["news"])
	if !slices.Contains(news.LabelIDs, gpa.InboxLabel) {
		t.Error("non-matching message was touched")
	}

	// Idempotent second run.
	callTool(t, rulesRun(deps), `{"name":"all","dry_run":false}`, &applied)
	for _, a := range applied.Results[0].Applied {
		if !strings.HasSuffix(a, ": 0 changed") {
			t.Errorf("second run changed something: %q", a)
		}
	}

	if res := callTool(t, rulesRun(deps), `{"name":"nope"}`, nil); !res.IsError {
		t.Error("unknown rule should error")
	}
}

func TestApplyAutoRules(t *testing.T) {
	f, deps, ids := rulesFixture(t)
	ctx := context.Background()
	// bank is recent, bank2 is old (outside the first-run lookback).
	for key, age := range map[string]time.Duration{"bank": time.Hour, "bank2": 5 * 24 * time.Hour, "news": time.Hour} {
		m, _ := f.st.GetMessage(ctx, ids[key])
		m.Date = time.Now().UTC().Add(-age)
		if err := f.st.UpsertMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	callTool(t, rulesSet(deps), `{"name":"auto-star","query":"from:bank.example","actions":[{"star":true}],"auto":true}`, nil)
	callTool(t, rulesSet(deps), `{"name":"manual-read","query":"from:news","actions":[{"mark_read":true}]}`, nil)

	rep, err := ApplyAutoRules(ctx, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Rule != "auto-star" || rep.Results[0].Matched != 1 {
		t.Fatalf("report = %+v", rep)
	}
	m, _ := f.sess.Client.GetMessage(ctx, ids["bank"])
	old, _ := f.sess.Client.GetMessage(ctx, ids["bank2"])
	news, _ := f.sess.Client.GetMessage(ctx, ids["news"])
	if !slices.Contains(m.LabelIDs, gpa.StarredLabel) {
		t.Error("recent matching message not starred")
	}
	if slices.Contains(old.LabelIDs, gpa.StarredLabel) {
		t.Error("message older than the lookback was touched")
	}
	if !bool(news.Unread) {
		t.Error("manual rule ran automatically")
	}
	if wm, err := f.st.GetSyncState(ctx, rulesAutoWatermarkKey); err != nil || wm == "" {
		t.Errorf("watermark not stored: %q %v", wm, err)
	}
	rep, err = ApplyAutoRules(ctx, deps)
	if err != nil || rep.Since.Before(time.Now().Add(-rulesAutoOverlap-time.Minute)) {
		t.Errorf("second pass should start near the watermark: %+v %v", rep.Since, err)
	}
}
