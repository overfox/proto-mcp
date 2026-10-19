package mcptools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// M5: an auto rule may only label / star / mark read. Moving mail —
// spam, archive, any folder — is refused at validation.
func TestAutoRuleMoveRefused(t *testing.T) {
	for _, dest := range []string{"spam", "archive", "inbox", "Receipts"} {
		r := Rule{Name: "x", Query: "from:a", Auto: true, Actions: []RuleAction{{Star: true}, {Move: dest}}}
		if err := validateRule(r); err == nil {
			t.Errorf("auto rule moving to %q accepted", dest)
		}
		r.Auto = false
		if dest != "Receipts" { // user folder names resolve later; system ones validate now
			if err := validateRule(r); err != nil {
				t.Errorf("manual rule moving to %q rejected: %v", dest, err)
			}
		}
	}
	ok := Rule{Name: "x", Query: "from:a", Auto: true, Actions: []RuleAction{{Label: "L"}, {Star: true}, {MarkRead: true}}}
	if err := validateRule(ok); err != nil {
		t.Fatalf("label/star/mark_read auto rule rejected: %v", err)
	}

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	deps := Deps{Store: st, RulesPath: filepath.Join(t.TempDir(), "rules.yaml")}
	_, herr := rulesSet(deps).Handler(mcpCtx(), json.RawMessage(
		`{"name":"spam-it","query":"from:x","actions":[{"move":"spam"}],"auto":true}`))
	if herr == nil {
		t.Fatal("rules_set accepted an auto rule that moves to spam")
	}
}

// Existing files with such auto rules: the rule is kept but its auto
// flag is turned off (logged), so ApplyAutoRules never runs it.
func TestExistingAutoMoveRuleDisabled(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.yaml")
	doc := "rules:\n" +
		"  - name: bury\n    query: from:x\n    auto: true\n    actions:\n      - move: spam\n" +
		"  - name: mark\n    query: from:y\n    auto: true\n    actions:\n      - star: true\n"
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadRules(Deps{RulesPath: p})
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	if len(rules) != 2 || rules[0].Auto || !rules[1].Auto {
		t.Fatalf("rules = %+v, want bury auto=false, mark auto=true", rules)
	}
}

type recAuditor struct{ events []AutoRuleEvent }

func (r *recAuditor) AutoRuleAction(_ context.Context, ev AutoRuleEvent) {
	r.events = append(r.events, ev)
}

// M5: every auto-rule action is audited.
func TestApplyAutoRulesAudits(t *testing.T) {
	f, deps, ids := rulesFixture(t)
	ctx := context.Background()
	m, _ := f.st.GetMessage(ctx, ids["bank"])
	m.Date = time.Now().UTC().Add(-time.Hour)
	if err := f.st.UpsertMessage(ctx, m); err != nil {
		t.Fatal(err)
	}
	callTool(t, rulesSet(deps), `{"name":"auto-star","query":"from:bank.example","actions":[{"star":true},{"mark_read":true}],"auto":true}`, nil)
	rec := &recAuditor{}
	if _, err := ApplyAutoRules(ctx, deps, rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 2 {
		t.Fatalf("audit events = %d, want 2 (one per action): %+v", len(rec.events), rec.events)
	}
	for _, ev := range rec.events {
		if ev.Rule != "auto-star" || len(ev.MessageIDs) == 0 || ev.Err != nil {
			t.Errorf("event = %+v", ev)
		}
	}
}

// M5: the rules_run approval is bound to the rule CONTENT: the prompt
// (which the middleware folds into the approval-cache key) changes
// when the rule is edited, even though the args don't.
func TestRulesRunPromptBoundToContent(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	deps := Deps{Store: st, RulesPath: filepath.Join(t.TempDir(), "rules.yaml")}
	callTool(t, rulesSet(deps), `{"name":"r1","query":"from:a","actions":[{"star":true}]}`, nil)
	args := json.RawMessage(`{"name":"r1","dry_run":false}`)
	_, before := rulesRun(deps).PromptBody(args)
	if !strings.Contains(before, "from:a") || !strings.Contains(before, "rule content:") {
		t.Fatalf("prompt doesn't show the rule content:\n%s", before)
	}
	callTool(t, rulesSet(deps), `{"name":"r1","query":"from:a","actions":[{"move":"spam"}]}`, nil)
	_, after := rulesRun(deps).PromptBody(args)
	if before == after {
		t.Fatal("rules_run prompt (approval key) unchanged after the rule was edited")
	}
	if !strings.Contains(after, "move to spam") {
		t.Fatalf("edited prompt doesn't show the new action:\n%s", after)
	}
}

// The rules_set dialog can't be forged with newlines in the query.
func TestRulesSetPromptSanitizesQuery(t *testing.T) {
	deps := Deps{RulesPath: filepath.Join(t.TempDir(), "rules.yaml")}
	_, body := rulesSet(deps).PromptBody(json.RawMessage(
		`{"name":"x","query":"from:a\nmode: manual (rules_run only)","actions":[{"star":true}],"auto":true}`))
	if strings.Contains(body, "\nmode: manual") || strings.Contains(body, "from:a\n") {
		t.Fatalf("query newline reached the dialog:\n%s", body)
	}
}
