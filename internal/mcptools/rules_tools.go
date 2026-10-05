package mcptools

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

const ruleSchema = `{"type": "object", "properties": {
	"name":        {"type": "string"},
	"description": {"type": "string"},
	"query":       {"type": "string"},
	"auto":        {"type": "boolean"},
	"actions":     {"type": "array", "items": ` + ruleActionSchema + `}
}}`

const ruleActionSchema = `{"type": "object", "properties": {
	"label":     {"type": "string", "description": "Apply this label (id or name)."},
	"move":      {"type": "string", "description": "Move to inbox, archive, spam, or a user folder (id or name). Never trash."},
	"star":      {"type": "boolean"},
	"mark_read": {"type": "boolean"}
}, "additionalProperties": false}`

// rulesList — show the saved rules.
func rulesList(deps Deps) mcp.Tool {
	type result struct {
		Rules []Rule `json:"rules"`
		Path  string `json:"path"`
	}
	return mcp.Tool{
		Name: "rules_list",
		Description: "List the local mail rules (saved mail_search queries with organizing actions: label, move, star, mark_read). " +
			"Rules with auto=true are applied to new mail after each background sync; others run only via rules_run. Read-only.",
		InputSchema: json.RawMessage(`{"type": "object", "properties": {}, "additionalProperties": false}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"rules": {"type": "array", "items": ` + ruleSchema + `},
				"path":  {"type": "string"}
			},
			"required": ["rules", "path"]
		}`),
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			rulesMu.Lock()
			rules, err := loadRules(deps)
			rulesMu.Unlock()
			if err != nil {
				return mcp.ErrorResult("rules_list: %v", err), nil
			}
			p, _ := rulesPath(deps)
			if rules == nil {
				rules = []Rule{}
			}
			return mcp.StructuredResult(result{Rules: rules, Path: p})
		},
	}
}

// rulesSet — create or replace one rule (standing configuration).
func rulesSet(deps Deps) mcp.Tool {
	type result struct {
		Rule     Rule   `json:"rule"`
		Replaced bool   `json:"replaced"`
		Warning  string `json:"warning,omitempty"`
	}
	return mcp.Tool{
		Name: "rules_set",
		Description: "Create or replace (by name) a local mail rule: a mail_search DSL query plus 1-4 actions, each exactly one of " +
			"{\"label\": <label id or name>}, {\"move\": inbox|archive|spam|<user folder id or name>}, {\"star\": true}, {\"mark_read\": true}. " +
			"Rules can never send, forward, trash or delete. auto=true applies the rule to new mail after every background sync; " +
			"otherwise it only runs via rules_run. Tip: run rules_run with dry_run=true first to see what the query matches. " +
			"Standing configuration — every change is confirmed by the user.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name":        {"type": "string", "description": "Unique rule name (letters, digits, space, _ . -)."},
				"description": {"type": "string"},
				"query":       {"type": "string", "description": "mail_search DSL, e.g. from:juliusbaer.com subject:statement"},
				"actions":     {"type": "array", "minItems": 1, "maxItems": 4, "items": ` + ruleActionSchema + `},
				"auto":        {"type": "boolean", "default": false}
			},
			"required": ["name", "query", "actions"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"rule":     ` + ruleSchema + `,
				"replaced": {"type": "boolean"},
				"warning":  {"type": "string"}
			},
			"required": ["rule", "replaced"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var r Rule
			_ = json.Unmarshal(raw, &r)
			acts := make([]string, 0, len(r.Actions))
			for _, a := range r.Actions {
				acts = append(acts, describeAction(a))
			}
			mode := "manual (rules_run only)"
			if r.Auto {
				mode = "AUTOMATIC on new mail after every sync"
			}
			title := mcp.SanitizePromptText("Approve rules_set?", 120)
			body := fmt.Sprintf("save mail rule %q\nmatch: %s\nthen: %s\nmode: %s",
				r.Name, r.Query, strings.Join(acts, ", "), mode)
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var r Rule
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&r); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_set: "+err.Error())
			}
			r.Name = strings.TrimSpace(r.Name)
			r.Query = strings.TrimSpace(r.Query)
			if err := validateRule(r); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_set: "+err.Error())
			}

			rulesMu.Lock()
			defer rulesMu.Unlock()
			rules, err := loadRules(deps)
			if err != nil {
				return mcp.ErrorResult("rules_set: %v", err), nil
			}
			replaced := false
			for i := range rules {
				if strings.EqualFold(rules[i].Name, r.Name) {
					rules[i] = r
					replaced = true
				}
			}
			if !replaced {
				rules = append(rules, r)
			}
			if err := saveRules(deps, rules); err != nil {
				return mcp.ErrorResult("rules_set: %v", err), nil
			}
			return mcp.StructuredResult(result{Rule: r, Replaced: replaced, Warning: unresolvedTargets(ctx, deps, r)})
		},
	}
}

// unresolvedTargets warns (without failing) when a label / folder name
// in the rule isn't in the local mirror yet — the rule is saved, but
// running it will error until the label exists.
func unresolvedTargets(ctx mcp.Context, deps Deps, r Rule) string {
	if deps.Store == nil {
		return ""
	}
	var missing []string
	for _, a := range r.Actions {
		switch {
		case a.Label != "":
			if _, err := resolveLabelRef(ctx.Std, deps, a.Label, 1); err != nil {
				missing = append(missing, "label "+a.Label)
			}
		case a.Move != "":
			if _, ok := systemFolderToLabelID[strings.ToLower(a.Move)]; ok {
				continue
			}
			if _, err := resolveLabelRef(ctx.Std, deps, a.Move, 3); err != nil {
				missing = append(missing, "folder "+a.Move)
			}
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return "not found in the local mirror (create it or run mail_sync): " + strings.Join(missing, ", ")
}

// rulesDelete — remove one rule by name.
func rulesDelete(deps Deps) mcp.Tool {
	type input struct {
		Name string `json:"name"`
	}
	type result struct {
		Name    string `json:"name"`
		Deleted bool   `json:"deleted"`
	}
	return mcp.Tool{
		Name:        "rules_delete",
		Description: "Delete one local mail rule by name. Does not undo anything the rule already did.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"name": {"type": "string"}},
			"required": ["name"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"name": {"type": "string"}, "deleted": {"type": "boolean"}},
			"required": ["name", "deleted"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			title := mcp.SanitizePromptText("Approve rules_delete?", 120)
			return title, mcp.SanitizePromptText(fmt.Sprintf("delete mail rule %q", in.Name), 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_delete: "+err.Error())
			}
			if in.Name == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_delete: name is required")
			}
			rulesMu.Lock()
			defer rulesMu.Unlock()
			rules, err := loadRules(deps)
			if err != nil {
				return mcp.ErrorResult("rules_delete: %v", err), nil
			}
			kept := rules[:0]
			deleted := false
			for _, r := range rules {
				if strings.EqualFold(r.Name, in.Name) {
					deleted = true
					continue
				}
				kept = append(kept, r)
			}
			if !deleted {
				return mcp.ErrorResult("rules_delete: no rule named %q", in.Name), nil
			}
			if err := saveRules(deps, kept); err != nil {
				return mcp.ErrorResult("rules_delete: %v", err), nil
			}
			return mcp.StructuredResult(result{Name: in.Name, Deleted: true})
		},
	}
}

// rulesRun — run one rule or all of them now. dry_run (default true)
// only reports matches.
func rulesRun(deps Deps) mcp.Tool {
	type input struct {
		Name        string `json:"name"`
		DryRun      *bool  `json:"dry_run,omitempty"`
		MaxMessages int    `json:"max_messages,omitempty"`
		Since       string `json:"since,omitempty"`
	}
	type result struct {
		DryRun  bool            `json:"dry_run"`
		Results []RuleRunResult `json:"results"`
	}
	return mcp.Tool{
		Name: "rules_run",
		Description: "Run one local mail rule (name) or every rule (name=\"all\") against the local mirror. " +
			"dry_run defaults to TRUE: it only reports how many messages match and lists up to 50 of them. " +
			"Pass dry_run=false to apply the actions (idempotent — messages already labelled / moved / starred / read are skipped). " +
			"Each rule touches at most max_messages (default 200, max 500); optional since (RFC3339 / YYYY-MM-DD / 24h / 7d) narrows to recent mail.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name":         {"type": "string", "description": "Rule name, or \"all\"."},
				"dry_run":      {"type": "boolean", "default": true},
				"max_messages": {"type": "integer", "minimum": 1, "maximum": 500, "default": 200},
				"since":        {"type": "string"}
			},
			"required": ["name"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"dry_run": {"type": "boolean"},
				"results": {"type": "array", "items": {"type": "object", "properties": {
					"rule": {"type": "string"}, "matched": {"type": "integer"}, "capped": {"type": "boolean"},
					"applied": {"type": "array", "items": {"type": "string"}}, "error": {"type": "string"},
					"dry_run": {"type": "boolean"},
					"messages": {"type": "array", "items": {"type": "object", "properties": {
						"message_id": {"type": "string"}, "subject": {"type": "string"},
						"from": {"type": "string"}, "date": {"type": "string"}}}}}}}
			},
			"required": ["dry_run", "results"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			title := mcp.SanitizePromptText("Approve rules_run?", 120)
			verb := "preview (dry run) mail rule"
			if in.DryRun != nil && !*in.DryRun {
				verb = "APPLY mail rule"
			}
			if strings.EqualFold(in.Name, "all") {
				return title, mcp.SanitizePromptText(verb+"s: all", 4000)
			}
			return title, mcp.SanitizePromptText(fmt.Sprintf("%s %q", verb, in.Name), 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_run: "+err.Error())
			}
			if in.Name == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_run: name is required (or \"all\")")
			}
			dryRun := in.DryRun == nil || *in.DryRun
			max := clampInt(in.MaxMessages, defaultRuleRunMax, 1, maxStateBatch)
			var sinceUnix int64
			if in.Since != "" {
				t, err := parseSince(in.Since, nowUTC())
				if err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "rules_run: "+err.Error())
				}
				sinceUnix = t.Unix()
			}

			rulesMu.Lock()
			rules, err := loadRules(deps)
			rulesMu.Unlock()
			if err != nil {
				return mcp.ErrorResult("rules_run: %v", err), nil
			}
			var selected []Rule
			for _, r := range rules {
				if strings.EqualFold(in.Name, "all") || strings.EqualFold(r.Name, in.Name) {
					selected = append(selected, r)
				}
			}
			if len(selected) == 0 {
				return mcp.ErrorResult("rules_run: no rule named %q (see rules_list)", in.Name), nil
			}
			res := result{DryRun: dryRun, Results: []RuleRunResult{}}
			for _, r := range selected {
				res.Results = append(res.Results, runRule(ctx.Std, deps, r, dryRun, sinceUnix, max))
			}
			return mcp.StructuredResult(res)
		},
	}
}
