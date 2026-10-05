package mcptools

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

const (
	defaultContactsLimit = 25
	maxContactsLimit     = 100
)

// contactsSearch — read-only lookup in the Proton address book by
// name or email substring. Deliberately returns ONLY the display name
// and email addresses: the contact cards also hold phone numbers,
// postal addresses, birthdays and notes (encrypted + signed vCards),
// and none of that is needed to address mail. Uses the contact-emails
// index (names and addresses are plaintext there), so no card
// decryption happens.
func contactsSearch(deps Deps) mcp.Tool {
	type input struct {
		Query string `json:"query"`
		Limit int    `json:"limit,omitempty"`
	}
	type contact struct {
		Name   string   `json:"name"`
		Emails []string `json:"emails"`
	}
	type result struct {
		Contacts []contact `json:"contacts"`
		Total    int       `json:"total"`
	}

	return mcp.Tool{
		Name: "contacts_search",
		Description: "Search the Proton address book by name or email substring (case-insensitive). " +
			"Returns each matching contact's display name and email addresses only — no phone numbers, " +
			"postal addresses or notes. Pass an empty query to list contacts (up to limit). Read-only.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"query": {"type": "string", "description": "Substring of a name or email address. Empty lists all."},
				"limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"contacts": {"type": "array", "items": {"type": "object", "properties": {
					"name":   {"type": "string"},
					"emails": {"type": "array", "items": {"type": "string"}}
				}, "required": ["name", "emails"]}},
				"total": {"type": "integer", "description": "Matching contacts before the limit was applied."}
			},
			"required": ["contacts", "total"]
		}`),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "contacts_search: "+err.Error())
				}
			}
			limit := in.Limit
			if limit <= 0 {
				limit = defaultContactsLimit
			}
			if limit > maxContactsLimit {
				limit = maxContactsLimit
			}
			if deps.Session == nil || deps.Session.Client == nil {
				return mcp.ErrorResult("contacts_search: session not available"), nil
			}

			// The API's Email filter is an exact match, so fetch the
			// index and filter locally for substring semantics.
			emails, err := deps.Session.Client.GetAllContactEmails(ctx.Std, "")
			if err != nil {
				return mcp.ErrorResult("contacts_search: %v", err), nil
			}
			q := strings.ToLower(strings.TrimSpace(in.Query))

			type agg struct {
				name    string
				emails  []string
				matched bool
			}
			byContact := map[string]*agg{}
			var order []string
			for _, e := range emails {
				key := e.ContactID
				if key == "" {
					key = "email:" + e.ID
				}
				a, ok := byContact[key]
				if !ok {
					a = &agg{name: e.Name}
					byContact[key] = a
					order = append(order, key)
				}
				if a.name == "" {
					a.name = e.Name
				}
				a.emails = append(a.emails, e.Email)
				if q == "" || strings.Contains(strings.ToLower(e.Name), q) || strings.Contains(strings.ToLower(e.Email), q) {
					a.matched = true
				}
			}

			var matches []contact
			for _, key := range order {
				a := byContact[key]
				if !a.matched {
					continue
				}
				matches = append(matches, contact{Name: a.name, Emails: dedupe(a.emails)})
			}
			sort.SliceStable(matches, func(i, j int) bool {
				return strings.ToLower(matches[i].Name) < strings.ToLower(matches[j].Name)
			})
			res := result{Contacts: matches, Total: len(matches)}
			if len(res.Contacts) > limit {
				res.Contacts = res.Contacts[:limit]
			}
			if res.Contacts == nil {
				res.Contacts = []contact{}
			}
			return mcp.StructuredResult(res)
		},
	}
}

// dedupe returns s without repeated values (case-insensitive), order kept.
func dedupe(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		k := strings.ToLower(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}
