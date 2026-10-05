package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// planCache remembers the plan lookup per user for the life of the
// process (the subscription doesn't change mid-session in any way that
// matters here), including a negative result, so account_whoami makes
// at most one network call.
var planCache struct {
	sync.Mutex
	byUser map[string]string
}

// planLookupTimeout bounds the one-time plan lookup.
const planLookupTimeout = 5 * time.Second

// accountPlan returns the subscription plan name from the organization
// endpoint (/core/v4/organizations — paid plans are modelled as an
// organization with a PlanName; the user object itself carries no plan
// field in go-proton-api). Free accounts have no organization, so the
// lookup fails and the plan is reported as "" (omitted).
func accountPlan(ctx context.Context, sess *protonclient.Session) string {
	if sess == nil || sess.Client == nil {
		return ""
	}
	planCache.Lock()
	defer planCache.Unlock()
	if plan, ok := planCache.byUser[sess.User.ID]; ok {
		return plan
	}
	if planCache.byUser == nil {
		planCache.byUser = map[string]string{}
	}
	cctx, cancel := context.WithTimeout(ctx, planLookupTimeout)
	defer cancel()
	plan := ""
	if org, err := sess.Client.GetOrganizationData(cctx); err == nil {
		plan = org.Organization.PlanName
	} else if cctx.Err() != nil || ctx.Err() != nil {
		return "" // timed out / cancelled: don't cache, try again next call
	}
	planCache.byUser[sess.User.ID] = plan
	return plan
}

func accountWhoami(deps Deps) mcp.Tool {
	type result struct {
		Email       string   `json:"email"`
		DisplayName string   `json:"display_name,omitempty"`
		UserID      string   `json:"user_id"`
		Addresses   []string `json:"addresses"`
		Plan        string   `json:"plan,omitempty"`
	}

	return mcp.Tool{
		Name:        "account_whoami",
		Description: "Identify the Proton account this MCP server is signed into. Returns email, display name, user ID, list of address aliases, and the subscription plan name when the account has one (free accounts omit it). Read-only. Everything except the plan comes from the session established at initialize; the plan is one cached lookup.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"email":        {"type": "string"},
				"display_name": {"type": "string"},
				"user_id":      {"type": "string"},
				"addresses":    {"type": "array", "items": {"type": "string"}},
				"plan":         {"type": "string", "description": "Proton plan name (e.g. mail2022, bundle2022); omitted for free accounts."}
			},
			"required": ["email", "user_id", "addresses"]
		}`),
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			if deps.Session == nil {
				return nil, errors.New("session not available — server was not properly initialized")
			}
			primary, _ := deps.Session.PrimaryAddress()
			addrs := make([]string, 0, len(deps.Session.Addresses))
			for _, a := range deps.Session.Addresses {
				addrs = append(addrs, a.Email)
			}
			return mcp.StructuredResult(result{
				Email:       primary.Email,
				DisplayName: deps.Session.User.DisplayName,
				UserID:      deps.Session.User.ID,
				Addresses:   addrs,
				Plan:        accountPlan(ctx.Std, deps.Session),
			})
		},
	}
}
