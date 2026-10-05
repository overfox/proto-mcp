package mcptools

import (
	"encoding/json"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// mailStar / mailUnstar toggle Proton's Starred system label. Same
// batch id shape, reversibility and allow-by-default posture as
// mail_mark_read / mail_mark_unread: starring is a personal flag with
// no external effect.
func mailStar(deps Deps) mcp.Tool {
	return starTool(deps, "mail_star", true)
}

func mailUnstar(deps Deps) mcp.Tool {
	return starTool(deps, "mail_unstar", false)
}

func starTool(deps Deps, name string, star bool) mcp.Tool {
	desc := "Star one message (message_id) or a batch (message_ids). Reversible via mail_unstar. Local mirror updated immediately; find starred mail with mail_search is:starred."
	action := "starred"
	if !star {
		desc = "Remove the star from one message (message_id) or a batch (message_ids). Reversible via mail_star. Local mirror updated immediately."
		action = "unstarred"
	}
	return mcp.Tool{
		Name:        name,
		Description: desc,
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				` + stateIDsSchemaProps + `
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			ids, merr := decodeStateIDs(raw, name)
			if merr != nil {
				return nil, merr
			}
			if deps.Session == nil || deps.Session.Client == nil {
				return mcp.ErrorResult("%s: session not available", name), nil
			}
			var err error
			if star {
				err = deps.Session.Client.LabelMessages(ctx.Std, ids, gpa.StarredLabel)
			} else {
				err = deps.Session.Client.UnlabelMessages(ctx.Std, ids, gpa.StarredLabel)
			}
			if err != nil {
				return mcp.ErrorResult("%s: %v", name, err), nil
			}
			warn := updateMessagesFlag(ctx.Std, deps, ids, func(m *store.Message) { m.Starred = star })
			return mcp.StructuredResult(stateActionOK(ids, action, warn))
		},
	}
}
