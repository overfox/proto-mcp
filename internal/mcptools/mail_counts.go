package mcptools

import (
	"encoding/json"
	"fmt"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// mailCounts — total + unread message counts, optionally scoped to a
// folder or label. Mirror-backed aggregate: answering "how many
// unread emails do I have?" previously meant paging envelope lists
// 200 rows at a time.
func mailCounts(deps Deps) mcp.Tool {
	type input struct {
		Folder  string `json:"folder,omitempty"`
		LabelID string `json:"label_id,omitempty"`
	}
	type result struct {
		Total  int64  `json:"total"`
		Unread int64  `json:"unread"`
		Scope  string `json:"scope"`
	}
	return mcp.Tool{
		Name: "mail_counts",
		Description: "Total and unread message counts from the local mirror, optionally scoped by " +
			"folder (system name or user folder label_id) and/or label_id. " +
			"Freshness matches the mirror (background sync every ~2 min); call mail_sync first for up-to-the-second counts.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"folder":   {"type": "string", "description": "System folder name (inbox, sent, ...) or user folder label_id"},
				"label_id": {"type": "string", "description": "Count only messages carrying this label"}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"total":  {"type": "integer"},
				"unread": {"type": "integer"},
				"scope":  {"type": "string"}
			},
			"required": ["total", "unread", "scope"]
		}`),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_counts: "+err.Error())
				}
			}
			total, unread, err := deps.Store.Counts(ctx.Std, store.ListFilter{
				Folder:  in.Folder,
				LabelID: in.LabelID,
			})
			if err != nil {
				return mcp.ErrorResult("mail_counts: %v", err), nil
			}
			scope := "all"
			if in.Folder != "" {
				scope = "folder:" + in.Folder
			}
			if in.LabelID != "" {
				scope += fmt.Sprintf("+label:%s", in.LabelID)
			}
			return mcp.StructuredResult(result{Total: total, Unread: unread, Scope: scope})
		},
	}
}
