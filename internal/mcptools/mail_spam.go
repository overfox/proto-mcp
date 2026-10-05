package mcptools

import (
	"encoding/json"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// mailReportSpam — move messages to Spam, which is how Proton's own
// clients report spam (the move trains the server-side filter; there
// is no separate report endpoint in the SDK). Same mechanics as
// mail_move destination=spam, but a dedicated verb makes intent clear
// in the approval prompt and the audit log.
func mailReportSpam(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_report_spam",
		Description: "Report one message (message_id) or a batch (message_ids) as spam by moving it to the Spam folder — a batch is one call and one approval. " +
			"Reversible: mail_move the messages back to inbox (or wherever they were).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				` + stateIDsSchemaProps + `
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in stateIDsInput
			_ = json.Unmarshal(raw, &in)
			ids, _ := in.resolveIDs("mail_report_spam")
			title := mcp.SanitizePromptText("Approve mail_report_spam?", 120)
			body := "report " + batchPromptNoun(deps, ids) + " as spam (moves to Spam; reversible via mail_move)"
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			ids, merr := decodeStateIDs(raw, "mail_report_spam")
			if merr != nil {
				return nil, merr
			}
			if deps.Session == nil || deps.Session.Client == nil {
				return mcp.ErrorResult("mail_report_spam: session not available"), nil
			}
			_, warn, err := moveMessages(ctx.Std, deps, ids, gpa.SpamLabel, "spam")
			if err != nil {
				return mcp.ErrorResult("mail_report_spam: %v", err), nil
			}
			return mcp.StructuredResult(stateActionOK(ids, "reported_spam", warn))
		},
	}
}
