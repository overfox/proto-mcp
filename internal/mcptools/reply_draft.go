package mcptools

import (
	"encoding/json"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// mail_draft_reply prepares a reply as a draft instead of sending it.
// The draft is created with the original as its parent (ParentID +
// reply / reply-all action), so whether it is later sent from the
// Proton apps or with mail_send_draft, Proton sets In-Reply-To /
// References and files it in the original's conversation. Recipients,
// subject and quote are built exactly as mail_reply / mail_reply_all
// build them.
//
// Like mail_draft_create this has no external effect, so policy allows
// it; files from outside attachment_path_allowlist still need their own
// Touch ID approval (draftAttachmentGate).

type draftReplyInput struct {
	replyInput
	ReplyAll bool     `json:"reply_all,omitempty"`
	BCC      []string `json:"bcc,omitempty"`
}

type draftReplyResult struct {
	draftResult
	InReplyTo string `json:"in_reply_to"`
	ThreadID  string `json:"thread_id,omitempty"`
	Quoted    bool   `json:"quoted"`
}

func mailDraftReply(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_draft_reply",
		Description: "Create a reply DRAFT in the original message's thread (nothing is sent). " +
			"Recipients and subject are filled in like mail_reply: To = the original's Reply-To (else its sender; " +
			"for your own sent message, its recipients); `reply_all: true` also CCs the original To+CC minus your " +
			"own addresses. `extra_to` / `cc` / `bcc` add recipients. The original is quoted below body_text / " +
			"body_html unless include_quote is false. The draft is linked to the original, so when sent " +
			"(Proton apps or mail_send_draft, which needs Touch ID) it keeps In-Reply-To/References and stays in " +
			"the same conversation. Edit it with mail_draft_update. `attachments` work as in mail_draft_create.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"in_reply_to":   {"type": "string", "description": "message_id of the message being replied to (usually the latest in the thread)."},
				"reply_all":     {"type": "boolean", "default": false},
				"extra_to":      {"type": "array", "items": {"type": "string"}},
				"cc":            {"type": "array", "items": {"type": "string"}},
				"bcc":           {"type": "array", "items": {"type": "string"}},
				"body_text":     {"type": "string"},
				"body_html":     {"type": "string"},
				"include_quote": {"type": "boolean", "default": true},
				"attachments":   ` + attachmentInputSchemaFragment + `
			},
			"required": ["in_reply_to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"draft_id":    {"type": "string"},
				"subject":     {"type": "string"},
				"to":          {"type": "array", "items": {"type": "string"}},
				"cc":          {"type": "array", "items": {"type": "string"}},
				"bcc":         {"type": "array", "items": {"type": "string"}},
				"mime_type":   {"type": "string"},
				"in_reply_to": {"type": "string"},
				"thread_id":   {"type": "string"},
				"quoted":      {"type": "boolean"}
			},
			"required": ["draft_id", "subject", "mime_type", "in_reply_to", "quoted"]
		}`),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			const tool = "mail_draft_reply"
			var in draftReplyInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": "+err.Error())
			}
			if in.InReplyTo == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": in_reply_to is required")
			}
			for _, a := range append(append(append([]string{}, in.ExtraTo...), in.CC...), in.BCC...) {
				if err := ensureValidEmail(a); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": "+err.Error())
				}
			}
			if deps.Session == nil || deps.Session.Client == nil {
				return mcp.ErrorResult("%s: no active session", tool), nil
			}

			parent, err := deps.Session.Client.GetMessage(ctx.Std, in.InReplyTo)
			if err != nil {
				return mcp.ErrorResult("%s: fetch original: %v", tool, err), nil
			}
			p := replyParentFromMessage(parent)
			to, cc := replyRecipients(p, selfAddresses(deps), in.ReplyAll, in.ExtraTo, in.CC)
			subject := replySubject(p.Subject)

			bodyText, bodyHTML := in.BodyText, in.BodyHTML
			if in.quote() {
				if bodyText, bodyHTML, err = appendReplyQuote(deps, parent, bodyText, bodyHTML); err != nil {
					return mcp.ErrorResult("%s: quote original: %v", tool, err), nil
				}
			}

			decoded, err := decodeAttachmentsGated(deps, in.Attachments,
				draftAttachmentGate(ctx.Std, deps, tool, subject, to))
			if err != nil {
				return mcp.ErrorResult("%s: %v", tool, err), nil
			}
			tpl, mimeType, err := buildDraftTemplate(deps, subject, to, cc, in.BCC, bodyText, bodyHTML)
			if err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": "+err.Error())
			}
			_, addrKR, err := senderKeyring(deps)
			if err != nil {
				return mcp.ErrorResult("%s: %v", tool, err), nil
			}
			msg, err := deps.Session.Client.CreateDraft(ctx.Std, addrKR, gpa.CreateDraftReq{
				Message:  tpl,
				ParentID: in.InReplyTo,
				Action:   replyAction(in.ReplyAll),
			})
			if err != nil {
				return mcp.ErrorResult("%s: create draft: %v", tool, err), nil
			}
			if _, err := uploadAttachmentsAndCollectKeys(ctx.Std, deps, addrKR, msg.ID, decoded); err != nil {
				return mcp.ErrorResult("%s: %v", tool, err), nil
			}

			// Mirror the draft into the original's local thread so
			// mail_read_thread shows it alongside the conversation.
			threadID := ""
			if deps.Store != nil {
				if row, err := protonMessageToStore(msg); err == nil {
					if orig, gerr := deps.Store.GetMessage(ctx.Std, in.InReplyTo); gerr == nil && orig.ThreadID != "" {
						row.ThreadID = orig.ThreadID
					}
					row.Folder = "drafts"
					threadID = row.ThreadID
					_ = deps.Store.UpsertMessage(ctx.Std, row)
				}
			}

			return mcp.StructuredResult(draftReplyResult{
				draftResult: draftResult{
					DraftID:  msg.ID,
					Subject:  msg.Subject,
					To:       addressStrings(msg.ToList),
					CC:       addressStrings(msg.CCList),
					BCC:      addressStrings(msg.BCCList),
					MIMEType: mimeType,
				},
				InReplyTo: in.InReplyTo,
				ThreadID:  threadID,
				Quoted:    in.quote(),
			})
		},
	}
}
