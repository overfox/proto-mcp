package mcptools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// decodeBase64 is a thin wrapper for clarity at call sites that
// decode SDK-returned base64 (KeyPackets, etc.).
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// The send family. Five tools sharing one core send path:
//
//	mail_send         — compose + send (new draft → send → done)
//	mail_send_draft   — send an existing draft (mail_draft_create → send later)
//	mail_reply        — reply to one message; To = original sender (+ extra_to / cc)
//	mail_reply_all    — reply to all; CC = original To+CC minus self (+ extra_to / cc)
//	mail_forward      — forward; new To list, optional quoted original
//
// All five are decision:prompt + ttl:0 in default.yaml (the send floor
// forbids weakening that). The single Touch ID dialog shows recipients,
// subject, a body excerpt and every attachment (send_prompt.go) before
// any network call, and the handler refuses to send anything other than
// what that dialog showed (sendLedger). allowed_recipients and
// rate_limit enforcement happen in the MCP middleware between policy
// and broker (see internal/mcp/middleware.go), and allowed_recipients is
// re-checked in finalizeSend against the final recipient list.

// sendInput is the public shape for mail_send. Reply / reply_all /
// forward use variants that reference an existing message_id.
type sendInput struct {
	Subject     string                `json:"subject"`
	To          []string              `json:"to"`
	CC          []string              `json:"cc,omitempty"`
	BCC         []string              `json:"bcc,omitempty"`
	BodyText    string                `json:"body_text,omitempty"`
	BodyHTML    string                `json:"body_html,omitempty"`
	Attachments []sendAttachmentInput `json:"attachments,omitempty"`
}

type sendResult struct {
	MessageID  string   `json:"message_id"`
	Subject    string   `json:"subject"`
	Recipients []string `json:"recipients"`
	Sent       bool     `json:"sent"`
}

// sendDialogNote is appended to every send tool description.
const sendDialogNote = " The Touch ID dialog shown before sending lists every recipient (flagging " +
	"addresses outside your own domains as external), the subject, the start of the body, and every " +
	"attachment with its size; the send is refused if what would be sent differs from what the dialog showed."

func mailSend(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_send",
		Description: "Compose and send a message in one step. IRREVERSIBLE — once sent, " +
			"it cannot be unsent. Optional `attachments` array uploads files alongside " +
			"the body (each entry: filename + content_b64, or an absolute host `path`). Paths inside " +
			"attachment_path_allowlist attach as-is; any other file under the user's home folder or " +
			"/Volumes is allowed but its full path is listed in the send dialog. Paths inside a " +
			"Cowork/VM sandbox (/sessions/..., /mnt/...) are not host paths. Refuses individual " +
			"or cumulative attachment sizes exceeding max_attachment_bytes (default 25 MiB). " +
			"Refuses PGP/MIME-encrypted external recipients — send to a Proton address or " +
			"a recipient without an on-file PGP key instead." + sendDialogNote,
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"subject":     {"type": "string"},
				"to":          {"type": "array", "items": {"type": "string"}, "minItems": 1},
				"cc":          {"type": "array", "items": {"type": "string"}},
				"bcc":         {"type": "array", "items": {"type": "string"}},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"},
				"attachments": ` + attachmentInputSchemaFragment + `
			},
			"required": ["subject", "to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   extractSendRecipients,
		PromptBody:   sendPromptBodyWithDeps(deps, "mail_send"),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in sendInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_send: "+err.Error())
			}
			if in.Subject == "" || len(in.To) == 0 {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_send: subject and at least one to recipient are required")
			}
			entry, have := sendLedger.take("mail_send", raw)
			return sendCompose(ctx, deps, "mail_send", "", gpa.ReplyAction, in, ledgerGate(entry, have))
		},
	}
}

func mailSendDraft(deps Deps) mcp.Tool {
	type input struct {
		DraftID string `json:"draft_id"`
	}
	return mcp.Tool{
		Name: "mail_send_draft",
		Description: "Send an existing draft. IRREVERSIBLE. Recipients, subject, body and attachments come " +
			"from the draft itself and are read back in the Touch ID dialog. If the draft can't be loaded " +
			"for the dialog, or it is changed (e.g. by mail_draft_update) after the dialog was shown, the " +
			"send is refused." + sendDialogNote,
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"draft_id": {"type": "string"}},
			"required": ["draft_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		// For send_draft we need to fetch the draft to know
		// recipients. The Recipients extractor signature is
		// pure-args, so we can't reach the server here. Leave nil:
		// allowed_recipients enforcement still works once the
		// handler runs and validates recipients before SendDraft.
		Recipients: nil,
		PromptBody: func(args json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(args, &in)
			title := mcp.SanitizePromptText("Approve mail_send_draft?", 120)
			ctx, cancel := context.WithTimeout(context.Background(), promptServerFetch)
			defer cancel()
			draft, plain, err := fetchDraftPlain(ctx, deps, in.DraftID)
			if err != nil {
				reason := "could not load draft " + shortID(in.DraftID) + ": " + err.Error()
				sendLedger.record("mail_send_draft", args, sendApproval{failure: reason})
				return title, formatSendPrompt(deps, sendPromptSpec{
					Action:   "Send draft",
					Tool:     "mail_send_draft",
					Subject:  "(unknown)",
					Warnings: []string{"COULD NOT LOAD THE DRAFT — approving will NOT send it (" + clipRunes(err.Error(), 100) + ")"},
				})
			}
			sendLedger.record("mail_send_draft", args, sendApproval{draftDigest: draftDigest(draft, plain)})
			return title, formatSendPrompt(deps, draftPromptSpec(draft, plain))
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_send_draft: "+err.Error())
			}
			if in.DraftID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_send_draft: draft_id is required")
			}
			entry, have := sendLedger.take("mail_send_draft", raw)
			if !have {
				return mcp.ErrorResult("mail_send_draft refused: %s", errNoApprovalRecord), nil
			}
			if entry.failure != "" {
				return mcp.ErrorResult("mail_send_draft refused: the approval dialog could not show the draft (%s); "+
					"nothing was sent", entry.failure), nil
			}
			return sendDraftByID(ctx, deps, "mail_send_draft", in.DraftID, entry.draftDigest)
		},
	}
}

// replyInput is the shared input for mail_reply / mail_reply_all.
// ExtraTo / CC add recipients on top of the ones derived from the
// parent message.
type replyInput struct {
	InReplyTo   string                `json:"in_reply_to"`
	ExtraTo     []string              `json:"extra_to,omitempty"`
	CC          []string              `json:"cc,omitempty"`
	BodyText    string                `json:"body_text,omitempty"`
	BodyHTML    string                `json:"body_html,omitempty"`
	Attachments []sendAttachmentInput `json:"attachments,omitempty"`
	// IncludeQuote appends the standard "On <date>, <sender> wrote:"
	// quote of the original. nil → true.
	IncludeQuote *bool `json:"include_quote,omitempty"`
}

func (in replyInput) quote() bool { return in.IncludeQuote == nil || *in.IncludeQuote }

const replyInputSchema = `{
	"type": "object",
	"properties": {
		"in_reply_to": {"type": "string"},
		"extra_to":    {"type": "array", "items": {"type": "string"}, "description": "Additional To recipients beyond the ones derived from the original message."},
		"cc":          {"type": "array", "items": {"type": "string"}, "description": "Additional CC recipients."},
		"body_text":   {"type": "string"},
		"body_html":   {"type": "string"},
		"attachments": ` + attachmentInputSchemaFragment + `,
		"include_quote": {"type": "boolean", "default": true, "description": "Append the quoted original below your text (\"On <date>, <sender> wrote:\" + > lines). Default true."}
	},
	"required": ["in_reply_to"],
	"additionalProperties": false
}`

// extractReplyRecipients exposes the args-resident reply recipients
// (extra_to + cc) to the middleware allowlist stage. Parent-derived
// recipients are checked in finalizeSend.
func extractReplyRecipients(args json.RawMessage) []string {
	var in replyInput
	if err := json.Unmarshal(args, &in); err != nil {
		return nil
	}
	var out []string
	for _, entry := range append(append([]string{}, in.ExtraTo...), in.CC...) {
		out = append(out, normalizeRecipientList(entry)...)
	}
	return out
}

func mailReply(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_reply",
		Description: "Reply to a message in its thread. IRREVERSIBLE once sent. To = the original's Reply-To " +
			"(else its sender; replying to your own sent message goes to its recipients), plus any " +
			"`extra_to` addresses; optional `cc` adds CC recipients. Threading is kept: the reply is linked to " +
			"the original (In-Reply-To/References, same Proton conversation) and quotes it unless include_quote is false. " +
			"To prepare a reply for review instead of sending, use mail_draft_reply. " +
			"Subject prefixed Re: if not already. Optional `attachments` array attaches " +
			"new files (does NOT carry over parent attachments — use mail_forward for that)." + sendDialogNote,
		InputSchema:  json.RawMessage(replyInputSchema),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   extractReplyRecipients,
		PromptBody:   replyPromptBody(deps, "mail_reply", false),
		Handler:      replyHandler(deps, "mail_reply", false),
	}
}

func mailReplyAll(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_reply_all",
		Description: "Reply-all to a message. IRREVERSIBLE. " +
			"To = original Reply-To / sender (+ `extra_to`). CC = original To+CC minus your own addresses (+ `cc`). " +
			"Kept in the same thread and quotes the original unless include_quote is false. " +
			"BCC dropped (BCC by definition not visible to other recipients). " +
			"Optional `attachments` array — same shape as mail_send." + sendDialogNote,
		InputSchema:  json.RawMessage(replyInputSchema),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients:   extractReplyRecipients,
		PromptBody:   replyPromptBody(deps, "mail_reply_all", true),
		Handler:      replyHandler(deps, "mail_reply_all", true),
	}
}

// replyParent is the subset of a parent message a reply needs.
type replyParent struct {
	Sender  string
	ReplyTo []string // the original's Reply-To; empty → reply to Sender
	To, CC  []string
	Subject string
}

func replyParentFromMessage(m gpa.Message) replyParent {
	p := replyParent{To: addressStrings(m.ToList), CC: addressStrings(m.CCList), Subject: m.Subject,
		ReplyTo: addressStrings(m.ReplyTos)}
	if m.Sender != nil {
		p.Sender = m.Sender.Address
	}
	return p
}

// lookupReplyParent resolves the parent for the reply dialog: the
// server first (the same source the handler uses), else the local
// mirror. ok=false when neither can answer.
func lookupReplyParent(deps Deps, messageID string) (replyParent, bool) {
	if messageID == "" {
		return replyParent{}, false
	}
	if deps.Session != nil && deps.Session.Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), promptServerFetch)
		m, err := deps.Session.Client.GetMessage(ctx, messageID)
		cancel()
		if err == nil {
			return replyParentFromMessage(m), true
		}
	}
	if deps.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), promptLookupTimeout)
		defer cancel()
		m, err := deps.Store.GetMessage(ctx, messageID)
		if err == nil && m.FromAddress != "" {
			return replyParent{
				Sender:  m.FromAddress,
				To:      addressesFromJSON(m.ToJSON),
				CC:      addressesFromJSON(m.CcJSON),
				Subject: m.Subject,
			}, true
		}
	}
	return replyParent{}, false
}

// replyRecipients computes who a reply goes to. Shared by the dialog
// and the handler so the two can be compared exactly.
func replyRecipients(p replyParent, self []string, replyAll bool, extraTo, extraCC []string) (to, cc []string) {
	seen := map[string]bool{}
	add := func(list *[]string, addr string, skipSelf bool) {
		key := strings.ToLower(strings.TrimSpace(addr))
		if key == "" || seen[key] || (skipSelf && contains(self, key)) {
			return
		}
		seen[key] = true
		*list = append(*list, addr)
	}
	for _, a := range replyPrimary(p, self) {
		add(&to, a, false)
	}
	for _, a := range extraTo {
		add(&to, a, false)
	}
	if replyAll {
		for _, a := range append(append([]string{}, p.To...), p.CC...) {
			add(&cc, a, true)
		}
	}
	for _, a := range extraCC {
		add(&cc, a, false)
	}
	return to, cc
}

// replyPrimary is who a reply is addressed to, the way mail clients do
// it: the original's Reply-To if it set one (mailing lists, ticket
// systems, "reply to my other address"), else its sender. Replying to
// a message you sent yourself continues the conversation with its
// recipients rather than addressing you.
func replyPrimary(p replyParent, self []string) []string {
	if contains(self, strings.ToLower(strings.TrimSpace(p.Sender))) && len(p.To) > 0 {
		return p.To
	}
	if len(p.ReplyTo) > 0 {
		return p.ReplyTo
	}
	return []string{p.Sender}
}

// replyPrefix matches the reply markers clients put on subjects
// ("Re:", "RE:", "Re[2]:", "AW:", "SV:", "Antw:"), so a reply to a
// reply doesn't become "Re: Re: …" and threads keep one subject.
var replyPrefix = regexp.MustCompile(`(?i)^\s*(re|aw|sv|vs|antw|ref)(\[\d+\])?\s*:`)

func replySubject(s string) string {
	if replyPrefix.MatchString(s) {
		return strings.TrimSpace(s)
	}
	return "Re: " + strings.TrimSpace(s)
}

// replyAction is the Proton draft action for a reply. It's what makes
// the server mark the original Replied / Replied-all.
func replyAction(replyAll bool) gpa.CreateDraftAction {
	if replyAll {
		return gpa.ReplyAllAction
	}
	return gpa.ReplyAction
}

func replyPromptBody(deps Deps, tool string, replyAll bool) func(json.RawMessage) (string, string) {
	return func(args json.RawMessage) (string, string) {
		var in replyInput
		_ = json.Unmarshal(args, &in)
		spec := sendPromptSpec{Action: "Reply", Tool: tool, BodyText: in.BodyText, BodyHTML: in.BodyHTML}
		if replyAll {
			spec.Action = "Reply-all"
		}
		var rec sendApproval
		if p, ok := lookupReplyParent(deps, in.InReplyTo); ok {
			spec.To, spec.CC = replyRecipients(p, selfAddresses(deps), replyAll, in.ExtraTo, in.CC)
			spec.Subject = replySubject(p.Subject)
			rec.recipients = recipientSet(spec.To, spec.CC)
			if in.quote() {
				spec.BodySuffix = "+ quoted original"
			}
		} else {
			rec.failure = "could not resolve original message " + shortID(in.InReplyTo)
			spec.Warnings = append(spec.Warnings,
				"COULD NOT RESOLVE THE ORIGINAL MESSAGE — approving will NOT send")
			spec.To, spec.CC = in.ExtraTo, in.CC
			spec.Subject = "(unknown)"
		}
		for _, a := range append(append([]string{}, in.ExtraTo...), in.CC...) {
			if err := ensureValidEmail(a); err != nil {
				spec.Warnings = append(spec.Warnings, "invalid address "+clipRunes(a, 60)+" — the call will be refused")
			}
		}
		var outside []string
		spec.Attachments, outside = describeAttachments(deps, in.Attachments)
		rec.outsidePaths = pathSet(outside)
		sendLedger.record(tool, args, rec)
		return mcp.SanitizePromptText("Approve "+tool+"?", 120), formatSendPrompt(deps, spec)
	}
}

func replyHandler(deps Deps, tool string, replyAll bool) mcp.Handler {
	return func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
		var in replyInput
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": "+err.Error())
		}
		if in.InReplyTo == "" {
			return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": in_reply_to is required")
		}
		for _, a := range append(append([]string{}, in.ExtraTo...), in.CC...) {
			if err := ensureValidEmail(a); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, tool+": "+err.Error())
			}
		}
		entry, have := sendLedger.take(tool, raw)
		if !have {
			return mcp.ErrorResult("%s refused: %s", tool, errNoApprovalRecord), nil
		}
		if entry.failure != "" {
			return mcp.ErrorResult("%s refused: the approval dialog could not show the recipients (%s); "+
				"nothing was sent", tool, entry.failure), nil
		}
		return sendReply(ctx, deps, tool, in, replyAll, entry)
	}
}

func mailForward(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_forward",
		Description: "Forward a message to new recipients. IRREVERSIBLE. " +
			"Subject prefixed Fwd:. Body is the new content; set `include_original: true` to append " +
			"the standard quoted original (From/Date/Subject/To/Cc header block + the original's text body). " +
			"Optional `attachments` array attaches new files. Set " +
			"`include_parent_attachments: true` to carry over the parent message's " +
			"attachments via re-encrypted session keys (no byte-level round-trip; " +
			"the server keeps the encrypted bytes and just re-keys for the new draft); " +
			"they are listed in the send dialog." + sendDialogNote,
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"forward_of":                 {"type": "string"},
				"to":                         {"type": "array", "items": {"type": "string"}, "minItems": 1},
				"cc":                         {"type": "array", "items": {"type": "string"}},
				"bcc":                        {"type": "array", "items": {"type": "string"}},
				"body_text":                  {"type": "string"},
				"body_html":                  {"type": "string"},
				"attachments":                ` + attachmentInputSchemaFragment + `,
				"include_parent_attachments": {"type": "boolean", "default": false},
				"include_original":           {"type": "boolean", "default": false, "description": "Append the quoted original message (header block + text body) below body."}
			},
			"required": ["forward_of", "to"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(sendResultSchema),
		Recipients: func(args json.RawMessage) []string {
			var in forwardInput
			if err := json.Unmarshal(args, &in); err != nil {
				return nil
			}
			var out []string
			for _, entry := range append(append(append([]string{}, in.To...), in.CC...), in.BCC...) {
				out = append(out, normalizeRecipientList(entry)...)
			}
			return out
		},
		PromptBody: forwardPromptBody(deps),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in forwardInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_forward: "+err.Error())
			}
			if in.ForwardOf == "" || len(in.To) == 0 {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_forward: forward_of and at least one to recipient are required")
			}
			entry, have := sendLedger.take("mail_forward", raw)
			if have && entry.failure != "" {
				return mcp.ErrorResult("mail_forward refused: the approval dialog could not show the forwarded "+
					"attachments (%s); nothing was sent", entry.failure), nil
			}
			return sendForward(ctx, deps, in, entry, have)
		},
	}
}

func forwardPromptBody(deps Deps) func(json.RawMessage) (string, string) {
	return func(args json.RawMessage) (string, string) {
		var in forwardInput
		_ = json.Unmarshal(args, &in)
		spec := sendPromptSpec{
			Action: "Forward", Tool: "mail_forward",
			To: in.To, CC: in.CC, BCC: in.BCC,
			BodyText: in.BodyText, BodyHTML: in.BodyHTML,
		}
		var rec sendApproval

		var parent *gpa.Message
		if deps.Session != nil && deps.Session.Client != nil && in.ForwardOf != "" {
			ctx, cancel := context.WithTimeout(context.Background(), promptServerFetch)
			if m, err := deps.Session.Client.GetMessage(ctx, in.ForwardOf); err == nil {
				parent = &m
			}
			cancel()
		}
		if parent != nil {
			spec.Subject = forwardSubject(parent.Subject)
		} else {
			spec.Subject = "Fwd: " + lookupSubject(deps, in.ForwardOf)
		}
		if in.IncludeOriginal {
			from := ""
			if parent != nil && parent.Sender != nil {
				from = " from " + parent.Sender.Address
			}
			spec.BodySuffix = "+ quoted original message" + from
		}
		if in.IncludeParentAttachments {
			if parent == nil {
				rec.failure = "could not load the original message to list its attachments"
				spec.Warnings = append(spec.Warnings,
					"COULD NOT LIST THE ORIGINAL'S ATTACHMENTS — approving will NOT send")
			} else {
				for _, a := range parent.Attachments {
					spec.Attachments = append(spec.Attachments, promptAttachment{
						Name: sanitize.Filename(a.Name), Size: a.Size, Parent: true,
					})
					rec.parentAttachmentIDs = append(rec.parentAttachmentIDs, a.ID)
				}
				sort.Strings(rec.parentAttachmentIDs)
			}
		}
		newAtts, outside := describeAttachments(deps, in.Attachments)
		spec.Attachments = append(spec.Attachments, newAtts...)
		rec.outsidePaths = pathSet(outside)
		sendLedger.record("mail_forward", args, rec)
		return mcp.SanitizePromptText("Approve mail_forward?", 120), formatSendPrompt(deps, spec)
	}
}

func forwardSubject(s string) string {
	if !strings.HasPrefix(strings.ToLower(s), "fwd:") {
		return "Fwd: " + s
	}
	return s
}

// forwardInput is the parsed input for mail_forward. Hoisted to the
// package level so sendForward and the inner Recipients/PromptBody
// closures share a single struct shape. Phase 8/B.
//
// Phase 8/C added IncludeParentAttachments — when true, mail_forward
// carries the parent message's attachments over to the new draft
// without a byte-round-trip via CreateDraftReq.AttachmentKeyPackets.
// Any explicit `attachments` provided on the input get uploaded
// alongside. IncludeOriginal appends the quoted original body.
type forwardInput struct {
	ForwardOf                string                `json:"forward_of"`
	To                       []string              `json:"to"`
	CC                       []string              `json:"cc,omitempty"`
	BCC                      []string              `json:"bcc,omitempty"`
	BodyText                 string                `json:"body_text,omitempty"`
	BodyHTML                 string                `json:"body_html,omitempty"`
	Attachments              []sendAttachmentInput `json:"attachments,omitempty"`
	IncludeParentAttachments bool                  `json:"include_parent_attachments,omitempty"`
	IncludeOriginal          bool                  `json:"include_original,omitempty"`
}

// ============================================================
// Helpers
// ============================================================

// extractSendRecipients pulls To+CC+BCC out of a mail_send arg
// payload for the allowed_recipients middleware stage.
//
// SECURITY D7: each entry runs through mail.ParseAddressList rather
// than being passed raw. That:
//   - Strips display names ("Alice <alice@example.com>" → "alice@example.com")
//     so the allowlist comparison sees the bare address.
//   - Explodes any multi-address entries ("a@x.com,b@y.com" → ["a@x.com",
//     "b@y.com"]) so a smuggled second recipient lands in the
//     allowlist check rather than getting hidden in the display
//     portion. (The actual SDK send path uses mail.ParseAddress
//     singular and rejects multi-addr entries; this is defense
//     in depth so the allowlist sees what the SDK would actually
//     attempt.)
//
// Returns nil on parse failure — the handler's own validation will
// catch that later with a clearer error message.
func extractSendRecipients(args json.RawMessage) []string {
	var in sendInput
	if err := json.Unmarshal(args, &in); err != nil {
		return nil
	}
	out := make([]string, 0, len(in.To)+len(in.CC)+len(in.BCC))
	for _, entry := range append(append(append([]string{}, in.To...), in.CC...), in.BCC...) {
		out = append(out, normalizeRecipientList(entry)...)
	}
	return out
}

// normalizeRecipientList parses one address-list string into bare
// .Address values. If parsing fails completely, returns the raw
// input as a single-element slice so the allowlist still sees
// SOMETHING (rather than the empty list, which would skip the
// check entirely — fail closed, not open).
func normalizeRecipientList(s string) []string {
	addrs, err := mail.ParseAddressList(s)
	if err != nil || len(addrs) == 0 {
		return []string{s}
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a != nil && a.Address != "" {
			out = append(out, a.Address)
		}
	}
	if len(out) == 0 {
		return []string{s}
	}
	return out
}

// sendPromptBodyWithDeps returns mail_send's PromptBody: recipients,
// subject, body excerpt and every attachment (send_prompt.go), and
// records the out-of-allowlist paths it listed for the handler.
func sendPromptBodyWithDeps(deps Deps, toolName string) func(json.RawMessage) (string, string) {
	return func(args json.RawMessage) (string, string) {
		var in sendInput
		_ = json.Unmarshal(args, &in)
		spec := sendPromptSpec{
			Action: "Send", Tool: toolName,
			To: in.To, CC: in.CC, BCC: in.BCC,
			Subject:  in.Subject,
			BodyText: in.BodyText, BodyHTML: in.BodyHTML,
		}
		var outside []string
		spec.Attachments, outside = describeAttachments(deps, in.Attachments)
		sendLedger.record(toolName, args, sendApproval{outsidePaths: pathSet(outside)})
		return mcp.SanitizePromptText("Approve "+toolName+"?", 120), formatSendPrompt(deps, spec)
	}
}

// sendCompose is mail_send: create a draft, send it, return.
// Phase 8/B — uploads attachments to the draft between CreateDraft
// and SendDraft so they ride on the same send call. gate approves
// out-of-allowlist path attachments (send family: they must have been
// listed in the approved dialog).
func sendCompose(ctx mcp.Context, deps Deps, toolName, parentID string, action gpa.CreateDraftAction, in sendInput, gate attachmentGate) (*mcp.ToolResult, error) {
	decoded, err := decodeAttachmentsGated(deps, in.Attachments, gate)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	tpl, mimeType, err := buildDraftTemplate(deps, in.Subject, in.To, in.CC, in.BCC, in.BodyText, in.BodyHTML)
	if err != nil {
		return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
	}
	_, addrKR, err := senderKeyring(deps)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	createReq := gpa.CreateDraftReq{
		Message:  tpl,
		ParentID: parentID,
		Action:   action,
	}
	draft, err := deps.Session.Client.CreateDraft(ctx.Std, addrKR, createReq)
	if err != nil {
		return mcp.ErrorResult("%s: create draft: %v", toolName, err), nil
	}
	attKeys, err := uploadAttachmentsAndCollectKeys(ctx.Std, deps, addrKR, draft.ID, decoded)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	return finalizeSend(ctx, deps, toolName, addrKR, draft, tpl, mimeType, allRecipients(in.To, in.CC, in.BCC), attKeys)
}

// sendDraftByID is mail_send_draft: load draft, verify it is the draft
// the user approved, send.
//
// Draft-swap protection: the dialog fetched the draft and recorded
// draftDigest(recipients, subject, MIME type, decrypted body,
// attachment IDs). A mail_draft_update landing between the dialog and
// this fetch would change what gets sent, so the digest is recomputed
// here and any difference refuses the send.
//
// Phase 8/B — existing draft attachments are already uploaded to
// the server; we just need to recover their session keys via the
// sender keyring so AddTextPackage can re-encrypt them per
// recipient. No new upload, no attachment input on this tool.
func sendDraftByID(ctx mcp.Context, deps Deps, toolName, draftID, approvedDigest string) (*mcp.ToolResult, error) {
	// PROTO-125: draft.Body is armored CIPHERTEXT (CreateDraft encrypted
	// it to us). finalizeSend → AddTextPackage treats its body argument
	// as PLAINTEXT and encrypts it again — double-encrypting the message
	// into garbage. fetchDraftPlain decrypts it back to the original
	// plaintext so the send path encrypts it exactly once.
	draft, plainBody, err := fetchDraftPlain(ctx.Std, deps, draftID)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	if approvedDigest == "" || draftDigest(draft, plainBody) != approvedDigest {
		return mcp.ErrorResult("%s refused: the draft changed after you approved it (recipients, subject, "+
			"body or attachments differ from what the Touch ID dialog showed); nothing was sent — "+
			"call mail_send_draft again to review the current draft", toolName), nil
	}
	_, addrKR, err := senderKeyring(deps)
	if err != nil {
		return mcp.ErrorResult("%s: %v", toolName, err), nil
	}
	mimeType := "text/plain"
	if string(draft.MIMEType) == "text/html" {
		mimeType = "text/html"
	}
	recipients := allRecipients(
		addressStrings(draft.ToList),
		addressStrings(draft.CCList),
		addressStrings(draft.BCCList),
	)
	tpl := gpa.DraftTemplate{
		Subject:  draft.Subject,
		Sender:   draft.Sender,
		ToList:   draft.ToList,
		CCList:   draft.CCList,
		BCCList:  draft.BCCList,
		Body:     plainBody,
		MIMEType: draft.MIMEType,
	}

	// Recover session keys for existing attachments on the draft.
	attKeys, err := recoverDraftAttachmentKeys(addrKR, draft)
	if err != nil {
		return mcp.ErrorResult("%s: recover draft attachment keys: %v", toolName, err), nil
	}

	return finalizeSend(ctx, deps, toolName, addrKR, draft, tpl, mimeType, recipients, attKeys)
}

// recoverDraftAttachmentKeys returns the (attachment_id → session
// key) map for every attachment already on the given draft. Used
// by mail_send_draft (and the 8/C forward shortcut) so existing
// attachments fan out per recipient inside AddTextPackage.
//
// SDK shape: each Attachment.KeyPackets is the base64-encoded
// session key encrypted to the sender's public key. Decrypting it
// with addrKR gets us the symmetric session key.
func recoverDraftAttachmentKeys(addrKR *crypto.KeyRing, draft gpa.Message) (map[string]*crypto.SessionKey, error) {
	if len(draft.Attachments) == 0 {
		return nil, nil
	}
	out := make(map[string]*crypto.SessionKey, len(draft.Attachments))
	for _, a := range draft.Attachments {
		kpBytes, err := decodeBase64(a.KeyPackets)
		if err != nil {
			return nil, fmt.Errorf("attachment %s (%s): decode KeyPackets: %w", a.ID, a.Name, err)
		}
		sk, err := addrKR.DecryptSessionKey(kpBytes)
		if err != nil {
			return nil, fmt.Errorf("attachment %s (%s): %w", a.ID, a.Name, err)
		}
		out[a.ID] = sk
	}
	return out, nil
}

// sendReply is the reply / reply_all body. Fetches the original,
// builds the recipient lists (parent-derived + extra_to / cc), checks
// they are exactly the ones the approval dialog showed, and calls
// sendCompose with ParentID. Phase 8/B — accepts attachments.
func sendReply(ctx mcp.Context, deps Deps, toolName string, in replyInput, replyAll bool, entry sendApproval) (*mcp.ToolResult, error) {
	parent, err := deps.Session.Client.GetMessage(ctx.Std, in.InReplyTo)
	if err != nil {
		return mcp.ErrorResult("%s: fetch parent: %v", toolName, err), nil
	}
	p := replyParentFromMessage(parent)
	to, cc := replyRecipients(p, selfAddresses(deps), replyAll, in.ExtraTo, in.CC)
	if got := recipientSet(to, cc); !sameStrings(got, entry.recipients) {
		return mcp.ErrorResult("%s refused: the recipients would be %s but the approval dialog showed %s; "+
			"nothing was sent — retry to review the current recipients",
			toolName, strings.Join(got, ", "), strings.Join(entry.recipients, ", ")), nil
	}

	bodyText, bodyHTML := in.BodyText, in.BodyHTML
	if in.quote() {
		if bodyText, bodyHTML, err = appendReplyQuote(deps, parent, bodyText, bodyHTML); err != nil {
			return mcp.ErrorResult("%s: quote original: %v", toolName, err), nil
		}
	}
	return sendCompose(ctx, deps, toolName, in.InReplyTo, replyAction(replyAll), sendInput{
		Subject:     replySubject(p.Subject),
		To:          to,
		CC:          cc,
		BodyText:    bodyText,
		BodyHTML:    bodyHTML,
		Attachments: in.Attachments,
	}, ledgerGate(entry, true))
}

// sendForward is the forward body. Subject Fwd:-prefixed; body is the
// caller's, plus the quoted original when include_original is set.
// Phase 8/B — accepts new attachments. Phase 8/C — when
// include_parent_attachments is set, carries parent attachments over
// via re-encrypted session keys (no byte-level round-trip); those must
// match the ones the approval dialog listed.
func sendForward(ctx mcp.Context, deps Deps, in forwardInput, entry sendApproval, have bool) (*mcp.ToolResult, error) {
	parent, err := deps.Session.Client.GetMessage(ctx.Std, in.ForwardOf)
	if err != nil {
		return mcp.ErrorResult("mail_forward: fetch parent: %v", err), nil
	}
	subject := forwardSubject(parent.Subject)

	bodyText, bodyHTML := in.BodyText, in.BodyHTML
	if in.IncludeOriginal {
		quoted, qerr := quotedOriginal(deps, parent)
		if qerr != nil {
			return mcp.ErrorResult("mail_forward: include_original: %v", qerr), nil
		}
		if bodyHTML != "" {
			bodyHTML += "<br><br><blockquote>" +
				strings.ReplaceAll(html.EscapeString(quoted), "\n", "<br>") + "</blockquote>"
		} else {
			if bodyText != "" {
				bodyText += "\n\n"
			}
			bodyText += quoted
		}
	}
	gate := ledgerGate(entry, have)

	// Fast path: no parent-attachment carryover. Reuse sendCompose
	// — identical behavior to the 8/B contract.
	if !in.IncludeParentAttachments || len(parent.Attachments) == 0 {
		if in.IncludeParentAttachments && have && len(entry.parentAttachmentIDs) != 0 {
			return mcp.ErrorResult("mail_forward refused: the original's attachments changed after approval; nothing was sent"), nil
		}
		return sendCompose(ctx, deps, "mail_forward", in.ForwardOf, gpa.ForwardAction, sendInput{
			Subject:     subject,
			To:          in.To,
			CC:          in.CC,
			BCC:         in.BCC,
			BodyText:    bodyText,
			BodyHTML:    bodyHTML,
			Attachments: in.Attachments,
		}, gate)
	}

	// The parent attachments carried over must be exactly the ones the
	// dialog listed.
	ids := make([]string, 0, len(parent.Attachments))
	for _, a := range parent.Attachments {
		ids = append(ids, a.ID)
	}
	sort.Strings(ids)
	if !have || !sameStrings(ids, entry.parentAttachmentIDs) {
		return mcp.ErrorResult("mail_forward refused: the original's attachments don't match what the approval " +
			"dialog listed; nothing was sent — retry to review them"), nil
	}

	// Parent-attachment carryover path. Pre-validate the new
	// attachments first so we fail fast.
	newDecoded, err := decodeAttachmentsGated(deps, in.Attachments, gate)
	if err != nil {
		return mcp.ErrorResult("mail_forward: %v", err), nil
	}

	// Build the parent-attachment KeyPackets list: decrypt each
	// parent attachment's session key with our address keyring,
	// then re-encrypt it back to ourselves (same keyring). The
	// server uses these packets to attach the existing encrypted
	// data blobs to the new draft without re-uploading bytes.
	_, addrKR, err := senderKeyring(deps)
	if err != nil {
		return mcp.ErrorResult("mail_forward: %v", err), nil
	}
	parentKPs, err := reencryptParentKeyPackets(addrKR, parent)
	if err != nil {
		return mcp.ErrorResult("mail_forward: re-encrypt parent attachment keys: %v", err), nil
	}

	tpl, mimeType, err := buildDraftTemplate(deps, subject, in.To, in.CC, in.BCC, bodyText, bodyHTML)
	if err != nil {
		return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_forward: "+err.Error())
	}

	draft, err := deps.Session.Client.CreateDraft(ctx.Std, addrKR, gpa.CreateDraftReq{
		Message:              tpl,
		ParentID:             in.ForwardOf,
		Action:               gpa.ForwardAction,
		AttachmentKeyPackets: parentKPs,
	})
	if err != nil {
		return mcp.ErrorResult("mail_forward: create draft: %v", err), nil
	}

	// After CreateDraft the parent attachments are server-side
	// already; recover their session keys so they fan out per
	// recipient in AddTextPackage. The list comes back on the new
	// draft (re-fetch it to get fresh Attachments).
	freshDraft, err := deps.Session.Client.GetMessage(ctx.Std, draft.ID)
	if err != nil {
		return mcp.ErrorResult("mail_forward: refresh draft: %v", err), nil
	}
	parentAttKeys, err := recoverDraftAttachmentKeys(addrKR, freshDraft)
	if err != nil {
		return mcp.ErrorResult("mail_forward: recover draft keys: %v", err), nil
	}

	// Upload any NEW attachments alongside.
	newAttKeys, err := uploadAttachmentsAndCollectKeys(ctx.Std, deps, addrKR, draft.ID, newDecoded)
	if err != nil {
		return mcp.ErrorResult("mail_forward: %v", err), nil
	}

	// Merge maps.
	merged := make(map[string]*crypto.SessionKey, len(parentAttKeys)+len(newAttKeys))
	for k, v := range parentAttKeys {
		merged[k] = v
	}
	for k, v := range newAttKeys {
		merged[k] = v
	}

	return finalizeSend(ctx, deps, "mail_forward", addrKR, draft, tpl, mimeType, allRecipients(in.To, in.CC, in.BCC), merged)
}

// quotedOriginal renders the standard forwarded-message block: a
// header block followed by the original's text body (decrypted with
// the receiving address's keyring).
func quotedOriginal(deps Deps, parent gpa.Message) (string, error) {
	plain, err := decryptParentBody(deps, parent)
	if err != nil {
		return "", err
	}
	return formatQuotedOriginal(parent, plain), nil
}

// decryptParentBody decrypts the original with the keyring of the
// address that received it.
func decryptParentBody(deps Deps, parent gpa.Message) (string, error) {
	if deps.Session == nil {
		return "", errors.New("no active session")
	}
	kr, ok := deps.Session.AddrKRs[parent.AddressID]
	if !ok || kr == nil {
		return "", fmt.Errorf("no keyring for address %s", parent.AddressID)
	}
	plain, err := parent.Decrypt(kr)
	if err != nil {
		return "", fmt.Errorf("decrypt original: %w", err)
	}
	return string(plain), nil
}

// appendReplyQuote adds the quoted original below the caller's text:
// "On <date>, <sender> wrote:" + "> " lines for plain text, the same
// inside a <blockquote> for HTML.
func appendReplyQuote(deps Deps, parent gpa.Message, bodyText, bodyHTML string) (string, string, error) {
	body, err := decryptParentBody(deps, parent)
	if err != nil {
		return "", "", err
	}
	header, text := replyQuoteParts(parent, body)
	if bodyHTML != "" {
		bodyHTML += "<br><br><div>" + html.EscapeString(header) + "</div>" +
			`<blockquote style="margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex">` +
			strings.ReplaceAll(html.EscapeString(text), "\n", "<br>") + "</blockquote>"
		return bodyText, bodyHTML, nil
	}
	if bodyText != "" {
		bodyText += "\n\n"
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if l == "" {
			lines[i] = ">"
		} else {
			lines[i] = "> " + l
		}
	}
	return bodyText + header + "\n" + strings.Join(lines, "\n"), bodyHTML, nil
}

// replyQuoteParts returns the attribution line and the original's
// text (control characters stripped) for a reply quote.
func replyQuoteParts(parent gpa.Message, body string) (header, text string) {
	who := "someone"
	if parent.Sender != nil {
		who = parent.Sender.Address
		if parent.Sender.Name != "" {
			who = parent.Sender.Name + " <" + parent.Sender.Address + ">"
		}
	}
	header = who + " wrote:"
	if parent.Time != 0 {
		header = "On " + time.Unix(parent.Time, 0).Format("Mon, 2 Jan 2006 at 15:04") + ", " + header
	}
	return header, strings.TrimRight(quoteText(parent, body), "\n")
}

// quoteText converts a decrypted original to line-preserving plain
// text with control characters removed.
func quoteText(parent gpa.Message, body string) string {
	var text string
	switch mt := string(parent.MIMEType); {
	case strings.HasPrefix(mt, "text/plain"):
		text = body
	case strings.HasPrefix(mt, "text/html"):
		text = htmlToQuoteText(body)
	default:
		text = sanitize.Text(body)
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f && (r < 0x80 || r > 0x9f)) {
			return r
		}
		return -1
	}, strings.ReplaceAll(text, "\r\n", "\n"))
}

// formatQuotedOriginal builds the forward quote from an
// already-decrypted body.
func formatQuotedOriginal(parent gpa.Message, body string) string {
	text := quoteText(parent, body)
	fmtAddr := func(a *mail.Address) string {
		if a == nil {
			return ""
		}
		if a.Name != "" {
			return a.Name + " <" + a.Address + ">"
		}
		return a.Address
	}
	fmtList := func(l []*mail.Address) string {
		out := make([]string, 0, len(l))
		for _, a := range l {
			if s := fmtAddr(a); s != "" {
				out = append(out, s)
			}
		}
		return strings.Join(out, ", ")
	}
	var b strings.Builder
	b.WriteString("---------- Forwarded message ----------\n")
	b.WriteString("From: " + fmtAddr(parent.Sender) + "\n")
	if parent.Time != 0 {
		b.WriteString("Date: " + time.Unix(parent.Time, 0).Format(time.RFC1123Z) + "\n")
	}
	b.WriteString("Subject: " + parent.Subject + "\n")
	b.WriteString("To: " + fmtList(parent.ToList) + "\n")
	if cc := fmtList(parent.CCList); cc != "" {
		b.WriteString("Cc: " + cc + "\n")
	}
	b.WriteString("\n")
	b.WriteString(strings.TrimRight(text, "\n"))
	return b.String()
}

var (
	htmlBreaks    = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/li|/tr|/h[1-6])\s*/?>`)
	htmlTags      = regexp.MustCompile(`(?s)<[^>]*>`)
	htmlStyleTags = regexp.MustCompile(`(?is)<(style|script)\b[^>]*>.*?</\s*(style|script)\s*>`)
	blankRuns     = regexp.MustCompile(`\n{3,}`)
)

// htmlToQuoteText is a line-preserving HTML → text conversion for the
// quoted original (sanitize.Text collapses all whitespace, which is
// right for snippets but mangles a quoted email).
func htmlToQuoteText(s string) string {
	s = htmlStyleTags.ReplaceAllString(s, "")
	s = htmlBreaks.ReplaceAllString(s, "\n")
	s = htmlTags.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.TrimSpace(blankRuns.ReplaceAllString(strings.Join(lines, "\n"), "\n\n"))
}

// reencryptParentKeyPackets reads each parent attachment's
// (base64-encoded) KeyPackets, decrypts it to the bare session key
// via the user's keyring, and re-encrypts it back to the same
// keyring — returning the new base64-encoded packets in the same
// order as parent.Attachments. The list is what
// CreateDraftReq.AttachmentKeyPackets expects.
//
// Why decrypt + re-encrypt when the keyring is the same? Two
// reasons: (1) the SDK contract says "encrypted to the sender",
// not "the parent's recipient-encoded packets verbatim"; (2)
// future multi-address handling (parent received on one address,
// forwarded from another) reuses this exact code path.
func reencryptParentKeyPackets(addrKR *crypto.KeyRing, parent gpa.Message) ([]string, error) {
	out := make([]string, 0, len(parent.Attachments))
	for i, a := range parent.Attachments {
		kpBytes, err := decodeBase64(a.KeyPackets)
		if err != nil {
			return nil, fmt.Errorf("attachment %d (%s): decode KeyPackets: %w", i, a.Name, err)
		}
		sk, err := addrKR.DecryptSessionKey(kpBytes)
		if err != nil {
			return nil, fmt.Errorf("attachment %d (%s): decrypt session key: %w", i, a.Name, err)
		}
		enc, err := addrKR.EncryptSessionKey(sk)
		if err != nil {
			return nil, fmt.Errorf("attachment %d (%s): re-encrypt session key: %w", i, a.Name, err)
		}
		out = append(out, base64.StdEncoding.EncodeToString(enc))
	}
	return out, nil
}

// decryptDraftBody turns the armored ciphertext stored on a draft
// (CreateDraft encrypts the body to the sender) back into the original
// plaintext, so the send path can re-encrypt it once instead of
// double-encrypting the ciphertext (PROTO-125). The draft body is
// unsigned, so no verification keyring is passed.
func decryptDraftBody(addrKR *crypto.KeyRing, armored string) (string, error) {
	msg, err := crypto.NewPGPMessageFromArmored(armored)
	if err != nil {
		return "", fmt.Errorf("parse armored draft body: %w", err)
	}
	plain, err := addrKR.Decrypt(msg, nil, crypto.GetUnixTime())
	if err != nil {
		return "", fmt.Errorf("decrypt draft body: %w", err)
	}
	return plain.GetString(), nil
}

// finalizeSend is the shared "build packages → SendDraft → return"
// tail used by every send tool. Encapsulates the per-recipient
// public-key lookup + AddTextPackage call.
//
// SECURITY D6: this is also the choke point where handler-side
// allowed_recipients re-validation happens. reply / reply_all /
// send_draft can't expose recipients via Tool.Recipients (the list
// comes from a server fetch, not from raw args), so the middleware
// allowlist stage skips them. We close that gap here — every send
// tool that ends up calling SendDraft must pass through this
// function, and every call validates against the active policy
// before any encryption or network call to /mail/v4/send.
func finalizeSend(ctx mcp.Context, deps Deps, toolName string, addrKR *crypto.KeyRing, draft gpa.Message, tpl gpa.DraftTemplate, mimeType string, recipients []string, attKeys map[string]*crypto.SessionKey) (*mcp.ToolResult, error) {
	// Normalize the recipients we got from wherever (raw args via
	// allRecipients, draft fetch via addressStrings, reply build) so
	// the allowlist comparison sees the same shape extractSendRecipients
	// produces for the middleware path.
	normalized := make([]string, 0, len(recipients))
	for _, r := range recipients {
		normalized = append(normalized, normalizeRecipientList(r)...)
	}
	if deps.Policy != nil {
		if _, pol := deps.Policy.Decide(toolName, nil, mcpCallerFromContext(ctx)); pol != nil && len(pol.AllowedRecipients) > 0 {
			if bad := firstDisallowedRecipient(normalized, pol.AllowedRecipients); bad != "" {
				return mcp.ErrorResult("%s denied: recipient %s not on allowlist", toolName, bad), nil
			}
		}
	}

	prefs, err := buildSendPreferences(ctx.Std, deps, normalized, mimeType)
	if err != nil {
		return mcp.ErrorResult("%s: build send preferences: %v", toolName, err), nil
	}
	req := gpa.SendDraftReq{}
	if attKeys == nil {
		attKeys = map[string]*crypto.SessionKey{}
	}
	if err := req.AddTextPackage(addrKR, tpl.Body, mimeTypeForSend(mimeType), prefs, attKeys); err != nil {
		return mcp.ErrorResult("%s: build text package: %v", toolName, err), nil
	}
	sent, err := deps.Session.Client.SendDraft(ctx.Std, draft.ID, req)
	if err != nil {
		return mcp.ErrorResult("%s: send: %v", toolName, err), nil
	}
	return mcp.StructuredResult(sendResult{
		MessageID:  sent.ID,
		Subject:    sent.Subject,
		Recipients: normalized,
		Sent:       true,
	})
}

// mcpCallerFromContext maps mcp.CallerInfo (a plain struct on
// Context) to policy.Caller (which is caller.Caller). The two have
// the same shape; the conversion is here rather than upstream so
// the internal/mcp package doesn't need to depend on policy.Caller
// shape.
func mcpCallerFromContext(ctx mcp.Context) policy.Caller {
	return policy.Caller{
		PID:    ctx.Caller.PID,
		UID:    ctx.Caller.UID,
		Binary: ctx.Caller.Binary,
	}
}

// firstDisallowedRecipient is duplicated from internal/mcp's
// middleware so the handler-side D6 check uses identical
// semantics. Same matching rules: full address (case-insensitive)
// OR domain suffix ("@example.com").
func firstDisallowedRecipient(extracted, allowed []string) string {
	if len(allowed) == 0 {
		return ""
	}
	full := map[string]struct{}{}
	var domains []string
	for _, a := range allowed {
		if strings.HasPrefix(a, "@") {
			domains = append(domains, strings.ToLower(a))
		} else {
			full[strings.ToLower(a)] = struct{}{}
		}
	}
	for _, addr := range extracted {
		lower := strings.ToLower(addr)
		if _, ok := full[lower]; ok {
			continue
		}
		matched := false
		for _, d := range domains {
			if strings.HasSuffix(lower, d) {
				matched = true
				break
			}
		}
		if !matched {
			return addr
		}
	}
	return ""
}

// allRecipients merges To+CC+BCC into one slice.
func allRecipients(to, cc, bcc []string) []string {
	out := make([]string, 0, len(to)+len(cc)+len(bcc))
	out = append(out, to...)
	out = append(out, cc...)
	out = append(out, bcc...)
	return out
}

// selfAddresses returns lowercase strings of every address attached
// to this session, so reply_all can drop us from CC.
func selfAddresses(deps Deps) []string {
	if deps.Session == nil {
		return nil
	}
	out := make([]string, 0, len(deps.Session.Addresses))
	for _, a := range deps.Session.Addresses {
		out = append(out, strings.ToLower(a.Email))
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ensureValidEmail returns nil if s parses as a single RFC5322
// address. Used by handlers that take addresses from the LLM and
// want to fail fast before the SDK does.
func ensureValidEmail(s string) error {
	if _, err := mail.ParseAddress(s); err != nil {
		return fmt.Errorf("invalid email %q: %w", s, err)
	}
	return nil
}

// (compile-only guards)
var (
	_ = errors.New
	_ = context.Background
	_ = ensureValidEmail
)

const sendResultSchema = `{
	"type": "object",
	"properties": {
		"message_id": {"type": "string"},
		"subject":    {"type": "string"},
		"recipients": {"type": "array", "items": {"type": "string"}},
		"sent":       {"type": "boolean"}
	},
	"required": ["message_id", "sent"]
}`
