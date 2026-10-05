package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/ProtonMail/gluon/rfc822"
	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// Drafts. Four tools sharing the encryption-on-write path that the
// SDK hides behind CreateDraft / UpdateDraft (Proton encrypts the
// body with the sender's keyring before persisting).
//
// Inputs accept either body_text or body_html (or both). HTML goes
// through sanitize.Outbound first — same bluemonday policy as
// inbound, so scripts / iframes / remote-image refs are stripped
// before encryption. The LLM cannot send markup we wouldn't have
// accepted from a stranger.

type draftInputCreate struct {
	Subject     string                `json:"subject"`
	To          []string              `json:"to"`
	CC          []string              `json:"cc,omitempty"`
	BCC         []string              `json:"bcc,omitempty"`
	BodyText    string                `json:"body_text,omitempty"`
	BodyHTML    string                `json:"body_html,omitempty"`
	Attachments []sendAttachmentInput `json:"attachments,omitempty"`
}

type draftInputUpdate struct {
	DraftID     string                `json:"draft_id"`
	Subject     string                `json:"subject,omitempty"`
	To          []string              `json:"to,omitempty"`
	CC          []string              `json:"cc,omitempty"`
	BCC         []string              `json:"bcc,omitempty"`
	BodyText    string                `json:"body_text,omitempty"`
	BodyHTML    string                `json:"body_html,omitempty"`
	Attachments []sendAttachmentInput `json:"attachments,omitempty"`
}

type draftResult struct {
	DraftID  string   `json:"draft_id"`
	Subject  string   `json:"subject"`
	To       []string `json:"to,omitempty"`
	CC       []string `json:"cc,omitempty"`
	BCC      []string `json:"bcc,omitempty"`
	MIMEType string   `json:"mime_type"`
}

func mailDraftCreate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_draft_create",
		Description: "Create a new draft message. Proton encrypts the body with your address keyring before persisting. " +
			"Body can be plain text (body_text) or HTML (body_html) — HTML is sanitized through the same allowlist " +
			"as inbound mail before encryption (scripts / iframes / tracking pixels stripped). " +
			"Optional `attachments` array uploads files to the draft (same shape as mail_send). " +
			"attachments[].path takes an absolute path on the host Mac anywhere under the user's home folder or /Volumes: " +
			"files inside attachment_path_allowlist attach silently, any other file first shows a Touch ID prompt " +
			"with its full path and size (one prompt covers all such files in the call). Paths inside a " +
			"Cowork/VM sandbox (/sessions/..., /mnt/...) are not host paths. " +
			"Returns the draft_id which mail_send_draft / mail_draft_update / mail_draft_delete take.",
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
		OutputSchema: json.RawMessage(draftResultSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in draftInputCreate
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_create: "+err.Error())
			}
			if in.Subject == "" || len(in.To) == 0 {
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					"mail_draft_create: subject and at least one to recipient are required")
			}

			decoded, err := decodeAttachmentsGated(deps, in.Attachments,
				draftAttachmentGate(ctx.Std, deps, "mail_draft_create", in.Subject, in.To))
			if err != nil {
				return mcp.ErrorResult("mail_draft_create: %v", err), nil
			}

			tpl, mimeType, err := buildDraftTemplate(deps, in.Subject, in.To, in.CC, in.BCC, in.BodyText, in.BodyHTML)
			if err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_create: "+err.Error())
			}

			senderAddrID, addrKR, err := senderKeyring(deps)
			if err != nil {
				return mcp.ErrorResult("mail_draft_create: %v", err), nil
			}
			_ = senderAddrID

			msg, err := deps.Session.Client.CreateDraft(ctx.Std, addrKR, gpa.CreateDraftReq{
				Message: tpl,
				Action:  gpa.ReplyAction, // zero value; ParentID empty = new draft
			})
			if err != nil {
				return mcp.ErrorResult("mail_draft_create: %v", err), nil
			}

			// Phase 8/B — upload attachments to the draft. Session
			// keys are discarded; drafts don't send, so we don't
			// need to fan keys out to recipients here.
			if _, err := uploadAttachmentsAndCollectKeys(ctx.Std, deps, addrKR, msg.ID, decoded); err != nil {
				return mcp.ErrorResult("mail_draft_create: %v", err), nil
			}

			mirrorUpsertDraft(ctx, deps, msg, "drafts")
			return mcp.StructuredResult(draftResult{
				DraftID:  msg.ID,
				Subject:  msg.Subject,
				To:       addressStrings(msg.ToList),
				CC:       addressStrings(msg.CCList),
				BCC:      addressStrings(msg.BCCList),
				MIMEType: mimeType,
			})
		},
	}
}

func mailDraftUpdate(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_draft_update",
		Description: "Update an existing draft. Any field you don't pass is preserved. body_html still runs through outbound sanitization. " +
			"Optional `attachments` array uploads ADDITIONAL files (does not replace existing attachments on the draft — for that, mail_draft_delete + mail_draft_create). " +
			"Path attachments outside attachment_path_allowlist (anywhere under home or /Volumes) need a Touch ID approval showing the full path; " +
			"Cowork/VM paths (/sessions/..., /mnt/...) are not host paths.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"draft_id":    {"type": "string"},
				"subject":     {"type": "string"},
				"to":          {"type": "array", "items": {"type": "string"}},
				"cc":          {"type": "array", "items": {"type": "string"}},
				"bcc":         {"type": "array", "items": {"type": "string"}},
				"body_text":   {"type": "string"},
				"body_html":   {"type": "string"},
				"attachments": ` + attachmentInputSchemaFragment + `
			},
			"required": ["draft_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(draftResultSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in draftInputUpdate
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_update: "+err.Error())
			}
			if in.DraftID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_update: draft_id is required")
			}

			// Fetch the current draft so unspecified fields persist.
			current, err := deps.Session.Client.GetMessage(ctx.Std, in.DraftID)
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: fetch current: %v", err), nil
			}

			subject := pickStr(in.Subject, current.Subject)
			to := pickAddrList(in.To, current.ToList)
			cc := pickAddrList(in.CC, current.CCList)
			bcc := pickAddrList(in.BCC, current.BCCList)
			// body_text / body_html / nothing — if nothing supplied,
			// keep the existing body. current.Body is armored PGP
			// ciphertext at this point (CreateDraft encrypts to the
			// sender), so it must be DECRYPTED first — the old
			// sanitize.Text(current.Body) path silently replaced the
			// body with PGP armor on any metadata-only update.
			// Decrypt via the PROTO-125 helper and preserve the
			// original MIME type.
			_, addrKR, err := senderKeyring(deps)
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: %v", err), nil
			}
			text, html := in.BodyText, in.BodyHTML
			if text == "" && html == "" {
				plain, derr := decryptDraftBody(addrKR, current.Body)
				if derr != nil {
					return mcp.ErrorResult("mail_draft_update: decrypt current body: %v", derr), nil
				}
				if string(current.MIMEType) == "text/html" {
					html = plain
				} else {
					text = plain
				}
			}

			toStrs := toEmailStrings(to)
			ccStrs := toEmailStrings(cc)
			bccStrs := toEmailStrings(bcc)
			tpl, mimeType, err := buildDraftTemplate(deps, subject, toStrs, ccStrs, bccStrs, text, html)
			if err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_update: "+err.Error())
			}

			decoded, err := decodeAttachmentsGated(deps, in.Attachments,
				draftAttachmentGate(ctx.Std, deps, "mail_draft_update", subject, toStrs))
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: %v", err), nil
			}

			msg, err := deps.Session.Client.UpdateDraft(ctx.Std, in.DraftID, addrKR, gpa.UpdateDraftReq{
				Message: tpl,
			})
			if err != nil {
				return mcp.ErrorResult("mail_draft_update: %v", err), nil
			}

			// Phase 8/B — additive attachment upload. Existing
			// attachments on the draft are preserved by the SDK;
			// these get added.
			if _, err := uploadAttachmentsAndCollectKeys(ctx.Std, deps, addrKR, msg.ID, decoded); err != nil {
				return mcp.ErrorResult("mail_draft_update: %v", err), nil
			}

			mirrorUpsertDraft(ctx, deps, msg, "drafts")
			return mcp.StructuredResult(draftResult{
				DraftID:  msg.ID,
				Subject:  msg.Subject,
				To:       addressStrings(msg.ToList),
				CC:       addressStrings(msg.CCList),
				BCC:      addressStrings(msg.BCCList),
				MIMEType: mimeType,
			})
		},
	}
}

func mailDraftDelete(deps Deps) mcp.Tool {
	type input struct {
		DraftID string `json:"draft_id"`
	}
	return mcp.Tool{
		Name:        "mail_draft_delete",
		Description: "Delete a draft. This is a Proton DeleteMessage on the draft, which trashes it (recoverable from Trash).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {"draft_id": {"type": "string"}},
			"required": ["draft_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"draft_id": {"type": "string"},
				"deleted":  {"type": "boolean"}
			},
			"required": ["draft_id", "deleted"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			subj := lookupSubject(deps, in.DraftID)
			title := mcp.SanitizePromptText("Approve mail_draft_delete?", 120)
			body := "delete draft " + subj + " (moves to Trash; recoverable)"
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_delete: "+err.Error())
			}
			if in.DraftID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_delete: draft_id is required")
			}
			if err := deps.Session.Client.DeleteMessage(ctx.Std, in.DraftID); err != nil {
				return mcp.ErrorResult("mail_draft_delete: %v", err), nil
			}
			_ = deps.Store.DeleteMessage(ctx.Std, in.DraftID)
			return mcp.StructuredResult(map[string]any{
				"draft_id": in.DraftID,
				"deleted":  true,
			})
		},
	}
}

func mailDraftList(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "mail_draft_list",
		Description: "List drafts from the local mirror, newest-first. Convenience over mail_list folder=\"drafts\" — same data, narrower default.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"limit":  {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
				"cursor": {"type": "string"}
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(messageListSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in struct {
				Limit  int    `json:"limit,omitempty"`
				Cursor string `json:"cursor,omitempty"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_draft_list: "+err.Error())
				}
			}
			opts := store.SearchOpts{
				Limit:  normalizeListLimit(in.Limit),
				Filter: store.ListFilter{Folder: "drafts"},
			}
			qhash := filterHash(opts.Filter)
			if in.Cursor != "" {
				off, ok := decodeCursor(in.Cursor, qhash)
				if !ok {
					return nil, mcp.NewError(mcp.CodeInvalidParams,
						"mail_draft_list: cursor is stale or belongs to a different query")
				}
				opts.Offset = off
			}
			hits, err := deps.Store.Search(ctx.Std, "", opts)
			if err != nil {
				return nil, err
			}
			summaries := make([]messageSummary, 0, len(hits))
			for _, h := range hits {
				summaries = append(summaries, hitToSummary(h))
			}
			res := listResult{Messages: summaries}
			if opts.Limit > 0 && len(hits) >= opts.Limit {
				res.NextCursor = encodeCursor(opts.Offset+len(hits), qhash)
			}
			return mcp.StructuredResult(res)
		},
	}
}

// draftAttachmentGate returns the tier-b gate for the draft tools:
// draft creation/update is policy `allow`, so files from outside
// attachment_path_allowlist need their own Touch ID approval here. One
// prompt lists every such file (full resolved path + size) and the
// draft it's for. It goes straight to the broker (deps.Approve), so
// Keep Alive — which only acts inside policy.Decide — can't suppress
// it. No broker → refuse.
func draftAttachmentGate(ctx context.Context, deps Deps, tool, subject string, to []string) attachmentGate {
	return func(outside []resolvedAttachmentPath) error {
		if deps.Approve == nil {
			return fmt.Errorf("%q is outside attachment_path_allowlist and needs a Touch ID approval, "+
				"but no approval broker is available", outside[0].Requested)
		}
		title, body := outsideAllowlistPrompt(tool, subject, to, outside)
		if err := deps.Approve(ctx, title, body); err != nil {
			return fmt.Errorf("attaching files from outside attachment_path_allowlist was not approved: %w", err)
		}
		return nil
	}
}

// outsideAllowlistPrompt formats the per-call Touch ID prompt for
// out-of-allowlist path attachments on a draft.
func outsideAllowlistPrompt(tool, subject string, to []string, outside []resolvedAttachmentPath) (string, string) {
	var b strings.Builder
	noun := "file"
	if len(outside) > 1 {
		noun = "files"
	}
	fmt.Fprintf(&b, "Attach %d %s from outside your attachment allowlist to a draft (%s)", len(outside), noun, tool)
	if len(to) > 0 {
		b.WriteString("\nTo: " + joinAddrs(to))
	}
	if subject != "" {
		b.WriteString("\nSubject: " + clipRunes(sanitizeField(subject), 100))
	}
	for _, o := range outside {
		fmt.Fprintf(&b, "\n%s (%s)", sanitizeField(o.Resolved), humanBytes(o.Size))
	}
	return mcp.SanitizePromptText("Approve attaching files to "+tool+"?", 120),
		mcp.SanitizePromptText(b.String(), 4000)
}

// buildDraftTemplate is the shared body-building path. Handles
// outbound HTML sanitization and the MIME-type decision (plain
// text when no HTML, HTML when html is provided — and if both
// supplied, HTML wins since rich body is more expressive).
func buildDraftTemplate(deps Deps, subject string, to, cc, bcc []string, bodyText, bodyHTML string) (gpa.DraftTemplate, string, error) {
	body := bodyText
	mimeType := "text/plain"
	if bodyHTML != "" {
		// SECURITY: outbound sanitization. Same allowlist as inbound.
		body = sanitize.Outbound(bodyHTML)
		mimeType = "text/html"
	}

	sender, err := primarySenderAddress(deps)
	if err != nil {
		return gpa.DraftTemplate{}, "", err
	}
	toList, err := parseAddrList(to)
	if err != nil {
		return gpa.DraftTemplate{}, "", fmt.Errorf("to: %w", err)
	}
	ccList, err := parseAddrList(cc)
	if err != nil {
		return gpa.DraftTemplate{}, "", fmt.Errorf("cc: %w", err)
	}
	bccList, err := parseAddrList(bcc)
	if err != nil {
		return gpa.DraftTemplate{}, "", fmt.Errorf("bcc: %w", err)
	}

	return gpa.DraftTemplate{
		Subject:  subject,
		Sender:   sender,
		ToList:   toList,
		CCList:   ccList,
		BCCList:  bccList,
		Body:     body,
		MIMEType: rfc822.MIMEType(mimeType),
	}, mimeType, nil
}

// primarySenderAddress returns the primary-address mail.Address for
// the current session.
func primarySenderAddress(deps Deps) (*mail.Address, error) {
	if deps.Session == nil {
		return nil, errors.New("no active session")
	}
	addr, ok := deps.Session.PrimaryAddress()
	if !ok {
		return nil, errors.New("no primary address resolved on session")
	}
	return &mail.Address{
		Name:    addr.DisplayName,
		Address: addr.Email,
	}, nil
}

// senderKeyring returns (addressID, *crypto.KeyRing) for the primary
// address. Used by CreateDraft / UpdateDraft for body encryption.
func senderKeyring(deps Deps) (string, *crypto.KeyRing, error) {
	if deps.Session == nil {
		return "", nil, errors.New("no active session")
	}
	addr, ok := deps.Session.PrimaryAddress()
	if !ok {
		return "", nil, errors.New("no primary address resolved on session")
	}
	kr, ok := deps.Session.AddrKRs[addr.ID]
	if !ok || kr == nil {
		return "", nil, fmt.Errorf("no keyring for address %s", addr.ID)
	}
	return addr.ID, kr, nil
}

func parseAddrList(addrs []string) ([]*mail.Address, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	out := make([]*mail.Address, 0, len(addrs))
	for _, s := range addrs {
		a, err := mail.ParseAddress(s)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func toEmailStrings(addrs []*mail.Address) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, a.Address)
	}
	return out
}

func pickAddrList(preferred []string, fallback []*mail.Address) []*mail.Address {
	if len(preferred) > 0 {
		parsed, _ := parseAddrList(preferred)
		return parsed
	}
	return fallback
}

func addressStrings(addrs []*mail.Address) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, a.Address)
	}
	return out
}

func mirrorUpsertDraft(ctx mcp.Context, deps Deps, m gpa.Message, folder string) {
	row, err := protonMessageToStore(m)
	if err != nil {
		return
	}
	row.Folder = folder
	_ = deps.Store.UpsertMessage(ctx.Std, row)
}

// protonMessageToStore is a lightweight translator that pulls
// envelope fields off a full gpa.Message (the SDK returns this for
// CreateDraft / UpdateDraft / GetMessage). The full proton →
// store.Message translator (proton.ToStoreMessage) is metadata-only;
// we synthesize what we need here for drafts.
func protonMessageToStore(m gpa.Message) (store.Message, error) {
	toJSON, err := marshalAddrJSON(m.ToList)
	if err != nil {
		return store.Message{}, err
	}
	ccJSON, err := marshalAddrJSON(m.CCList)
	if err != nil {
		return store.Message{}, err
	}
	fromAddr, fromName := "", ""
	if m.Sender != nil {
		fromAddr, fromName = m.Sender.Address, m.Sender.Name
	}
	return store.Message{
		ID:          m.ID,
		ThreadID:    m.ID, // drafts get a self-thread until reply
		Subject:     m.Subject,
		FromAddress: fromAddr,
		FromName:    fromName,
		ToJSON:      toJSON,
		CcJSON:      ccJSON,
		Date:        time.Unix(m.Time, 0).UTC(),
		Unread:      false,
		SizeBytes:   int64(m.Size),
	}, nil
}

func marshalAddrJSON(addrs []*mail.Address) (string, error) {
	if len(addrs) == 0 {
		return "[]", nil
	}
	out := make([]map[string]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, map[string]string{
			"name":    a.Name,
			"address": a.Address,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

const draftResultSchema = `{
	"type": "object",
	"properties": {
		"draft_id":  {"type": "string"},
		"subject":   {"type": "string"},
		"to":        {"type": "array", "items": {"type": "string"}},
		"cc":        {"type": "array", "items": {"type": "string"}},
		"bcc":       {"type": "array", "items": {"type": "string"}},
		"mime_type": {"type": "string"}
	},
	"required": ["draft_id", "subject", "mime_type"]
}`
