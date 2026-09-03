package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// systemFolderToLabelID maps the LLM-facing folder names back to
// Proton's label-ID convention. These are the IDs `mail_move` writes
// to when the destination is one of the built-in folders. User-
// defined folders pass through their label_id directly via mail_label
// instead.
//
// Inverse of the priority list in proton.primaryFolder.
var systemFolderToLabelID = map[string]string{
	"inbox":   gpa.InboxLabel,
	"sent":    gpa.SentLabel,
	"drafts":  gpa.DraftsLabel,
	"archive": gpa.ArchiveLabel,
	"trash":   gpa.TrashLabel,
	"spam":    gpa.SpamLabel,
}

// maxStateBatch caps how many messages one organize call may touch.
// Large enough for real triage sessions, small enough that a runaway
// caller can't queue an unbounded server-side mutation. The SDK
// chunks the API requests internally.
const maxStateBatch = 500

// stateIDsInput is the shared id-bearing input for the organize
// family. Every tool accepts either the original single `message_id`
// or the batch `message_ids` — the whole batch is one tool call, one
// audit row, and (for prompted tools) ONE Touch ID approval, instead
// of N of each. The SDK endpoints are batch-native already.
type stateIDsInput struct {
	MessageID  string   `json:"message_id,omitempty"`
	MessageIDs []string `json:"message_ids,omitempty"`
}

// resolveIDs normalizes the two input forms into one non-empty,
// deduplicated id list. Exactly one of the forms must be provided.
func (in stateIDsInput) resolveIDs(toolName string) ([]string, *mcp.Error) {
	if in.MessageID != "" && len(in.MessageIDs) > 0 {
		return nil, mcp.NewError(mcp.CodeInvalidParams,
			toolName+": message_id and message_ids are mutually exclusive")
	}
	ids := in.MessageIDs
	if in.MessageID != "" {
		ids = []string{in.MessageID}
	}
	if len(ids) == 0 {
		return nil, mcp.NewError(mcp.CodeInvalidParams,
			toolName+": one of message_id or message_ids is required")
	}
	if len(ids) > maxStateBatch {
		return nil, mcp.NewError(mcp.CodeInvalidParams,
			fmt.Sprintf("%s: %d message_ids exceeds the %d per-call cap — split the batch",
				toolName, len(ids), maxStateBatch))
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for i, id := range ids {
		if id == "" {
			return nil, mcp.NewError(mcp.CodeInvalidParams,
				fmt.Sprintf("%s: message_ids[%d] is empty", toolName, i))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// stateIDsSchemaProps is the shared schema fragment for the id pair.
const stateIDsSchemaProps = `"message_id":  {"type": "string", "description": "Single message. Exactly one of message_id / message_ids."},
				"message_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 500, "description": "Batch form: apply the action to every listed message in one call (one approval)."}`

// batchPromptNoun renders "message <subject>" for a single id or
// "N messages (first: <subject>)" for a batch — the Touch ID prompt
// must convey scale without listing 500 subjects.
func batchPromptNoun(deps Deps, ids []string) string {
	if len(ids) == 1 {
		return "message " + lookupSubject(deps, ids[0])
	}
	return fmt.Sprintf("%d messages (first: %s)", len(ids), lookupSubject(deps, ids[0]))
}

// mailMarkRead — clear the Unread flag.
func mailMarkRead(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "mail_mark_read",
		Description: "Mark one message (message_id) or a batch (message_ids) as read. Reversible via mail_mark_unread. Local mirror updated immediately.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				` + stateIDsSchemaProps + `
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			ids, merr := decodeStateIDs(raw, "mail_mark_read")
			if merr != nil {
				return nil, merr
			}
			if err := deps.Session.Client.MarkMessagesRead(ctx.Std, ids...); err != nil {
				return mcp.ErrorResult("mail_mark_read: %v", err), nil
			}
			warn := updateMessagesFlag(ctx.Std, deps, ids, func(m *store.Message) { m.Unread = false })
			return mcp.StructuredResult(stateActionOK(ids, "marked_read", warn))
		},
	}
}

// mailMarkUnread — symmetric reverse.
func mailMarkUnread(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name:        "mail_mark_unread",
		Description: "Mark one message (message_id) or a batch (message_ids) as unread. Reversible via mail_mark_read. Local mirror updated immediately.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				` + stateIDsSchemaProps + `
			},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			ids, merr := decodeStateIDs(raw, "mail_mark_unread")
			if merr != nil {
				return nil, merr
			}
			if err := deps.Session.Client.MarkMessagesUnread(ctx.Std, ids...); err != nil {
				return mcp.ErrorResult("mail_mark_unread: %v", err), nil
			}
			warn := updateMessagesFlag(ctx.Std, deps, ids, func(m *store.Message) { m.Unread = true })
			return mcp.StructuredResult(stateActionOK(ids, "marked_unread", warn))
		},
	}
}

// mailMove — move messages to a destination folder. Implemented as
// "label with destination, unlabel current" rather than a single
// Proton move endpoint (Proton's label system handles this natively).
//
// Destination is one of the system folder names (inbox / sent /
// drafts / archive / trash / spam) OR a user-folder label_id. For
// system folders the LLM-facing name is friendlier; user folders
// require the label_id from folders_list since their names can
// collide with system ones.
func mailMove(deps Deps) mcp.Tool {
	type input struct {
		stateIDsInput
		Destination string `json:"destination"`
	}
	return mcp.Tool{
		Name: "mail_move",
		Description: "Move one message (message_id) or a batch (message_ids) to a different folder — a batch is one call and one approval. " +
			"Destination is one of the system folders (inbox, sent, drafts, archive, trash, spam) " +
			"OR the label_id of a user-defined folder (from folders_list). " +
			"Reversible — call mail_move again with the original folder.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				` + stateIDsSchemaProps + `,
				"destination": {"type": "string", "description": "System folder name or user folder label_id"}
			},
			"required": ["destination"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			ids, _ := in.resolveIDs("mail_move")
			toName := destinationName(deps, in.Destination)
			title := mcp.SanitizePromptText("Approve mail_move?", 120)
			body := "move " + batchPromptNoun(deps, ids) + " to " + toName
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_move: "+err.Error())
			}
			ids, merr := in.resolveIDs("mail_move")
			if merr != nil {
				return nil, merr
			}
			if in.Destination == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_move: destination is required")
			}

			destLabelID := in.Destination
			destFriendly := in.Destination
			if labelID, ok := systemFolderToLabelID[in.Destination]; ok {
				destLabelID = labelID
			} else {
				destFriendly = "" // unknown; we don't know the name
			}

			// Read current state from the mirror to find the source
			// folder each message must be unlabeled from. Messages in
			// different folders group into per-source unlabel batches;
			// rows missing from the mirror fall back to no-unlabel
			// (sync hadn't run yet).
			bySource := map[string][]string{}
			for _, id := range ids {
				if m, err := deps.Store.GetMessage(ctx.Std, id); err == nil {
					if srcID, ok := systemFolderToLabelID[m.Folder]; ok && srcID != destLabelID {
						bySource[srcID] = append(bySource[srcID], id)
					}
				}
			}

			if err := deps.Session.Client.LabelMessages(ctx.Std, ids, destLabelID); err != nil {
				return mcp.ErrorResult("mail_move: label %s: %v", destLabelID, err), nil
			}
			var warn string
			for srcID, srcIDs := range bySource {
				if err := deps.Session.Client.UnlabelMessages(ctx.Std, srcIDs, srcID); err != nil {
					// Destination label already applied — the move is
					// half-done for this group. Surface as warning,
					// not failure.
					warn = fmt.Sprintf("warning: failed to unlabel source %s: %v", srcID, err)
				}
			}

			// Mirror update.
			newFolder := destFriendly
			if newFolder == "" {
				newFolder = destLabelID // user folder id
			}
			if w := updateMessagesFlag(ctx.Std, deps, ids, func(m *store.Message) {
				m.Folder = newFolder
			}); warn == "" {
				warn = w
			}

			return mcp.StructuredResult(stateActionOK(ids, "moved_to:"+newFolder, warn))
		},
	}
}

// mailLabel — add or remove a single label from messages. For moves
// between folders use mail_move instead; this is the verb for
// applying classification labels (not folders).
func mailLabel(deps Deps) mcp.Tool {
	type input struct {
		stateIDsInput
		LabelID string `json:"label_id"`
		Action  string `json:"action"` // "add" | "remove"
	}
	return mcp.Tool{
		Name: "mail_label",
		Description: "Add or remove one label on one message (message_id) or a batch (message_ids) — a batch is one call and one approval. " +
			"Reversible — call again with the opposite action. " +
			"Use label_id values from labels_list; for moving between folders use mail_move.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				` + stateIDsSchemaProps + `,
				"label_id":   {"type": "string"},
				"action":     {"type": "string", "enum": ["add", "remove"]}
			},
			"required": ["label_id", "action"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(stateActionSchema),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			ids, _ := in.resolveIDs("mail_label")
			label := lookupLabelName(deps, in.LabelID)
			verb := "apply label"
			prep := "to"
			if in.Action == "remove" {
				verb = "remove label"
				prep = "from"
			}
			title := mcp.SanitizePromptText("Approve mail_label?", 120)
			body := verb + " " + label + " " + prep + " " + batchPromptNoun(deps, ids)
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_label: "+err.Error())
			}
			ids, merr := in.resolveIDs("mail_label")
			if merr != nil {
				return nil, merr
			}
			if in.LabelID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_label: label_id is required")
			}
			switch in.Action {
			case "add":
				if err := deps.Session.Client.LabelMessages(ctx.Std, ids, in.LabelID); err != nil {
					return mcp.ErrorResult("mail_label add: %v", err), nil
				}
				return mcp.StructuredResult(stateActionOK(ids, "labeled:"+in.LabelID, ""))
			case "remove":
				if err := deps.Session.Client.UnlabelMessages(ctx.Std, ids, in.LabelID); err != nil {
					return mcp.ErrorResult("mail_label remove: %v", err), nil
				}
				return mcp.StructuredResult(stateActionOK(ids, "unlabeled:"+in.LabelID, ""))
			default:
				return nil, mcp.NewError(mcp.CodeInvalidParams,
					`mail_label: action must be "add" or "remove"`)
			}
		},
	}
}

// mailTrash — move to trash. Reversible by mail_move back to the
// original folder while the message still exists in trash. (Proton
// has a separate "permanent delete" verb gated as deny by default —
// see mail_delete_permanent in 5/D.)
func mailTrash(deps Deps) mcp.Tool {
	return mcp.Tool{
		Name: "mail_trash",
		Description: "Move one message (message_id) or a batch (message_ids) to Trash — a batch is one call and one approval. " +
			"Reversible — call mail_move with the original folder. " +
			"For permanent deletion see mail_delete_permanent (gated as deny by default).",
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
			ids, _ := in.resolveIDs("mail_trash")
			title := mcp.SanitizePromptText("Approve mail_trash?", 120)
			body := "move " + batchPromptNoun(deps, ids) + " to Trash (reversible via mail_move)"
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			ids, merr := decodeStateIDs(raw, "mail_trash")
			if merr != nil {
				return nil, merr
			}
			// Proton's DeleteMessage moves to Trash (recoverable);
			// the true permanent delete is a different endpoint.
			if err := deps.Session.Client.DeleteMessage(ctx.Std, ids...); err != nil {
				return mcp.ErrorResult("mail_trash: %v", err), nil
			}
			warn := updateMessagesFlag(ctx.Std, deps, ids, func(m *store.Message) {
				m.Folder = "trash"
			})
			return mcp.StructuredResult(stateActionOK(ids, "trashed", warn))
		},
	}
}

// stateActionResult is the shared output shape for the five state
// mutation tools. Keeps the wire shape uniform across the family.
// Single-message calls keep the original message_id field; batches
// populate message_ids. count is always set.
type stateActionResult struct {
	MessageID  string   `json:"message_id,omitempty"`
	MessageIDs []string `json:"message_ids,omitempty"`
	Count      int      `json:"count"`
	Action     string   `json:"action"`
	Warning    string   `json:"warning,omitempty"`
}

func stateActionOK(ids []string, action, warning string) stateActionResult {
	res := stateActionResult{Count: len(ids), Action: action, Warning: warning}
	if len(ids) == 1 {
		res.MessageID = ids[0]
	} else {
		res.MessageIDs = ids
	}
	return res
}

const stateActionSchema = `{
	"type": "object",
	"properties": {
		"message_id":  {"type": "string"},
		"message_ids": {"type": "array", "items": {"type": "string"}},
		"count":       {"type": "integer"},
		"action":      {"type": "string"},
		"warning":     {"type": "string"}
	},
	"required": ["count", "action"]
}`

// decodeStateIDs is the shared parse path for the tools whose input
// is just the id pair (mark_read/unread, trash).
func decodeStateIDs(raw json.RawMessage, toolName string) ([]string, *mcp.Error) {
	var in stateIDsInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, mcp.NewError(mcp.CodeInvalidParams, toolName+": "+err.Error())
	}
	return in.resolveIDs(toolName)
}

// updateMessagesFlag applies mut to every id's mirror row. Mirror
// updates are best-effort — the server-side action already succeeded
// — so failures come back as a warning string ("" if all fine), not
// an error. ErrNotFound rows are skipped (sync writes them later).
func updateMessagesFlag(ctx context.Context, deps Deps, ids []string, mut func(*store.Message)) string {
	var failed int
	var lastErr error
	for _, id := range ids {
		if err := updateMessageFlag(ctx, deps, id, mut); err != nil {
			failed++
			lastErr = err
		}
	}
	if failed > 0 {
		return fmt.Sprintf("warning: local mirror update failed for %d of %d messages (last: %v)",
			failed, len(ids), lastErr)
	}
	return ""
}

// updateMessageFlag fetches the message from the local mirror,
// applies mut, and writes it back. ErrNotFound is non-fatal — we
// return an error so the caller knows but tool success isn't gated
// on the mirror being current. (Sync would have written the row
// eventually; we're just being eager.)
func updateMessageFlag(ctx context.Context, deps Deps, id string, mut func(*store.Message)) error {
	m, err := deps.Store.GetMessage(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil // sync will pick it up next round
		}
		return err
	}
	mut(&m)
	return deps.Store.UpsertMessage(ctx, m)
}
