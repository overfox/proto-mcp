package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// emlSubjectMaxRunes bounds the subject portion of a default .eml
// filename so a 900-character subject doesn't produce a filename the
// filesystem rejects (sanitize.Filename has its own byte cap; this
// keeps names readable well before that).
const emlSubjectMaxRunes = 80

// mailExportEML — archive one message as a raw RFC 822 .eml file
// (full headers, body and attachments), the format every mail client
// and document-management system imports. Built exactly the way
// Proton Bridge serves IMAP FETCH BODY[]: GetMessage + every
// attachment's encrypted bytes, then gpa.BuildRFC822 decrypts with the
// address keyring and re-assembles the MIME tree.
func mailExportEML(deps Deps) mcp.Tool {
	type input struct {
		MessageID string `json:"message_id"`
		Directory string `json:"directory,omitempty"`
		Filename  string `json:"filename,omitempty"`
	}
	type result struct {
		SavedPath       string `json:"saved_path"`
		Filename        string `json:"filename"`
		SizeBytes       int64  `json:"size_bytes"`
		AttachmentCount int    `json:"attachment_count"`
	}

	return mcp.Tool{
		Name: "mail_export_eml",
		Description: "Export one message as a raw RFC 822 .eml file (full original headers, body and all attachments) for " +
			"archival or import into another mail client / DMS. Written to ~/Downloads by default, or via the optional " +
			"directory param into a directory inside attachment_path_allowlist (policy.yaml). Default filename is " +
			"\"<YYYY-MM-DD> <subject>.eml\"; an explicit filename is sanitized and always gets the .eml extension. " +
			"Never overwrites — collisions get a (2), (3), ... suffix. The file is tagged with the macOS quarantine " +
			"attribute like a browser download. Decryption happens locally with the unlocked address keyring.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"message_id": {"type": "string"},
				"directory":  {"type": "string", "description": "Optional absolute target directory. Must be ~/Downloads or inside attachment_path_allowlist (policy.yaml)."},
				"filename":   {"type": "string", "description": "Optional filename; .eml is appended when missing. Default: \"<YYYY-MM-DD> <subject>.eml\"."}
			},
			"required": ["message_id"],
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"saved_path":       {"type": "string"},
				"filename":         {"type": "string"},
				"size_bytes":       {"type": "integer"},
				"attachment_count": {"type": "integer"}
			},
			"required": ["saved_path", "filename", "size_bytes", "attachment_count"]
		}`),
		PromptBody: func(raw json.RawMessage) (string, string) {
			var in input
			_ = json.Unmarshal(raw, &in)
			subj := lookupSubject(deps, in.MessageID)
			fname := "(dated subject).eml"
			if in.Filename != "" {
				fname = emlFilename(in.Filename)
			}
			dest := "~/Downloads"
			if in.Directory != "" {
				dest = in.Directory
			}
			title := mcp.SanitizePromptText("Approve mail_export_eml?", 120)
			body := "export message " + subj + " (with attachments) as " + fname + " to " + dest
			return title, mcp.SanitizePromptText(body, 4000)
		},
		Handler: func(ctx mcp.Context, raw json.RawMessage) (*mcp.ToolResult, error) {
			var in input
			if err := json.Unmarshal(raw, &in); err != nil {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_export_eml: "+err.Error())
			}
			if in.MessageID == "" {
				return nil, mcp.NewError(mcp.CodeInvalidParams, "mail_export_eml: message_id is required")
			}
			if deps.Session == nil || deps.Session.Client == nil {
				return nil, errors.New("mail_export_eml: session not available")
			}

			eml, msg, err := buildEML(ctx.Std, deps, in.MessageID)
			if err != nil {
				return mcp.ErrorResult("mail_export_eml: %v", err), nil
			}

			fname := in.Filename
			if fname == "" {
				date := time.Now()
				if msg.Time > 0 {
					date = time.Unix(msg.Time, 0)
				}
				fname = defaultEMLName(msg.Subject, date)
			}
			fname = emlFilename(fname)
			if err := checkSaveName(fname); err != nil {
				return mcp.ErrorResult("mail_export_eml: %v", err), nil
			}

			rootDir, err := resolveWriteDir(deps, in.Directory)
			if err != nil {
				return mcp.ErrorResult("mail_export_eml: %v", err), nil
			}
			finalPath, err := writeExclusive(rootDir, fname, eml)
			if err != nil {
				return mcp.ErrorResult("mail_export_eml: %v", err), nil
			}
			return mcp.StructuredResult(result{
				SavedPath:       finalPath,
				Filename:        filepath.Base(finalPath),
				SizeBytes:       int64(len(eml)),
				AttachmentCount: len(msg.Attachments),
			})
		},
	}
}

// buildEML fetches a message plus every attachment's encrypted data
// and assembles the decrypted RFC 822 literal. The whole-message size
// is bounded before any attachment bytes are fetched: an export may
// carry several attachments, so the ceiling is 4x the per-attachment
// policy cap (100 MiB at the 25 MiB default).
func buildEML(ctx context.Context, deps Deps, messageID string) ([]byte, gpa.Message, error) {
	m, err := deps.Session.Client.GetMessage(ctx, messageID)
	if err != nil {
		return nil, gpa.Message{}, fmt.Errorf("fetch message: %w", err)
	}
	kr, ok := deps.Session.AddrKRs[m.AddressID]
	if !ok {
		return nil, m, fmt.Errorf("no unlocked keyring for the message's address — re-login may be required")
	}
	limit := 4 * maxAttachmentBytes(deps)
	var total int64
	for _, a := range m.Attachments {
		total += a.Size
	}
	if total > limit || int64(m.Size) > limit {
		return nil, m, fmt.Errorf("message is too large to export (%d bytes of attachments; limit %d = 4x max_attachment_bytes)", total, limit)
	}

	attData := make(map[string][]byte, len(m.Attachments))
	for _, a := range m.Attachments {
		data, err := deps.Session.Client.GetAttachment(ctx, a.ID)
		if err != nil {
			return nil, m, fmt.Errorf("fetch attachment %s: %w", sanitize.Filename(a.Name), err)
		}
		attData[a.ID] = data
	}
	eml, err := gpa.BuildRFC822(kr, m, attData)
	if err != nil {
		return nil, m, fmt.Errorf("build RFC 822: %w", err)
	}
	return eml, m, nil
}

// defaultEMLName renders "<YYYY-MM-DD> <subject>.eml" in local time.
func defaultEMLName(subject string, date time.Time) string {
	subject = strings.Join(strings.Fields(subject), " ")
	if utf8.RuneCountInString(subject) > emlSubjectMaxRunes {
		subject = strings.TrimSpace(string([]rune(subject)[:emlSubjectMaxRunes]))
	}
	// ':' is legal on APFS but Finder shows it as '/', which reads as
	// a path. Swap for a dash so "Re: Statement" stays legible.
	subject = strings.ReplaceAll(subject, ":", " -")
	if subject == "" {
		subject = "message"
	}
	return date.Local().Format("2006-01-02") + " " + subject + ".eml"
}

// emlFilename sanitizes a candidate name and forces the .eml
// extension (which also neutralizes any executable extension the
// caller or subject smuggled in).
func emlFilename(name string) string {
	name = sanitize.Filename(name)
	name = filepath.Base(filepath.Clean(name))
	if !strings.EqualFold(filepath.Ext(name), ".eml") {
		name += ".eml"
	}
	return name
}

// resolveWriteDir returns the directory a writer tool may place a
// file in: ~/Downloads (created if needed) when dir is empty, else
// dir resolved through the attachment_path_allowlist with symlinks
// evaluated. Hidden path components are refused either way.
func resolveWriteDir(deps Deps, dir string) (string, error) {
	var rootDir string
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("home dir: %w", err)
		}
		rootDir = filepath.Clean(filepath.Join(home, "Downloads"))
		if err := os.MkdirAll(rootDir, 0o700); err != nil {
			return "", fmt.Errorf("mkdir ~/Downloads: %w", err)
		}
	} else {
		resolved, err := resolveAllowlisted(deps, dir)
		if err != nil {
			return "", fmt.Errorf("directory %q: %w (must be ~/Downloads or inside attachment_path_allowlist)", dir, err)
		}
		st, err := os.Stat(resolved)
		if err != nil || !st.IsDir() {
			return "", fmt.Errorf("directory %q is not an existing directory", dir)
		}
		rootDir = resolved
	}
	if err := checkSaveDir(rootDir); err != nil {
		return "", err
	}
	return rootDir, nil
}

// writeExclusive writes content to rootDir/fname without ever
// overwriting (O_EXCL with (N) suffixing), verifies the final path is
// still a direct child of rootDir, and tags it with the quarantine
// xattr. Returns the path actually written.
func writeExclusive(rootDir, fname string, content []byte) (string, error) {
	if fname == "" || fname == "." || fname == "/" {
		return "", fmt.Errorf("refusing empty / invalid filename %q", fname)
	}
	dest := filepath.Clean(filepath.Join(rootDir, fname))
	if filepath.Dir(dest) != rootDir {
		return "", fmt.Errorf("refusing path outside the target directory (resolved to %q)", dest)
	}
	finalPath, f, err := openExclusiveWithSuffix(dest)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("close: %w", err)
	}
	if err := setQuarantine(finalPath); err != nil {
		slog.Warn("quarantine xattr failed", "path", finalPath, "err", err)
	}
	return finalPath, nil
}
