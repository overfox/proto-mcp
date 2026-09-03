package mcptools

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gluon/rfc822"
	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// Phase 8/B — attachment send path. Shared between the send family
// (mail_send / mail_reply / mail_reply_all / mail_forward /
// mail_send_draft) and the draft family (mail_draft_create /
// mail_draft_update).
//
// Two helpers; one shape; one place for size enforcement and
// filename sanitization.

// sendAttachmentInput is the JSON shape every attachment-accepting
// tool exposes. Identical across send + draft inputs.
type sendAttachmentInput struct {
	// Filename is the user-visible name. Runs through
	// sanitize.Filename before upload (D21-class defense:
	// strips RTL spoofs, controls, path separators, leading
	// dots; caps at 255 bytes preserving extension).
	Filename string `json:"filename"`

	// MIMEType is the Content-Type the recipient sees. Sender
	// claims; receiver should verify. We don't sniff bytes.
	MIMEType string `json:"mime_type,omitempty"`

	// ContentB64 is the plaintext attachment bytes, base64-encoded.
	// Decoded + size-checked + then handed to the SDK's
	// UploadAttachment which encrypts before upload.
	ContentB64 string `json:"content_b64,omitempty"`

	// Path is the alternative to ContentB64: an absolute path on the
	// host that the daemon reads directly, so file bytes never travel
	// through the model's context (Cowork/VM clients can't reliably
	// inline large base64 into tool args). Refused unless the path
	// resolves inside the user's attachment_path_allowlist policy —
	// empty allowlist (the default) disables path attachments
	// entirely. Exactly one of ContentB64 / Path must be set.
	Path string `json:"path,omitempty"`
}

// decodedAttachment is the in-process representation between the
// validate step and the upload step. Filename is the SANITIZED
// form; Plain is the post-base64-decode plaintext bytes.
type decodedAttachment struct {
	Filename string
	MIMEType string
	Plain    []byte
}

// attachmentInputSchemaFragment is the JSON-schema chunk every
// send/draft tool drops into its inputSchema's properties bag.
// Centralized so a future field add (e.g. content_id for inline
// attachments) only touches one place.
const attachmentInputSchemaFragment = `{
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "filename":    {"type": "string", "description": "User-visible name. Required with content_b64; defaults to the basename for path."},
            "mime_type":   {"type": "string"},
            "content_b64": {"type": "string", "description": "Attachment bytes, base64. Use for small files only; prefer path for anything sizable."},
            "path":        {"type": "string", "description": "Absolute path on the host Mac, read directly by the daemon — no bytes through the model. Must resolve inside the attachment_path_allowlist directories configured in policy.yaml. Exactly one of content_b64 / path."}
        },
        "additionalProperties": false
    }
}`

// decodeAndValidateAttachments runs every attachment through:
//
//  1. base64 decode of content_b64 → plaintext bytes
//  2. per-attachment size check against max_attachment_bytes
//  3. sum-of-bytes check against the same cap (a 100-element list
//     of 24-MiB attachments would otherwise sneak past the per-item
//     check)
//  4. filename sanitization
//
// Returns the in-process list ready for upload, or an error that
// the caller renders as mcp.ErrorResult.
//
// The function does NOT touch the network. It's safe to call before
// CreateDraft / SendDraft so we fail fast.
func decodeAndValidateAttachments(deps Deps, atts []sendAttachmentInput) ([]decodedAttachment, error) {
	if len(atts) == 0 {
		return nil, nil
	}
	cap := maxAttachmentBytes(deps)
	out := make([]decodedAttachment, 0, len(atts))
	var total int64
	for i, a := range atts {
		if a.ContentB64 != "" && a.Path != "" {
			return nil, fmt.Errorf("attachments[%d]: content_b64 and path are mutually exclusive", i)
		}
		var plain []byte
		filename := a.Filename
		switch {
		case a.Path != "":
			var err error
			plain, err = readAllowlistedAttachment(deps, a.Path, cap)
			if err != nil {
				return nil, fmt.Errorf("attachments[%d]: %w", i, err)
			}
			if filename == "" {
				filename = filepath.Base(a.Path)
			}
		case a.ContentB64 != "":
			if filename == "" {
				return nil, fmt.Errorf("attachments[%d]: filename is required with content_b64", i)
			}
			var err error
			plain, err = base64.StdEncoding.DecodeString(a.ContentB64)
			if err != nil {
				return nil, fmt.Errorf("attachments[%d] (%s): content_b64 is not valid base64: %w",
					i, filename, err)
			}
		default:
			return nil, fmt.Errorf("attachments[%d]: one of content_b64 or path is required", i)
		}
		if int64(len(plain)) > cap {
			return nil, fmt.Errorf(
				"attachments[%d] (%s): %d bytes exceeds max_attachment_bytes (%d). "+
					"Increase the policy cap in ~/Library/Application Support/protonmcp/policy.yaml to override.",
				i, filename, len(plain), cap,
			)
		}
		total += int64(len(plain))
		if total > cap {
			return nil, fmt.Errorf(
				"attachments[0..%d]: cumulative %d bytes exceeds max_attachment_bytes (%d) — "+
					"split into multiple messages or raise the policy cap",
				i, total, cap,
			)
		}
		mt := a.MIMEType
		if mt == "" {
			mt = "application/octet-stream"
		}
		out = append(out, decodedAttachment{
			Filename: sanitize.Filename(filename),
			MIMEType: mt,
			Plain:    plain,
		})
	}
	return out, nil
}

// readAllowlistedAttachment reads a path-based attachment after
// enforcing the attachment_path_allowlist policy. The threat model:
// a prompt-injected model must not be able to pull arbitrary host
// files (~/.ssh, keychains, tax returns) into the mailbox. Defenses,
// in order:
//
//  1. Empty allowlist (the shipped default) refuses every path.
//  2. The path must be absolute and is symlink-resolved
//     (EvalSymlinks) BEFORE the containment check, so a symlink
//     planted inside an allowlisted dir can't point outside it.
//  3. Containment is checked against the symlink-resolved allowlist
//     dirs via filepath.Rel — string-prefix tricks (/allowed-evil)
//     don't pass.
//  4. The open uses O_NOFOLLOW (PROTO-135 pattern) as a TOCTOU
//     backstop, and the size cap is enforced from Stat before the
//     read so a huge file can't balloon memory first.
func readAllowlistedAttachment(deps Deps, p string, cap int64) ([]byte, error) {
	resolved, err := resolveAllowlisted(deps, p)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", p, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", p, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("path %q is a directory", p)
	}
	if st.Size() > cap {
		return nil, fmt.Errorf(
			"%q is %d bytes; exceeds max_attachment_bytes (%d). "+
				"Increase the policy cap in ~/Library/Application Support/protonmcp/policy.yaml to override.",
			p, st.Size(), cap,
		)
	}
	return io.ReadAll(f)
}

// resolveAllowlisted enforces the attachment_path_allowlist policy
// on an absolute path: symlink-resolves it FIRST (a symlink planted
// inside an allowlisted dir can't point outside it), then checks
// containment against each symlink-resolved allowlist dir via
// filepath.Rel (string-prefix tricks like /allowed-evil don't pass).
// Returns the resolved path on success. Shared by path-based
// attachment reads and mail_save_attachment's directory override.
func resolveAllowlisted(deps Deps, p string) (string, error) {
	var allow []string
	if deps.Policy != nil {
		allow = deps.Policy.AttachmentPathAllowlist()
	}
	if len(allow) == 0 {
		return "", fmt.Errorf("path %q refused: attachment_path_allowlist is empty. "+
			"Add allowed directories in ~/Library/Application Support/protonmcp/policy.yaml", p)
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", p, err)
	}
	for _, dir := range allow {
		rdir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue // allowlisted dir unresolvable → can't grant from it
		}
		rel, err := filepath.Rel(rdir, resolved)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("path %q is outside attachment_path_allowlist", p)
}

// uploadAttachmentsAndCollectKeys uploads every decoded attachment
// to the draft on the server side, then recovers each one's session
// key from its KeyPackets so they can be re-encrypted to every
// recipient. Returns the (attachmentID → SessionKey) map that
// AddTextPackage expects.
//
// Cryptographic flow per attachment:
//
//  1. UploadAttachment encrypts the plaintext via the sender's
//     keyring (SDK handles split + sign + multipart upload). The
//     returned Attachment.KeyPackets is the base64-encoded key
//     packet — encrypted to the sender's public key.
//
//  2. base64-decode KeyPackets → raw key packet bytes.
//
//  3. addrKR.DecryptSessionKey recovers the per-attachment session
//     key. This is the symmetric key the data packet is encrypted
//     under — recovering it once means we can re-encrypt it to
//     every recipient's keyring inside AddTextPackage rather than
//     re-uploading the body N times.
//
// Returns nil map (not empty) if `decoded` is empty — same value
// AddTextPackage accepts for the no-attachments case.
func uploadAttachmentsAndCollectKeys(
	ctx context.Context,
	deps Deps,
	addrKR *crypto.KeyRing,
	draftID string,
	decoded []decodedAttachment,
) (map[string]*crypto.SessionKey, error) {
	if len(decoded) == 0 {
		return nil, nil
	}
	attKeys := make(map[string]*crypto.SessionKey, len(decoded))
	for i, d := range decoded {
		att, err := deps.Session.Client.UploadAttachment(ctx, addrKR, gpa.CreateAttachmentReq{
			MessageID:   draftID,
			Filename:    d.Filename,
			MIMEType:    rfc822.MIMEType(d.MIMEType),
			Disposition: gpa.AttachmentDisposition,
			Body:        d.Plain,
		})
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): upload: %w", i, d.Filename, err)
		}
		kpBytes, err := base64.StdEncoding.DecodeString(att.KeyPackets)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): decode KeyPackets: %w", i, d.Filename, err)
		}
		sk, err := addrKR.DecryptSessionKey(kpBytes)
		if err != nil {
			return nil, fmt.Errorf("attachments[%d] (%s): recover session key: %w", i, d.Filename, err)
		}
		attKeys[att.ID] = sk
	}
	return attKeys, nil
}

// attachmentsSummary formats a one-line summary for the Touch ID
// prompt body. Sanitized filenames; sizes in a human-readable form;
// truncates after 3 with "and N more" suffix beyond.
//
// Example outputs:
//
//	"Attachments: report.pdf (2.4 MB)"
//	"Attachments: report.pdf (2.4 MB), photo.jpg (850 KB)"
//	"Attachments: a.pdf (1 KB), b.pdf (1 KB), c.pdf (1 KB) and 5 more"
func attachmentsSummary(decoded []decodedAttachment) string {
	if len(decoded) == 0 {
		return ""
	}
	const max = 3
	parts := make([]string, 0, max)
	for i, d := range decoded {
		if i >= max {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", d.Filename, humanBytes(int64(len(d.Plain)))))
	}
	out := "Attachments: " + strings.Join(parts, ", ")
	if len(decoded) > max {
		out += fmt.Sprintf(" and %d more", len(decoded)-max)
	}
	return out
}

// humanBytes formats a byte count as a short human-readable string.
// Tuned for the Touch ID prompt — not for log lines (no precision).
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
