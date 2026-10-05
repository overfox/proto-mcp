package mcptools

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/sanitize"
)

// Send-family approval dialogs.
//
// The Touch ID helper renders ONLY the prompt body (as LAContext's
// localizedReason), and macOS truncates long reasons. The body is
// therefore ordered by what the user must not miss — recipients
// first, then subject, a body excerpt, and every attachment — and
// budgeted to ~640 chars (the helper appends a "Requested by" line,
// keeping the total near 700). The body excerpt shrinks first; the
// recipient and attachment lists are never elided.
//
// What the dialog showed is recorded in sendLedger (keyed by tool +
// raw args, which the middleware passes identically to PromptBody and
// Handler) so the handler can refuse to send anything other than what
// was approved: a different draft (draft swap), different reply
// recipients, out-of-allowlist files that weren't listed, or content
// the dialog couldn't load at all.

const (
	sendPromptBudget  = 640
	bodyExcerptMax    = 300
	bodyExcerptMin    = 80
	subjectPromptMax  = 120
	attachNamePrompt  = 80
	sendLedgerTTL     = 2 * time.Minute
	promptServerFetch = 5 * time.Second
)

// promptAttachment is one attachment line in a send dialog.
type promptAttachment struct {
	Name string
	Size int64
	// Path is set (full resolved path) for files from outside
	// attachment_path_allowlist; the dialog shows it instead of the
	// bare name so the user sees exactly which host file is leaving.
	Path string
	// Err is set when the attachment will be refused; shown so the
	// user knows the call will fail.
	Err string
	// Parent marks attachments carried over from the forwarded message.
	Parent bool
	// FromDraft marks attachments already on the draft.
	FromDraft bool
}

// sendPromptSpec is everything a send dialog shows.
type sendPromptSpec struct {
	Action      string // "Send", "Reply", "Reply-all", "Forward", "Send draft"
	Tool        string
	To, CC, BCC []string
	CCLabel     string // "CC" by default
	Subject     string
	BodyText    string
	BodyHTML    string
	BodySuffix  string // e.g. "+ quoted original from x"
	Attachments []promptAttachment
	Warnings    []string // e.g. "COULD NOT LOAD DRAFT — approving will NOT send"
}

// ownDomains returns the lower-cased domains of the account's own
// addresses. Empty when there's no session (tests): then nothing is
// flagged external rather than everything.
func ownDomains(deps Deps) map[string]bool {
	out := map[string]bool{}
	if deps.Session == nil {
		return out
	}
	for _, a := range deps.Session.Addresses {
		if i := strings.LastIndexByte(a.Email, '@'); i >= 0 {
			out[strings.ToLower(a.Email[i+1:])] = true
		}
	}
	return out
}

// promptAddrs formats a recipient list for the dialog: each entry
// sanitized (no line-break injection), display names reduced to the
// bare address where parseable, and "(external)" appended when the
// domain isn't one of the account's own.
func promptAddrs(addrs []string, own map[string]bool) string {
	out := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		for _, a := range normalizeRecipientList(raw) {
			s := sanitizeField(a)
			if len(own) > 0 {
				dom := ""
				if i := strings.LastIndexByte(a, '@'); i >= 0 {
					dom = strings.ToLower(strings.TrimSpace(a[i+1:]))
				}
				if !own[dom] {
					s += " (external)"
				}
			}
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}

// bodyExcerpt renders the outgoing body for the dialog: HTML reduced
// to text, prompt-sanitized, whitespace collapsed, clipped to max
// runes with "…".
func bodyExcerpt(text, html string, max int) string {
	src := text
	if html != "" {
		src = sanitize.Text(html)
	}
	src = mcp.SanitizePromptText(src, 20000)
	src = strings.Join(strings.Fields(src), " ")
	return clipRunes(src, max)
}

// formatSendPrompt assembles the dialog body for spec.
func formatSendPrompt(deps Deps, spec sendPromptSpec) string {
	own := ownDomains(deps)
	var head []string
	for _, w := range spec.Warnings {
		head = append(head, "⚠️ "+sanitizeField(w))
	}
	action := spec.Action
	if spec.Tool != "" {
		action += " (" + spec.Tool + ")"
	}
	head = append(head, action)
	head = append(head, "To: "+orNone(promptAddrs(spec.To, own)))
	if len(spec.CC) > 0 {
		label := spec.CCLabel
		if label == "" {
			label = "CC"
		}
		head = append(head, label+": "+promptAddrs(spec.CC, own))
	}
	if len(spec.BCC) > 0 {
		head = append(head, "BCC: "+promptAddrs(spec.BCC, own))
	}
	head = append(head, "Subject: "+clipRunes(sanitizeField(mcp.SanitizePromptText(spec.Subject, 2000)), subjectPromptMax))

	var tail []string
	if len(spec.Attachments) > 0 {
		lines := make([]string, 0, len(spec.Attachments))
		for _, a := range spec.Attachments {
			lines = append(lines, formatPromptAttachment(a))
		}
		tail = append(tail, fmt.Sprintf("Attachments (%d): %s", len(spec.Attachments), strings.Join(lines, "; ")))
	}

	fixed := len([]rune(strings.Join(head, "\n"))) + len([]rune(strings.Join(tail, "\n"))) + 16
	budget := sendPromptBudget - fixed - len([]rune(spec.BodySuffix))
	if budget > bodyExcerptMax {
		budget = bodyExcerptMax
	}
	if budget < bodyExcerptMin {
		budget = bodyExcerptMin
	}
	body := bodyExcerpt(spec.BodyText, spec.BodyHTML, budget)
	bodyLine := "Body: "
	if body == "" {
		bodyLine += "(empty)"
	} else {
		bodyLine += "\"" + body + "\""
	}
	if spec.BodySuffix != "" {
		bodyLine += " " + sanitizeField(spec.BodySuffix)
	}

	lines := append(head, bodyLine)
	lines = append(lines, tail...)
	return mcp.SanitizePromptText(strings.Join(lines, "\n"), 4000)
}

func formatPromptAttachment(a promptAttachment) string {
	var s string
	switch {
	case a.Path != "":
		s = sanitizeField(a.Path) + " [outside allowlist]"
	default:
		s = clipRunes(sanitizeField(a.Name), attachNamePrompt)
	}
	if a.Err != "" {
		return s + " (REFUSED: " + clipRunes(sanitizeField(a.Err), 120) + ")"
	}
	s += " (" + humanBytes(a.Size) + ")"
	switch {
	case a.Parent:
		s += " [from original]"
	case a.FromDraft:
		s += " [on draft]"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// describeAttachments resolves an attachments[] input for the dialog
// WITHOUT reading file contents: names + sizes, full paths for
// out-of-allowlist files, and refusal reasons. outside lists the
// resolved paths the dialog is approving.
func describeAttachments(deps Deps, atts []sendAttachmentInput) (out []promptAttachment, outside []string) {
	for i, a := range atts {
		name := a.Filename
		switch {
		case a.ContentB64 != "" && a.Path != "":
			out = append(out, promptAttachment{Name: orNone(name), Err: "content_b64 and path both set"})
		case a.Path != "":
			if name == "" {
				name = filepath.Base(a.Path)
			}
			r, err := resolveAttachmentPath(deps, a.Path)
			if err != nil {
				out = append(out, promptAttachment{Name: a.Path, Err: err.Error()})
				continue
			}
			pa := promptAttachment{Name: sanitize.Filename(name), Size: r.Size}
			if r.Tier == tierNeedsApproval {
				pa.Path = r.Resolved
				outside = append(outside, r.Resolved)
			}
			out = append(out, pa)
		case a.ContentB64 != "":
			n, err := base64.StdEncoding.DecodeString(a.ContentB64)
			if err != nil {
				out = append(out, promptAttachment{Name: orNone(name), Err: "invalid base64"})
				continue
			}
			out = append(out, promptAttachment{Name: sanitize.Filename(name), Size: int64(len(n))})
		default:
			out = append(out, promptAttachment{Name: fmt.Sprintf("attachments[%d]", i), Err: "no content_b64 or path"})
		}
	}
	return out, outside
}

// --- approval ledger -------------------------------------------------

// sendApproval is what a send dialog showed, for the handler to check.
type sendApproval struct {
	// failure, when set, means the dialog could not show the content
	// (lookup failed / timed out); the handler must refuse.
	failure string
	// outsidePaths are the out-of-allowlist resolved paths listed.
	outsidePaths map[string]bool
	// recipients is the normalized recipient set shown (reply family).
	recipients []string
	// draftDigest is the digest of the draft shown (send_draft).
	draftDigest string
	// parentAttachmentIDs are the forwarded-message attachments shown.
	parentAttachmentIDs []string
	expires             time.Time
}

type approvalLedger struct {
	mu      sync.Mutex
	entries map[string]sendApproval
	now     func() time.Time
}

var sendLedger = &approvalLedger{entries: map[string]sendApproval{}, now: time.Now}

func ledgerKey(tool string, args []byte) string {
	h := sha256.New()
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

func (l *approvalLedger) record(tool string, args []byte, a sendApproval) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, e := range l.entries { // lazy GC
		if now.After(e.expires) {
			delete(l.entries, k)
		}
	}
	a.expires = now.Add(sendLedgerTTL)
	l.entries[ledgerKey(tool, args)] = a
}

// take returns and removes the entry: one approval → one send.
func (l *approvalLedger) take(tool string, args []byte) (sendApproval, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := ledgerKey(tool, args)
	e, ok := l.entries[k]
	if !ok {
		return sendApproval{}, false
	}
	delete(l.entries, k)
	if l.now().After(e.expires) {
		return sendApproval{}, false
	}
	return e, true
}

// errNoApprovalRecord is returned when a handler that depends on what
// the dialog showed finds no record of it.
const errNoApprovalRecord = "no record of an approval dialog showing this send's content (it may have expired " +
	"or the dialog couldn't be shown); retry the call so the Touch ID dialog can show it"

// ledgerGate is the tier-b attachment gate for send-family handlers:
// every out-of-allowlist file must have been listed (by full resolved
// path) in the approved send dialog. No second prompt.
func ledgerGate(entry sendApproval, have bool) attachmentGate {
	return func(outside []resolvedAttachmentPath) error {
		for _, o := range outside {
			if !have || !entry.outsidePaths[o.Resolved] {
				return fmt.Errorf("%q is outside attachment_path_allowlist and was not listed in the approved "+
					"send dialog; refusing", o.Requested)
			}
		}
		return nil
	}
}

func pathSet(paths []string) map[string]bool {
	if len(paths) == 0 {
		return nil
	}
	m := make(map[string]bool, len(paths))
	for _, p := range paths {
		m[p] = true
	}
	return m
}

// recipientSet normalizes + lower-cases + sorts + dedupes.
func recipientSet(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, raw := range l {
			for _, a := range normalizeRecipientList(raw) {
				a = strings.ToLower(strings.TrimSpace(a))
				if a != "" && !seen[a] {
					seen[a] = true
					out = append(out, a)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- draft digest (mail_send_draft swap protection) -------------------

// draftDigest binds an approval to the exact draft content shown:
// recipients, subject, MIME type, decrypted body, and attachment IDs.
// Length-prefixed fields so no two field splits collide.
func draftDigest(d gpa.Message, plainBody string) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	list := func(tag string, xs []string) {
		field(tag)
		field(fmt.Sprint(len(xs)))
		for _, x := range xs {
			field(strings.ToLower(x))
		}
	}
	list("to", addressStrings(d.ToList))
	list("cc", addressStrings(d.CCList))
	list("bcc", addressStrings(d.BCCList))
	field(d.Subject)
	field(string(d.MIMEType))
	field(plainBody)
	ids := make([]string, 0, len(d.Attachments))
	for _, a := range d.Attachments {
		ids = append(ids, a.ID)
	}
	list("att", ids)
	return hex.EncodeToString(h.Sum(nil))
}

// fetchDraftPlain loads a draft and decrypts its body. Shared by the
// mail_send_draft dialog and handler so both digest the same thing.
func fetchDraftPlain(ctx context.Context, deps Deps, draftID string) (gpa.Message, string, error) {
	if deps.Session == nil || deps.Session.Client == nil {
		return gpa.Message{}, "", fmt.Errorf("no active session")
	}
	draft, err := deps.Session.Client.GetMessage(ctx, draftID)
	if err != nil {
		return gpa.Message{}, "", fmt.Errorf("fetch draft: %w", err)
	}
	_, addrKR, err := senderKeyring(deps)
	if err != nil {
		return gpa.Message{}, "", err
	}
	plain, err := decryptDraftBody(addrKR, draft.Body)
	if err != nil {
		return gpa.Message{}, "", err
	}
	return draft, plain, nil
}

// draftPromptSpec builds the dialog for a loaded draft.
func draftPromptSpec(draft gpa.Message, plain string) sendPromptSpec {
	spec := sendPromptSpec{
		Action:  "Send draft",
		Tool:    "mail_send_draft",
		To:      addressStrings(draft.ToList),
		CC:      addressStrings(draft.CCList),
		BCC:     addressStrings(draft.BCCList),
		Subject: draft.Subject,
	}
	if string(draft.MIMEType) == "text/html" {
		spec.BodyHTML = plain
	} else {
		spec.BodyText = plain
	}
	for _, a := range draft.Attachments {
		spec.Attachments = append(spec.Attachments, promptAttachment{
			Name: sanitize.Filename(a.Name), Size: a.Size, FromDraft: true,
		})
	}
	return spec
}
