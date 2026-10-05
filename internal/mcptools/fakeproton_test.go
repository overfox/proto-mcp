package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"runtime"
	"testing"

	"github.com/ProtonMail/gluon/rfc822"
	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/go-proton-api/server"
	"github.com/bradenaw/juniper/stream"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// fakeProton is a go-proton-api fake server plus a real unlocked
// Session against it and an in-memory mirror. Tests that need actual
// API behavior (decrypt, label endpoints, RFC 822 build) use this
// instead of hand-rolled stubs. No network beyond loopback.
type fakeProton struct {
	srv    *server.Server
	sess   *protonclient.Session
	st     *store.Store
	addrID string
	userID string
}

func newFakeProton(t *testing.T) *fakeProton {
	t.Helper()
	ctx := context.Background()
	srv := server.New()
	t.Cleanup(srv.Close)

	password := []byte("correct horse battery staple")
	userID, addrID, err := srv.CreateUser("alice", password)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	mgr := gpa.New(gpa.WithHostURL(srv.GetHostURL()), gpa.WithTransport(gpa.InsecureTransport()))
	t.Cleanup(mgr.Close)

	login, auth, err := mgr.NewClientWithLogin(ctx, "alice", password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	user, err := login.GetUser(ctx)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	salts, err := login.GetSalts(ctx)
	if err != nil {
		t.Fatalf("get salts: %v", err)
	}
	salted, err := salts.SaltForKey(password, user.Keys.Primary().ID)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	sess, err := protonclient.Resume(ctx, mgr, protonclient.ResumeArgs{
		Email:         "alice@" + srv.GetDomain(),
		UID:           auth.UID,
		AccessToken:   auth.AccessToken,
		RefreshToken:  auth.RefreshToken,
		SaltedKeyPass: secret.New(salted),
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Cleanup(sess.Close)

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &fakeProton{srv: srv, sess: sess, st: st, addrID: addrID, userID: userID}
}

func (f *fakeProton) deps() Deps {
	return Deps{Session: f.sess, Store: f.st}
}

// importMessage imports a literal RFC 822 message into the fake
// account (in the inbox), mirrors its metadata into the store the way
// sync would, and returns the Proton message ID.
func (f *fakeProton) importMessage(t *testing.T, literal string, labelIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	if len(labelIDs) == 0 {
		labelIDs = []string{gpa.InboxLabel}
	}
	kr := f.sess.AddrKRs[f.addrID]
	str, err := f.sess.Client.ImportMessages(ctx, kr, runtime.NumCPU(), runtime.NumCPU(), gpa.ImportReq{
		Metadata: gpa.ImportMetadata{
			AddressID: f.addrID,
			LabelIDs:  labelIDs,
			Unread:    true,
			Flags:     gpa.MessageFlagReceived,
		},
		Message: []byte(literal),
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	var id string
	for {
		res, err := str.Next(ctx)
		if errors.Is(err, stream.End) || errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("import stream: %v", err)
		}
		if res.Code != gpa.SuccessCode {
			t.Fatalf("import code %d", res.Code)
		}
		id = res.MessageID
	}
	if id == "" {
		t.Fatal("import returned no message id")
	}
	f.mirror(t, id)
	return id
}

// mirror upserts the current server metadata for id into the store.
func (f *fakeProton) mirror(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	m, err := f.sess.Client.GetMessage(ctx, id)
	if err != nil {
		t.Fatalf("get message: %v", err)
	}
	row, err := protonclient.ToStoreMessage(m.MessageMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.UpsertMessage(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetMessageLabels(ctx, id, m.LabelIDs); err != nil {
		t.Fatal(err)
	}
}

// callTool runs a tool handler and decodes its structured result into
// out (when non-nil). Returns the raw ToolResult for isError checks.
func callTool(t *testing.T, tl mcp.Tool, args string, out any) *mcp.ToolResult {
	t.Helper()
	res, err := tl.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s(%s): handler error: %v", tl.Name, args, err)
	}
	if res.IsError {
		return res
	}
	if out != nil {
		if err := json.Unmarshal([]byte(res.Content[0].Text), out); err != nil {
			t.Fatalf("%s: decode result: %v", tl.Name, err)
		}
	}
	return res
}

const fakeMsgWithAttachment = "From: Bank Ops <ops@bank.example>\r\n" +
	"To: alice@proton.local\r\n" +
	"Subject: Statement: Q3/2026\r\n" +
	"Date: Mon, 05 Oct 2026 09:30:00 +0000\r\n" +
	"Message-ID: <stmt-1@bank.example>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n" +
	"\r\n" +
	"--BOUND\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"Please find your statement attached.\r\n" +
	"--BOUND\r\n" +
	"Content-Type: text/csv; name=\"positions.csv\"\r\n" +
	"Content-Disposition: attachment; filename=\"positions.csv\"\r\n" +
	"\r\n" +
	"isin,qty\r\nCH0012345678,100\r\n" +
	"--BOUND--\r\n"

// fakeAttachment is one file to attach via createMessageWithAttachments.
type fakeAttachment struct {
	Name string
	MIME string
	Body []byte
}

// createMessageWithAttachments builds a message server-side through
// the draft + upload endpoints (the fake server's import path keeps
// multipart bodies whole and never splits out attachments). The
// result is a real Proton message with encrypted body and attachment
// key packets — exactly what the export / attachment decrypt paths
// consume in production. Mirrored into the store; returns the message
// ID and the attachment IDs in order.
func (f *fakeProton) createMessageWithAttachments(t *testing.T, subject, body string, atts ...fakeAttachment) (string, []string) {
	t.Helper()
	ctx := context.Background()
	kr := f.sess.AddrKRs[f.addrID]
	from := &mail.Address{Name: "Alice", Address: f.sess.Email}
	draft, err := f.sess.Client.CreateDraft(ctx, kr, gpa.CreateDraftReq{
		Message: gpa.DraftTemplate{
			Subject:  subject,
			Sender:   from,
			ToList:   []*mail.Address{{Name: "Bob", Address: "bob@example.com"}},
			Body:     body,
			MIMEType: rfc822.TextPlain,
		},
	})
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	var ids []string
	for _, a := range atts {
		att, err := f.sess.Client.UploadAttachment(ctx, kr, gpa.CreateAttachmentReq{
			MessageID:   draft.ID,
			Filename:    a.Name,
			MIMEType:    rfc822.MIMEType(a.MIME),
			Disposition: gpa.AttachmentDisposition,
			Body:        a.Body,
		})
		if err != nil {
			t.Fatalf("upload attachment: %v", err)
		}
		ids = append(ids, att.ID)
	}
	f.mirror(t, draft.ID)
	return draft.ID, ids
}

func mcpCtx() mcp.Context { return mcp.Context{Std: context.Background()} }
