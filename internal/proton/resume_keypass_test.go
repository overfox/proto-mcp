package proton

import (
	"bytes"
	"context"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/go-proton-api/server"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// TestResumeOwnsSaltedKeyPass is the regression test for the overnight
// Keychain corruption: session.TryResume Zero()s its copy of the key
// password right after Resume returns. When Resume stored the same
// Secret (a struct copy sharing the backing array), the live session
// was left holding all-zero key material, which the next token refresh
// then saved to the Keychain. Runs Resume for real against go-proton-api's
// fake server.
func TestResumeOwnsSaltedKeyPass(t *testing.T) {
	ctx := context.Background()
	srv := server.New()
	defer srv.Close()

	password := []byte("correct horse battery staple")
	if _, _, err := srv.CreateUser("alice", password); err != nil {
		t.Fatalf("create user: %v", err)
	}

	mgr := gpa.New(gpa.WithHostURL(srv.GetHostURL()), gpa.WithTransport(gpa.InsecureTransport()))
	defer mgr.Close()

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
	saltedRaw, err := salts.SaltForKey(password, user.Keys.Primary().ID)
	if err != nil {
		t.Fatalf("salt for key: %v", err)
	}
	want := append([]byte(nil), saltedRaw...)

	// Exactly what TryResume does: pass a Secret in, then wipe it.
	callerCopy := secret.New(saltedRaw)
	sess, err := Resume(ctx, mgr, ResumeArgs{
		Email:         "alice@" + "proton.local",
		UID:           auth.UID,
		AccessToken:   auth.AccessToken,
		RefreshToken:  auth.RefreshToken,
		SaltedKeyPass: callerCopy,
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	defer sess.Close()
	callerCopy.Zero()

	got := sess.SaltedKeyPass.Bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("session key password was wiped along with the caller's copy (len %d, all-zero=%v); "+
			"the next token refresh would save it to the Keychain and break the following resume",
			len(got), bytes.Count(got, []byte{0}) == len(got))
	}
}
