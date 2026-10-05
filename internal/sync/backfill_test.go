package sync

import (
	"context"
	"errors"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/go-proton-api/server"

	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// Backfill against go-proton-api's fake server: labels are seeded, the
// pre-drain cursor is persisted, and Confirm can veto.
func TestBackfill_FakeServer(t *testing.T) {
	ctx := context.Background()
	srv := server.New()
	defer srv.Close()
	userID, _, err := srv.CreateUser("carol", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.CreateLabel(userID, "Receipts", "", gpa.LabelTypeLabel); err != nil {
		t.Fatal(err)
	}
	mgr := gpa.New(gpa.WithHostURL(srv.GetHostURL()), gpa.WithTransport(gpa.InsecureTransport()))
	defer mgr.Close()
	c, _, err := mgr.NewClientWithLogin(ctx, "carol", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	sess := &protonclient.Session{Client: c}
	st := mustOpen(t)

	_, err = Backfill(ctx, sess, st, BackfillOptions{Confirm: func(int) (bool, error) { return false, nil }})
	if !errors.Is(err, ErrBackfillAborted) {
		t.Fatalf("declined confirm: err = %v", err)
	}
	if _, err := st.GetSyncState(ctx, cursorKey); err == nil {
		t.Fatal("aborted backfill persisted a cursor")
	}

	res, err := Backfill(ctx, sess, st, BackfillOptions{})
	if err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	if res.Labels != 1 {
		t.Errorf("labels seeded = %d, want 1", res.Labels)
	}
	cur, err := st.GetSyncState(ctx, cursorKey)
	if err != nil || cur == "" || cur != res.Cursor {
		t.Errorf("cursor = %q (%v), want %q", cur, err, res.Cursor)
	}

	sess.Close()
	if _, err := Backfill(ctx, sess, st, BackfillOptions{}); !errors.Is(err, protonclient.ErrSessionClosed) {
		t.Errorf("closed session: err = %v, want ErrSessionClosed", err)
	}
}
