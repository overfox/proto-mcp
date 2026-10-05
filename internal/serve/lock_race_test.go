package serve

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/go-proton-api/server"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
	syncpkg "github.com/just-an-oldsalt/proto-mcp/internal/sync"
)

// fakeProtonSession logs in to go-proton-api's in-process fake server
// and wraps the client in a Session, so tests exercise a real
// *gpa.Client (the thing Lock used to nil out from under sync).
func fakeProtonSession(t *testing.T) *protonclient.Session {
	t.Helper()
	srv := server.New()
	t.Cleanup(srv.Close)
	if _, _, err := srv.CreateUser("alice", []byte("pw")); err != nil {
		t.Fatalf("create user: %v", err)
	}
	mgr := gpa.New(gpa.WithHostURL(srv.GetHostURL()), gpa.WithTransport(gpa.InsecureTransport()))
	t.Cleanup(mgr.Close)
	c, _, err := mgr.NewClientWithLogin(context.Background(), "alice", []byte("pw"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return &protonclient.Session{Client: c, Email: "alice@proton.local"}
}

func liveRuntime(t *testing.T, sess *protonclient.Session) (*Runtime, *liveSession) {
	t.Helper()
	ls := newLiveSession(fakeBundle{sess: sess})
	return &Runtime{live: ls, Session: sess}, ls
}

// Regression for the lock-during-sync crash (sync.go:92 /
// calendar.go:66 nil-pointer panics in the daemon log): Lock used to
// Close the session — nilling Client — while the background sync
// goroutine was mid-drain, and its next sess.Client call panicked,
// killing the daemon. Now Lock cancels the drain, waits for it, and
// only then closes the session.
func TestLockDuringBackgroundSync_NoCrash(t *testing.T) {
	sess := fakeProtonSession(t)
	rt, _ := liveRuntime(t, sess)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rt.Store = st

	inSync := make(chan struct{})
	var sawCancel, closedMidSync atomic.Bool
	rt.syncFn = func(ctx context.Context, s *protonclient.Session, _ *store.Store, _ *slog.Logger) {
		close(inSync)
		select {
		case <-ctx.Done(): // Lock must cancel the in-flight drain
			sawCancel.Store(true)
		case <-time.After(2 * time.Second):
		}
		// An in-flight call finishing after the cancel: before the fix
		// s.Client was nil here and this panicked.
		closedMidSync.Store(s.Closed())
		_, _ = s.Client.GetLatestEventID(context.Background())
	}

	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		rt.backgroundSyncOnce(context.Background(), discardLogger())
	}()
	<-inSync

	lockDone := make(chan struct{})
	go func() { rt.Lock("test"); close(lockDone) }()

	select {
	case <-lockDone:
	case <-time.After(lockDrainTimeout + 2*time.Second):
		t.Fatal("Lock did not return")
	}
	<-syncDone
	if !sawCancel.Load() {
		t.Error("Lock did not cancel the in-flight sync")
	}
	if closedMidSync.Load() {
		t.Error("session was closed while sync still held it")
	}
	if !sess.Closed() {
		t.Error("session not closed after the sync released it")
	}
	if locked, _ := rt.Locked(); !locked {
		t.Error("runtime not locked")
	}
}

// Hammer lock/unlock against concurrent syncs and tool calls under
// -race: no panic, no data race on the session.
func TestLockUnlockStress(t *testing.T) {
	rt := &Runtime{locked: true}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rt.Store = st
	rt.acquireSession = func(context.Context) (SessionBundle, error) {
		return fakeBundle{sess: &protonclient.Session{Email: "x@example.com"}}, nil
	}
	rt.syncFn = func(ctx context.Context, s *protonclient.Session, _ *store.Store, _ *slog.Logger) {
		if s.Closed() {
			panic("sync saw a closed session")
		}
		_ = s.UserKR // read that would race the keyring wipe
		select {
		case <-ctx.Done():
		case <-time.After(time.Millisecond):
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				rt.backgroundSyncOnce(ctx, discardLogger())
			}
		}
	}()
	for range 200 {
		if err := rt.Unlock(ctx); err != nil {
			t.Fatal(err)
		}
		rt.Lock("stress")
	}
	close(stop)
	<-done
}

// Session-backed tools hold a reference for the whole call and refuse
// once the session is retired; a nil (start-locked) binding refuses
// without dereferencing anything.
func TestWrapTools(t *testing.T) {
	sess := &protonclient.Session{}
	ls := newLiveSession(fakeBundle{sess: sess})
	release := make(chan struct{})
	started := make(chan struct{})
	tools := wrapTools(ls, []mcp.Tool{
		{Name: "slow", Handler: func(c mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			close(started)
			<-release
			if sess.Closed() {
				t.Error("session closed during an in-flight tool call")
			}
			return &mcp.ToolResult{}, nil
		}},
		{Name: "connect", AllowWhenLocked: true, Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
			return &mcp.ToolResult{}, nil
		}},
	})
	done := make(chan struct{})
	go func() {
		_, _ = tools[0].Handler(mcp.Context{Std: context.Background()}, nil)
		close(done)
	}()
	<-started
	drained := ls.retire()
	select {
	case <-drained:
		t.Fatal("session drained while a tool still held it")
	default:
	}
	close(release)
	<-done
	<-drained
	if !sess.Closed() {
		t.Fatal("session not closed after last user released")
	}
	// Retired: new calls refuse with the locked message.
	res, err := tools[0].Handler(mcp.Context{Std: context.Background()}, nil)
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("retired session: got (%v, %v), want locked error result", res, err)
	}
	// AllowWhenLocked passes through untouched.
	if res, _ := tools[1].Handler(mcp.Context{}, nil); res == nil || res.IsError {
		t.Fatal("AllowWhenLocked tool was gated")
	}

	nilTools := wrapTools(nil, []mcp.Tool{{Name: "x", Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
		t.Fatal("handler ran with no session")
		return nil, nil
	}}})
	if res, _ := nilTools[0].Handler(mcp.Context{}, nil); res == nil || !res.IsError {
		t.Fatal("nil-session tool did not refuse")
	}
}

// Connect must not queue behind a pending unlock (offline SIGUSR2 used
// to hold the slot forever and hang proton_connect), and must ask the
// acquire for a single attempt.
func TestConnect_PromptAndNoRetry(t *testing.T) {
	rt := &Runtime{locked: true}
	var sawNoRetry atomic.Bool
	rt.acquireSession = func(ctx context.Context) (SessionBundle, error) {
		sawNoRetry.Store(!NetworkRetryAllowed(ctx))
		return nil, errors.New("proton API unreachable")
	}
	if _, _, err := rt.Connect(context.Background()); err == nil {
		t.Fatal("Connect succeeded offline")
	}
	if !sawNoRetry.Load() {
		t.Error("Connect did not disable the network retry loop")
	}
	// A network failure doesn't trigger the Touch ID cooldown...
	rt.unlockSlot() <- struct{}{} // ...but a busy slot fails fast.
	start := time.Now()
	_, _, err := rt.Connect(context.Background())
	if !errors.Is(err, ErrUnlockInProgress) {
		t.Fatalf("Connect with unlock in progress: err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Connect blocked behind the in-progress unlock")
	}
	<-rt.unlockSlot()

	// Unlock (SIGUSR2 path) honors ctx while waiting for the slot.
	rt.unlockSlot() <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rt.Unlock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Unlock waiting on a busy slot: err = %v", err)
	}
}

// Self-healing refresh: an ErrRefreshRequested triggers the backfill,
// at most once per fullRefreshMinInterval.
func TestMaybeFullRefresh_RateLimited(t *testing.T) {
	rt := &Runtime{}
	var runs atomic.Int32
	rt.fullRefreshFn = func(context.Context, *protonclient.Session, *store.Store) (*syncpkg.BackfillResult, error) {
		runs.Add(1)
		return &syncpkg.BackfillResult{}, nil
	}
	rt.maybeFullRefresh(context.Background(), nil, nil, discardLogger())
	rt.maybeFullRefresh(context.Background(), nil, nil, discardLogger())
	if got := runs.Load(); got != 1 {
		t.Fatalf("backfill ran %d times within the rate limit, want 1", got)
	}
	rt.lastFullRefresh.Store(time.Now().Add(-fullRefreshMinInterval - time.Minute).UnixNano())
	rt.maybeFullRefresh(context.Background(), nil, nil, discardLogger())
	if got := runs.Load(); got != 2 {
		t.Fatalf("backfill did not rerun after the interval (runs=%d)", got)
	}
}

// End to end against the fake server: a Proton-side refresh flag makes
// RunOnce return ErrRefreshRequested, and the runtime's sync path
// self-heals by backfilling (re-seeding the cursor) instead of freezing.
func TestBackgroundSync_RefreshTriggersBackfill(t *testing.T) {
	srv := server.New()
	defer srv.Close()
	userID, _, err := srv.CreateUser("bob", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	mgr := gpa.New(gpa.WithHostURL(srv.GetHostURL()), gpa.WithTransport(gpa.InsecureTransport()))
	defer mgr.Close()
	c, _, err := mgr.NewClientWithLogin(context.Background(), "bob", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	sess := &protonclient.Session{Client: c}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	// Seed a cursor, then have the server demand a refresh.
	if _, err := syncpkg.RunOnce(ctx, sess, st); err != nil {
		t.Fatal(err)
	}
	if err := srv.RefreshUser(userID, gpa.RefreshMail); err != nil {
		t.Fatal(err)
	}
	if _, err := syncpkg.RunOnce(ctx, sess, st); !errors.Is(err, syncpkg.ErrRefreshRequested) {
		t.Fatalf("setup: RunOnce err = %v, want ErrRefreshRequested", err)
	}
	before, _ := st.GetSyncState(ctx, "event_cursor")

	rt, _ := liveRuntime(t, sess)
	rt.Store = st
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	rt.backgroundSyncOnce(ctx, logger)
	if !strings.Contains(logs.String(), "automatic backfill complete") {
		t.Fatalf("no automatic backfill; log:\n%s", logs.String())
	}
	after, _ := st.GetSyncState(ctx, "event_cursor")
	if after == "" || after == before {
		t.Fatalf("cursor not re-seeded (before=%q after=%q)", before, after)
	}
	if _, err := syncpkg.RunOnce(ctx, sess, st); err != nil {
		t.Fatalf("sync still broken after self-heal: %v", err)
	}
}
