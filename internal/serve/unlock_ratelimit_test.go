package serve

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
)

func TestPromptLimiter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := &promptLimiter{now: func() time.Time { return now }}
	if err := l.allow(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	if err := l.allow(); !errors.Is(err, ErrUnlockRateLimited) {
		t.Fatalf("second prompt within 30s: err = %v", err)
	}
	// Five more at 31s spacing → 6 in the hour, the 7th refused.
	for i := 0; i < 5; i++ {
		now = now.Add(31 * time.Second)
		if err := l.allow(); err != nil {
			t.Fatalf("prompt %d: %v", i+2, err)
		}
	}
	now = now.Add(31 * time.Second)
	if err := l.allow(); !errors.Is(err, ErrUnlockRateLimited) {
		t.Fatalf("7th prompt in an hour: err = %v", err)
	}
	now = now.Add(time.Hour)
	if err := l.allow(); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
}

// proton_connect is rate-limited and the prompt names the requester.
func TestConnect_RateLimitedAndNamesRequester(t *testing.T) {
	var whoSeen []string
	rt := &Runtime{locked: true, unlockLimiter: newPromptLimiter()}
	rt.acquireSession = func(ctx context.Context) (SessionBundle, error) {
		whoSeen = append(whoSeen, unlockRequester(ctx))
		return nil, ErrTouchIDGate // declined
	}
	ctx := caller.WithCaller(context.Background(), caller.Caller{PID: 4242, Binary: "/x/claude"})
	if _, _, err := rt.Connect(ctx); err == nil {
		t.Fatal("declined connect succeeded")
	}
	if len(whoSeen) != 1 || whoSeen[0] != "proton_connect from claude (pid 4242)" {
		t.Fatalf("requester = %v", whoSeen)
	}
	// Bypass Connect's own decline cooldown: hit unlock directly as a
	// second SIGUSR2 would.
	if err := rt.unlock(context.Background(), false); !errors.Is(err, ErrUnlockRateLimited) {
		t.Fatalf("second prompt within 30s: err = %v", err)
	}
	if len(whoSeen) != 1 {
		t.Fatal("rate-limited unlock still prompted")
	}
}
