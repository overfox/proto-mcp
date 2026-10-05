package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/serve"
	"github.com/just-an-oldsalt/proto-mcp/internal/session"
)

func instantAfter(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

var errOffline = fmt.Errorf("%w: dial tcp: no route to host", session.ErrNetworkUnavailable)

func TestAcquireWithRetry_WaitsOutOutage(t *testing.T) {
	calls := 0
	resume := func(context.Context) (*session.Bundle, error) {
		calls++
		if calls < 3 {
			return nil, errOffline
		}
		return &session.Bundle{}, nil
	}
	state := serve.NewStatePublisher(filepath.Join(t.TempDir(), "state.json"), nil)
	b, err := acquireWithRetry(context.Background(), resume, state, instantAfter)
	if err != nil || b == nil {
		t.Fatalf("got (%v, %v), want a bundle", b, err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

// proton_connect marks its ctx no-retry: one attempt, prompt error.
func TestAcquireWithRetry_NoRetryReturnsPromptly(t *testing.T) {
	calls := 0
	resume := func(context.Context) (*session.Bundle, error) { calls++; return nil, errOffline }
	never := func(time.Duration) <-chan time.Time { return nil }
	_, err := acquireWithRetry(serve.WithoutNetworkRetry(context.Background()), resume, nil, never)
	if !errors.Is(err, session.ErrNetworkUnavailable) || calls != 1 {
		t.Fatalf("err = %v calls = %d, want one ErrNetworkUnavailable attempt", err, calls)
	}
}

// SIGTERM (ctx cancel) during the wait ends the loop with ctx's error,
// which run() turns into a clean exit 0.
func TestAcquireWithRetry_RespectsCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resume := func(context.Context) (*session.Bundle, error) { cancel(); return nil, errOffline }
	never := func(time.Duration) <-chan time.Time { return nil }
	done := make(chan error, 1)
	go func() { _, err := acquireWithRetry(ctx, resume, nil, never); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop ignored ctx cancellation")
	}
}

func TestAcquireWithRetry_AuthFailureIsFinal(t *testing.T) {
	calls := 0
	resume := func(context.Context) (*session.Bundle, error) { calls++; return nil, session.ErrLoginRequired }
	_, err := acquireWithRetry(context.Background(), resume, nil, instantAfter)
	if !errors.Is(err, session.ErrLoginRequired) || calls != 1 {
		t.Fatalf("err = %v calls = %d", err, calls)
	}
}
