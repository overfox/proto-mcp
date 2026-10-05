package serve

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// TestLockwatchBackoff_ResetsAfterHealthyRun drives the restart loop with
// a fake clock: three quick crashes back off 1s→2s→4s, a run longer than
// lockwatchHealthyRun resets to 1s, and the delay is capped at 30s.
func TestLockwatchBackoff_ResetsAfterHealthyRun(t *testing.T) {
	// Run durations for successive helper invocations.
	runs := []time.Duration{
		time.Second, time.Second, time.Second, // crash loop
		2 * time.Hour,       // healthy, then crashed
		time.Second,         // quick crash right after
		0, 0, 0, 0, 0, 0, 0, // crash loop to the cap
	}
	var (
		clock       = time.Unix(0, 0)
		waits       []time.Duration
		ctx, cancel = context.WithCancel(context.Background())
	)
	defer cancel()
	i := 0
	runOnce := func(context.Context) error {
		if i >= len(runs) {
			cancel()
			return nil
		}
		clock = clock.Add(runs[i])
		i++
		return errors.New("helper crashed")
	}
	after := func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		clock = clock.Add(d)
		ch := make(chan time.Time, 1)
		ch <- clock
		return ch
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runLockwatchLoopWith(ctx, runOnce, logger, func() time.Time { return clock }, after)

	s := time.Second
	want := []time.Duration{1 * s, 2 * s, 4 * s, 1 * s, 2 * s, 4 * s, 8 * s, 16 * s, 30 * s, 30 * s, 30 * s, 30 * s}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for k := range want {
		if waits[k] != want[k] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}
}
