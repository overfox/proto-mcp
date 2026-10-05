package serve

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestStagingSweep_RetentionAndTicker(t *testing.T) {
	var (
		mu      sync.Mutex
		cutoffs []time.Time
	)
	prev := stagingSweepFn
	stagingSweepFn = func(cutoff time.Time) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		cutoffs = append(cutoffs, cutoff)
		return 1, nil
	}
	t.Cleanup(func() { stagingSweepFn = prev })

	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		runStagingSweepEvery(ctx, logger, 5*time.Millisecond, func() time.Time { return now })
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(cutoffs)
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("sweep ran %d times, want >=3 (immediate + ticks)", n)
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if want := now.Add(-24 * time.Hour); !cutoffs[0].Equal(want) {
		t.Errorf("cutoff = %v, want %v (24h retention)", cutoffs[0], want)
	}
	if stagingRetention != 24*time.Hour || stagingSweepInterval != time.Hour {
		t.Errorf("retention/interval = %v/%v, want 24h/1h", stagingRetention, stagingSweepInterval)
	}
}
