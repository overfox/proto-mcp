package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Daemon states published to state.json. The menu bar reads the file;
// protonmcpd is the only writer.
const (
	StateStarting   = "starting"   // process up, Setup not finished
	StateConnecting = "connecting" // waiting on the network to establish a session
	StateLocked     = "locked"     // socket open, no session (see reason)
	StateUnlocked   = "unlocked"   // session live, tools served
)

// LockReasonTouchIDRequired is the lock reason when the startup Touch
// ID gate was declined / timed out: the daemon stays up, locked, and
// waits for an explicit unlock instead of exiting into a launchd
// relaunch (which re-prompted ~once a minute all night). The menu bar
// keys its "Connect (Touch ID)…" item off reason containing "lock" or
// "touch id", so keep both words in it.
const LockReasonTouchIDRequired = "keys locked — Touch ID required"

// stateHeartbeat is how often the state file is rewritten even when
// nothing changed, so a reader can tell a live daemon from a stale file
// (updated_at older than a couple of beats → daemon is gone or wedged).
const stateHeartbeat = 30 * time.Second

// stateDoc is the on-disk schema. Field names are a contract with the
// menu bar — don't rename.
type stateDoc struct {
	State      string `json:"state"`
	Reason     string `json:"reason"`
	Email      string `json:"email"`
	PID        int    `json:"pid"`
	KeepAlive  bool   `json:"keep_alive"`
	LastTool   string `json:"last_tool"`
	LastToolAt string `json:"last_tool_at"`
	UpdatedAt  string `json:"updated_at"`
}

// StatePublisher writes the daemon's state to a JSON file (0600, atomic
// tmp+rename) on every transition and as a heartbeat. All methods are
// safe on a nil receiver (serve-stdio runs without one) and for
// concurrent use.
type StatePublisher struct {
	path   string
	logger *slog.Logger

	mu         sync.Mutex
	doc        stateDoc
	lastToolAt time.Time
	keepAlive  func() bool
	removed    bool

	kick chan struct{}
}

// DefaultStatePath is ~/Library/Application Support/protonmcp/state.json,
// next to the daemon socket.
func DefaultStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "state.json"), nil
}

// NewStatePublisher returns a publisher for path. Nothing is written
// until the first SetState.
func NewStatePublisher(path string, logger *slog.Logger) *StatePublisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &StatePublisher{
		path:   path,
		logger: logger,
		doc:    stateDoc{PID: os.Getpid()},
		kick:   make(chan struct{}, 1),
	}
}

// SetKeepAlive installs the Keep Alive reader (the policy engine's),
// consulted on every write so a toggle shows up by the next heartbeat.
func (p *StatePublisher) SetKeepAlive(fn func() bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.keepAlive = fn
	p.mu.Unlock()
}

// SetState records a transition and writes the file synchronously.
// email "" keeps the last known account (a locked daemon still knows
// whose session it holds in the Keychain).
func (p *StatePublisher) SetState(state, reason, email string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.doc.State = state
	p.doc.Reason = reason
	if email != "" {
		p.doc.Email = email
	}
	p.mu.Unlock()
	p.write()
}

// ToolCalled records the most recent tool call (at completion). Called
// on the tool-call path, so it never touches the disk itself: it
// nudges the heartbeat goroutine, which coalesces bursts into one
// write.
func (p *StatePublisher) ToolCalled(name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.doc.LastTool = name
	p.lastToolAt = time.Now()
	p.mu.Unlock()
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Run rewrites the file every stateHeartbeat and after each
// ToolCalled, until ctx is cancelled. Writes nothing until the first
// SetState. Start it before serve.Setup so the heartbeat covers the
// starting / connecting phases too (the menu bar treats ~90s without
// an update as a dead daemon).
func (p *StatePublisher) Run(ctx context.Context) {
	if p == nil {
		return
	}
	t := time.NewTicker(stateHeartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.kick:
		}
		p.write()
	}
}

// Remove deletes the file and turns every later write into a no-op
// (a heartbeat racing shutdown must not resurrect it).
func (p *StatePublisher) Remove() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removed = true
	if err := os.Remove(p.path); err != nil && !os.IsNotExist(err) {
		p.logger.Warn("remove state file", "err", err.Error())
	}
}

// write serializes the current doc and atomically replaces the file.
// Holding mu across the write orders concurrent writers, so the file
// never goes backwards.
func (p *StatePublisher) write() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.removed || p.doc.State == "" {
		return
	}
	doc := p.doc
	if p.keepAlive != nil {
		doc.KeepAlive = p.keepAlive()
	}
	if !p.lastToolAt.IsZero() {
		doc.LastToolAt = p.lastToolAt.UTC().Format(time.RFC3339)
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeFileAtomic(p.path, doc); err != nil {
		p.logger.Warn("write state file", "err", err.Error())
	}
}

func writeFileAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
