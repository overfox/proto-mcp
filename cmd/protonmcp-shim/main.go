// protonmcp-shim is the thin stdio↔socket forwarder that Claude
// Desktop / Claude Code spawn. It connects to the running
// protonmcpd daemon's Unix socket and pumps NDJSON frames in both
// directions.
//
// Architecture:
//
//	Claude client
//	    │ stdin / stdout  (NDJSON, MCP spec)
//	    ▼
//	protonmcp-shim   (this binary; nearly stateless)
//	    │ Unix socket  (same NDJSON framing)
//	    ▼
//	protonmcpd       (long-running daemon; one Runtime, N conns)
//
// What this binary does NOT do: hold MCP session state beyond the
// handshake, enforce policy, or interpret tool calls. All of that
// lives in the daemon.
//
// Transparent reconnect. The daemon restarts more often than the
// Claude client does (rebuilds, `daemon install`, launchd restarts
// after a crash, the kill switch). Previously the shim exited when
// the socket closed and the client showed "Connection closed" until
// the whole app was restarted. Now the shim survives a daemon
// restart:
//
//   - it peeks at each client→daemon frame (id + method only) and
//     records the client's `initialize` request and the
//     `notifications/initialized` notification;
//   - when the socket drops it fails every request that was in
//     flight on that connection with a JSON-RPC error ("protonmcp
//     daemon restarted; retry") so the client is never left hanging,
//     then redials with backoff for up to reconnectWindow;
//   - on the new connection it replays initialize (under a
//     shim-private id whose response is swallowed) and initialized,
//     so the daemon's per-connection handshake state is restored
//     before any client traffic flows;
//   - frames the client sends while disconnected wait for the
//     reconnect (bounded by the reconnect window) and requests then
//     fail with a clear error if the daemon never came back. A later
//     request triggers a fresh, shorter reconnect attempt, so the
//     shim recovers on its own once the daemon is up again.
//
// stdout carries strictly valid NDJSON: only whole frames from the
// daemon or JSON-RPC error responses the shim synthesizes. Diagnostics
// go to stderr.
//
// Phase 6/B. See TODO.html and SECURITY.md for the broader
// context.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// errCodeDaemon is the JSON-RPC implementation-defined server error
// the shim uses for every error it synthesizes itself.
const errCodeDaemon = -32099

// restartedMessage is the error returned for requests that were in
// flight when the daemon connection dropped.
const restartedMessage = "protonmcp daemon restarted; retry"

// config holds the shim's timing knobs. Production values live in
// defaultConfig; tests shrink them.
type config struct {
	// initialWindow bounds the wait for the socket at startup. Long
	// because the daemon may be sitting in its Touch ID startup gate
	// (or launchd may be relaunching it) when Claude spawns us.
	initialWindow time.Duration
	// reconnectWindow bounds redialing after an established
	// connection drops (daemon restart / rebuild / crash).
	reconnectWindow time.Duration
	// retryWindow bounds the lazy redial a new request triggers once
	// an earlier reconnect attempt has given up.
	retryWindow time.Duration
	// handshakeTimeout bounds the wait for the replayed initialize
	// response on a fresh connection.
	handshakeTimeout time.Duration
	dialTimeout      time.Duration
	backoffMin       time.Duration
	backoffMax       time.Duration
}

var defaultConfig = config{
	initialWindow:    90 * time.Second,
	reconnectWindow:  3 * time.Minute,
	retryWindow:      15 * time.Second,
	handshakeTimeout: 15 * time.Second,
	dialTimeout:      2 * time.Second,
	backoffMin:       100 * time.Millisecond,
	backoffMax:       2 * time.Second,
}

func main() {
	if err := run(); err != nil {
		// stderr only — stdout is reserved for MCP framing.
		fmt.Fprintln(os.Stderr, "protonmcp-shim:", err)
		os.Exit(1)
	}
}

func run() error {
	sockPath, err := defaultSocketPath()
	if err != nil {
		return err
	}
	// Allow override via env (test convenience). Production users
	// shouldn't need this; the daemon's default path matches the
	// shim's default lookup.
	if v := os.Getenv("PROTONMCP_SOCKET"); v != "" {
		sockPath = v
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	s := newShim(sockPath, os.Stdout, defaultConfig)
	return s.run(ctx, os.Stdin)
}

// inflightReq is a client request forwarded to the daemon whose
// response hasn't come back yet.
type inflightReq struct {
	id  json.RawMessage // exactly as the client sent it
	gen uint64          // connection generation it was written to
}

type shim struct {
	sockPath string
	cfg      config
	logf     func(format string, args ...any)

	outMu sync.Mutex
	out   io.Writer

	mu           sync.Mutex
	ctx          context.Context
	conn         net.Conn // nil while disconnected
	gen          uint64   // bumped on every successful (re)connect
	reconnecting bool
	changed      chan struct{} // closed when a reconnect attempt ends
	lastErr      error         // why the last reconnect attempt gave up
	lastWindow   time.Duration
	inflight     map[string]inflightReq
	initLine     []byte // client's initialize request, verbatim
	initdLine    []byte // client's notifications/initialized, verbatim

	wmu sync.Mutex // serializes writes to conn
}

func newShim(sockPath string, out io.Writer, cfg config) *shim {
	return &shim{
		sockPath: sockPath,
		cfg:      cfg,
		out:      out,
		inflight: make(map[string]inflightReq),
		changed:  make(chan struct{}),
		logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "protonmcp-shim: "+format+"\n", args...)
		},
	}
}

// run starts the initial connect and forwards client frames until
// stdin closes or ctx is cancelled.
func (s *shim) run(ctx context.Context, in io.Reader) error {
	s.mu.Lock()
	s.ctx = ctx
	s.startReconnectLocked(s.cfg.initialWindow)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
		s.mu.Unlock()
	}()

	errc := make(chan error, 1)
	go func() { errc <- s.readClient(ctx, in) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// frame is the slice of a JSON-RPC message the shim cares about.
type frame struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func peek(line []byte) (f frame, ok bool) {
	t := bytes.TrimSpace(line)
	if len(t) == 0 || t[0] != '{' {
		return f, false // batch or garbage: forward untouched
	}
	if err := json.Unmarshal(t, &f); err != nil {
		return f, false
	}
	return f, true
}

func hasID(id json.RawMessage) bool {
	return len(id) > 0 && !bytes.Equal(bytes.TrimSpace(id), []byte("null"))
}

// idKey canonicalizes a JSON id so `1` from the client matches `1`
// re-encoded by the daemon.
func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if err := json.Compact(&b, id); err != nil {
		return string(id)
	}
	return b.String()
}

// readClient pumps client (stdin) frames to the daemon, one line at
// a time so frames never interleave.
func (s *shim) readClient(ctx context.Context, in io.Reader) error {
	br := bufio.NewReaderSize(in, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				line = append(line, '\n')
			}
			s.forward(ctx, line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read stdin: %w", err)
		}
	}
}

// forward sends one client frame to the daemon, waiting for a
// (re)connect if necessary.
func (s *shim) forward(ctx context.Context, line []byte) {
	f, parsed := peek(line)
	isRequest := parsed && f.Method != "" && hasID(f.ID)

	if parsed {
		switch f.Method {
		case "initialize":
			s.mu.Lock()
			s.initLine = append([]byte(nil), line...)
			s.mu.Unlock()
		case "notifications/initialized":
			s.mu.Lock()
			s.initdLine = append([]byte(nil), line...)
			s.mu.Unlock()
		}
	}

	for attempt := 0; ; attempt++ {
		conn, gen, err := s.acquire(ctx, isRequest)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isRequest {
				s.writeError(f.ID, unreachableMessage(s.sockPath, s.window(), err),
					map[string]any{"dial_error": err.Error()})
			}
			// Notifications and client responses to server requests
			// have nowhere to go; dropping them is the only option.
			return
		}
		if isRequest {
			s.mu.Lock()
			s.inflight[idKey(f.ID)] = inflightReq{id: f.ID, gen: gen}
			s.mu.Unlock()
		}
		s.wmu.Lock()
		_, werr := conn.Write(line)
		s.wmu.Unlock()
		if werr == nil {
			return
		}
		// The write failed: the connection is gone. lost() fails the
		// request we just registered (it was "in flight"), so don't
		// resend it — the daemon may already have acted on it.
		s.lost(gen, werr)
		if isRequest || attempt > 0 {
			return
		}
		// Notification / response: one retry on the next connection.
	}
}

// acquire returns the live connection, waiting for an in-progress
// reconnect. When the shim had already given up before this frame
// arrived and the frame is a request, it kicks off one short fresh
// attempt before failing. A frame that waited out a failed attempt
// fails right away rather than starting another one.
func (s *shim) acquire(ctx context.Context, isRequest bool) (net.Conn, uint64, error) {
	attempted := false
	for {
		s.mu.Lock()
		if s.conn != nil {
			c, g := s.conn, s.gen
			s.mu.Unlock()
			return c, g, nil
		}
		if !s.reconnecting {
			if !isRequest || attempted {
				err := s.lastErr
				s.mu.Unlock()
				if err == nil {
					err = errors.New("not connected")
				}
				return nil, 0, err
			}
			s.startReconnectLocked(s.cfg.retryWindow)
		}
		attempted = true
		ch := s.changed
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
}

func (s *shim) window() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastWindow
}

// startReconnectLocked launches a dial loop. Caller holds s.mu.
func (s *shim) startReconnectLocked(window time.Duration) {
	if s.reconnecting {
		return
	}
	s.reconnecting = true
	s.lastWindow = window
	s.changed = make(chan struct{})
	go s.reconnect(s.ctx, window)
}

func (s *shim) reconnect(ctx context.Context, window time.Duration) {
	deadline := time.Now().Add(window)
	backoff := s.cfg.backoffMin
	var lastErr error
	for {
		if ctx.Err() != nil {
			s.giveUp(ctx.Err())
			return
		}
		c, err := net.DialTimeout("unix", s.sockPath, s.cfg.dialTimeout)
		if err == nil {
			var br *bufio.Reader
			br, err = s.handshake(c)
			if err == nil {
				s.publish(c, br)
				return
			}
			_ = c.Close()
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			s.logf("giving up on daemon at %s after %s: %v", s.sockPath, window, lastErr)
			s.giveUp(lastErr)
			return
		}
		wait := backoff
		if rem := time.Until(deadline); wait > rem {
			wait = rem
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		backoff *= 2
		if backoff > s.cfg.backoffMax {
			backoff = s.cfg.backoffMax
		}
	}
}

// replayIDPrefix marks the shim's own replayed initialize so its
// response can be swallowed instead of reaching the client.
const replayIDPrefix = "protonmcp-shim-replay-"

// handshake replays the client's initialize + initialized on a fresh
// connection. It is a no-op on the very first connection (the client
// hasn't sent initialize yet; its own frames do the handshake). The
// returned reader must be used for all further reads from c — it may
// already hold buffered daemon frames.
func (s *shim) handshake(c net.Conn) (*bufio.Reader, error) {
	br := bufio.NewReaderSize(c, 64*1024)
	s.mu.Lock()
	initLine, initdLine, gen := s.initLine, s.initdLine, s.gen+1
	s.mu.Unlock()
	if initLine == nil {
		return br, nil
	}

	var msg map[string]json.RawMessage
	if err := json.Unmarshal(initLine, &msg); err != nil {
		return nil, fmt.Errorf("replay initialize: %w", err)
	}
	replayID := fmt.Sprintf("%s%d", replayIDPrefix, gen)
	idJSON, _ := json.Marshal(replayID)
	msg["id"] = idJSON
	replay, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("replay initialize: %w", err)
	}

	_ = c.SetDeadline(time.Now().Add(s.cfg.handshakeTimeout))
	if _, err := c.Write(append(replay, '\n')); err != nil {
		return nil, fmt.Errorf("replay initialize: %w", err)
	}
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("await replayed initialize response: %w", err)
		}
		f, ok := peek(line)
		if ok && f.Method == "" && idKey(f.ID) == string(idJSON) {
			// Swallowed. An error result is logged but not fatal:
			// the connection is up and later requests will surface
			// whatever the daemon is unhappy about.
			var resp struct {
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(line, &resp) == nil && resp.Error != nil {
				s.logf("replayed initialize returned error: %s", resp.Error.Message)
			}
			break
		}
		// Anything else (a server notification, say) goes to the
		// client as usual.
		s.writeOut(line)
	}
	if initdLine != nil {
		if _, err := c.Write(initdLine); err != nil {
			return nil, fmt.Errorf("replay initialized: %w", err)
		}
	}
	_ = c.SetDeadline(time.Time{})
	return br, nil
}

func (s *shim) publish(c net.Conn, br *bufio.Reader) {
	s.mu.Lock()
	s.gen++
	gen := s.gen
	s.conn = c
	s.reconnecting = false
	s.lastErr = nil
	close(s.changed)
	s.mu.Unlock()
	if gen > 1 {
		s.logf("reconnected to daemon at %s", s.sockPath)
	}
	go s.readDaemon(c, br, gen)
}

func (s *shim) giveUp(err error) {
	s.mu.Lock()
	s.reconnecting = false
	s.lastErr = err
	close(s.changed)
	s.mu.Unlock()
}

// readDaemon pumps daemon frames to stdout until the connection
// drops, then hands off to lost().
func (s *shim) readDaemon(c net.Conn, br *bufio.Reader, gen uint64) {
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			// A partial trailing frame (no newline) is dropped: it
			// can't be valid NDJSON and would corrupt stdout framing.
			s.lost(gen, err)
			return
		}
		if f, ok := peek(line); ok && f.Method == "" && hasID(f.ID) {
			s.mu.Lock()
			delete(s.inflight, idKey(f.ID))
			s.mu.Unlock()
		}
		s.writeOut(line)
	}
}

// lost handles the loss of connection generation gen: fails its
// in-flight requests and starts reconnecting. Idempotent per gen.
func (s *shim) lost(gen uint64, cause error) {
	s.mu.Lock()
	if s.conn == nil || gen != s.gen {
		s.mu.Unlock()
		return
	}
	_ = s.conn.Close()
	s.conn = nil
	var failed []json.RawMessage
	for k, r := range s.inflight {
		if r.gen == gen {
			failed = append(failed, r.id)
			delete(s.inflight, k)
		}
	}
	shuttingDown := s.ctx.Err() != nil
	if !shuttingDown {
		s.startReconnectLocked(s.cfg.reconnectWindow)
	}
	s.mu.Unlock()

	if shuttingDown {
		return
	}
	s.logf("daemon connection lost (%v); reconnecting, %d in-flight request(s) failed",
		cause, len(failed))
	for _, id := range failed {
		s.writeError(id, restartedMessage, nil)
	}
}

func (s *shim) writeOut(line []byte) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_, _ = s.out.Write(line)
}

// writeError emits a JSON-RPC error response for id on stdout.
func (s *shim) writeError(id json.RawMessage, message string, data any) {
	s.writeOut(errorFrame(id, message, data))
}

func errorFrame(id json.RawMessage, message string, data any) []byte {
	type rpcError struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    any    `json:"data,omitempty"`
	}
	if !hasID(id) {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcError        `json:"error"`
	}{"2.0", id, rpcError{errCodeDaemon, message, data}})
	return append(b, '\n')
}

// unreachableMessage is the user-facing text for "the daemon never
// answered". `protonmcp daemon start` kickstarts an installed
// LaunchAgent; a never-installed daemon needs `daemon install`, and
// an engaged menu-bar kill switch needs Switch On (start alone would
// fail against a disabled job).
func unreachableMessage(path string, window time.Duration, err error) string {
	return fmt.Sprintf("protonmcpd not reachable at %s (waited %s: %v) — "+
		"if the menu bar shows it switched off, use Switch On; otherwise run "+
		"`protonmcp daemon start` (or `protonmcp daemon install` if it was never installed), "+
		"then retry", path, window.Round(time.Second), err)
}

// defaultSocketPath mirrors protonmcpd's resolveSocketPath. Kept in
// sync deliberately rather than imported so the shim binary stays
// tiny (no cross-package deps beyond the standard library).
func defaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "protonmcp.sock"), nil
}
