package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDaemon is an in-process stand-in for protonmcpd: a Unix-socket
// NDJSON server that answers initialize, tracks per-connection
// handshake state like internal/mcp does, never answers "hang", and
// echoes every other request.
type fakeDaemon struct {
	l     net.Listener
	mu    sync.Mutex
	conns []net.Conn
	recv  chan rpcMsg
}

type rpcMsg struct {
	conn   int
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

func startFakeDaemon(t *testing.T, path string) *fakeDaemon {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("fake daemon listen: %v", err)
	}
	d := &fakeDaemon{l: l, recv: make(chan rpcMsg, 64)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns = append(d.conns, c)
			idx := len(d.conns)
			d.mu.Unlock()
			go d.serve(c, idx)
		}
	}()
	return d
}

func (d *fakeDaemon) serve(c net.Conn, idx int) {
	sc := bufio.NewScanner(c)
	initialized := false
	for sc.Scan() {
		var m rpcMsg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		m.conn = idx
		d.recv <- m
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18"}
		case "notifications/initialized":
			initialized = true
			continue
		case "hang":
			continue
		default:
			result = map[string]any{"echo": m.Method, "initialized": initialized}
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		_, _ = c.Write(append(b, '\n'))
	}
}

// stop simulates the daemon exiting: listener gone (socket unlinked)
// and every connection closed.
func (d *fakeDaemon) stop() {
	_ = d.l.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		_ = c.Close()
	}
}

func (d *fakeDaemon) next(t *testing.T) rpcMsg {
	t.Helper()
	select {
	case m := <-d.recv:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the fake daemon to receive a frame")
		return rpcMsg{}
	}
}

// shortSockPath returns a socket path under a short temp dir —
// t.TempDir() embeds the test name and can blow past macOS's
// 104-byte sockaddr_un limit.
func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pmcpshim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

var testConfig = config{
	initialWindow:    5 * time.Second,
	reconnectWindow:  5 * time.Second,
	retryWindow:      2 * time.Second,
	handshakeTimeout: 2 * time.Second,
	dialTimeout:      500 * time.Millisecond,
	backoffMin:       10 * time.Millisecond,
	backoffMax:       50 * time.Millisecond,
}

// testClient plays the Claude side: writes frames to the shim's
// stdin and reads (and validates) every NDJSON frame on its stdout.
type testClient struct {
	t     *testing.T
	stdin *io.PipeWriter
	lines chan map[string]any
}

func startShim(t *testing.T, sock string, cfg config) *testClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	s := newShim(sock, outW, cfg)
	s.logf = func(format string, args ...any) { t.Logf("shim: "+format, args...) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.run(ctx, inR); err != nil {
			t.Errorf("shim run: %v", err)
		}
	}()
	c := &testClient{t: t, stdin: inW, lines: make(chan map[string]any, 64)}
	go func() {
		br := bufio.NewReader(outR)
		for {
			line, err := br.ReadBytes('\n')
			if err != nil {
				return
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Errorf("shim wrote invalid NDJSON to stdout: %q", line)
				continue
			}
			c.lines <- m
		}
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		cancel()
		<-done
		_ = outW.Close()
	})
	return c
}

func (c *testClient) send(frame string) {
	c.t.Helper()
	if _, err := io.WriteString(c.stdin, frame+"\n"); err != nil {
		c.t.Fatalf("write stdin: %v", err)
	}
}

func (c *testClient) recv() map[string]any {
	c.t.Helper()
	select {
	case m := <-c.lines:
		return m
	case <-time.After(10 * time.Second):
		c.t.Fatal("timed out waiting for a frame on the shim's stdout")
		return nil
	}
}

func idOf(m map[string]any) string {
	b, _ := json.Marshal(m["id"])
	return string(b)
}

func errMessage(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["message"].(string)
	return s
}

func TestShimSurvivesDaemonRestart(t *testing.T) {
	sock := shortSockPath(t)
	client := startShim(t, sock, testConfig)

	// Daemon comes up a little after the shim (startup Touch ID
	// gate): the client's first frames must wait, not fail.
	time.Sleep(200 * time.Millisecond)
	d1 := startFakeDaemon(t, sock)
	defer d1.stop()

	client.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if m := client.recv(); idOf(m) != "0" || m["result"] == nil {
		t.Fatalf("initialize response = %v", m)
	}
	client.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	client.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	m := client.recv()
	if idOf(m) != "1" || m["result"].(map[string]any)["initialized"] != true {
		t.Fatalf("tools/list response = %v", m)
	}

	// A request in flight when the daemon dies.
	client.send(`{"jsonrpc":"2.0","id":2,"method":"hang"}`)
	for d1.next(t).Method != "hang" {
	}
	d1.stop()

	m = client.recv()
	if idOf(m) != "2" || !strings.Contains(errMessage(m), "daemon restarted") {
		t.Fatalf("in-flight request should fail with a restart error, got %v", m)
	}

	// A request sent while disconnected waits for the new daemon.
	client.send(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	time.Sleep(200 * time.Millisecond)
	d2 := startFakeDaemon(t, sock)
	defer d2.stop()

	// The replayed initialize's response must be swallowed: the very
	// next frame the client sees is the answer to id 3, and the new
	// connection already counts as initialized.
	m = client.recv()
	if idOf(m) != "3" || m["result"] == nil {
		t.Fatalf("post-restart response = %v", m)
	}
	if m["result"].(map[string]any)["initialized"] != true {
		t.Fatalf("handshake not replayed before client traffic: %v", m)
	}

	first, second, third := d2.next(t), d2.next(t), d2.next(t)
	var replayID string
	_ = json.Unmarshal(first.ID, &replayID)
	if first.Method != "initialize" || !strings.HasPrefix(replayID, replayIDPrefix) {
		t.Errorf("first frame on new connection = %s %s, want replayed initialize", first.Method, first.ID)
	}
	if second.Method != "notifications/initialized" {
		t.Errorf("second frame on new connection = %s, want notifications/initialized", second.Method)
	}
	if third.Method != "tools/list" || string(third.ID) != "3" {
		t.Errorf("third frame on new connection = %s %s, want tools/list 3", third.Method, third.ID)
	}

	// Steady state after the restart.
	client.send(`{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	if m := client.recv(); idOf(m) != "4" || m["result"] == nil {
		t.Fatalf("ping after restart = %v", m)
	}
	select {
	case extra := <-client.lines:
		t.Errorf("unexpected extra frame on stdout: %v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestShimFailsClearlyThenRecovers(t *testing.T) {
	sock := shortSockPath(t)
	cfg := testConfig
	cfg.initialWindow = 300 * time.Millisecond
	cfg.retryWindow = 2 * time.Second
	client := startShim(t, sock, cfg)

	// No daemon at all: the request fails with an actionable error
	// once the bounded wait runs out.
	client.send(`{"jsonrpc":"2.0","id":"a","method":"ping"}`)
	m := client.recv()
	if idOf(m) != `"a"` || !strings.Contains(errMessage(m), "protonmcp daemon start") {
		t.Fatalf("expected daemon-unreachable error for id a, got %v", m)
	}

	// The shim is still alive; once the daemon shows up, the next
	// request triggers a fresh connect and succeeds.
	d := startFakeDaemon(t, sock)
	defer d.stop()
	client.send(`{"jsonrpc":"2.0","id":"b","method":"ping"}`)
	if m := client.recv(); idOf(m) != `"b"` || m["result"] == nil {
		t.Fatalf("ping after daemon start = %v", m)
	}
}
