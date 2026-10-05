package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSocketPathHasExpectedShape(t *testing.T) {
	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "Application Support/protonmcp/protonmcp.sock") {
		t.Errorf("unexpected default socket path: %s", p)
	}
}

// TestErrorFrame checks the JSON-RPC error frames the shim
// synthesizes. They must be valid NDJSON (one line, ends with \n),
// echo the request id, and carry structured data when given.
func TestErrorFrame(t *testing.T) {
	b := errorFrame(json.RawMessage(`7`),
		unreachableMessage("/tmp/test.sock", 0, net.ErrClosed),
		map[string]any{"dial_error": net.ErrClosed.Error()})
	s := string(b)
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		t.Errorf("error frame must be exactly one NDJSON line: %q", s)
	}
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int               `json:"code"`
			Message string            `json:"message"`
			Data    map[string]string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, s)
	}
	if resp.JSONRPC != "2.0" || string(resp.ID) != "7" || resp.Error.Code != errCodeDaemon {
		t.Errorf("bad envelope: %s", s)
	}
	if !strings.Contains(resp.Error.Message, "/tmp/test.sock") ||
		!strings.Contains(resp.Error.Message, "protonmcp daemon start") {
		t.Errorf("message lacks path / remedy: %s", resp.Error.Message)
	}
	if resp.Error.Data["dial_error"] == "" {
		t.Errorf("missing structured dial_error: %s", s)
	}
	if got := string(errorFrame(nil, "x", nil)); !strings.Contains(got, `"id":null`) {
		t.Errorf("missing id should encode as null: %s", got)
	}
}

// TestShortSocketPathConstraint sanity-checks that the default
// socket path fits within macOS's 104-char sockaddr_un limit. If
// this ever fails for some path-config reason, the shim would also
// fail to connect and we'd want to know first.
func TestShortSocketPathConstraint(t *testing.T) {
	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 104 {
		t.Errorf("default socket path %d chars > 104 (sockaddr_un limit): %s", len(p), p)
	}
	// Sanity: the path is rooted under the user's home dir.
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(p, filepath.Clean(home)) {
		t.Errorf("default socket path not under home: %s (home=%s)", p, home)
	}
}
