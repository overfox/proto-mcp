package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

func callConnect(t *testing.T, deps Deps) *mcp.ToolResult {
	t.Helper()
	tool := protonConnect(deps)
	if !tool.AllowWhenLocked {
		t.Fatal("proton_connect must be AllowWhenLocked, or it can never end a lock")
	}
	res, err := tool.Handler(mcp.Context{Std: context.Background()}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return res
}

func connectResultJSON(res *mcp.ToolResult) string {
	b, _ := json.Marshal(res)
	return string(b)
}

func TestProtonConnectAlreadyConnected(t *testing.T) {
	res := callConnect(t, Deps{Connect: func(context.Context) (bool, string, error) {
		return true, "me@proton.me", nil
	}})
	if res.IsError || !strings.Contains(connectResultJSON(res), "already_connected") {
		t.Errorf("got %s, want already_connected", connectResultJSON(res))
	}
}

func TestProtonConnectUnlocks(t *testing.T) {
	res := callConnect(t, Deps{Connect: func(context.Context) (bool, string, error) {
		return false, "me@proton.me", nil
	}})
	if res.IsError || !strings.Contains(connectResultJSON(res), `"status":"connected"`) {
		t.Errorf("got %s, want connected", connectResultJSON(res))
	}
}

func TestProtonConnectDeclined(t *testing.T) {
	res := callConnect(t, Deps{Connect: func(context.Context) (bool, string, error) {
		return false, "", errors.New("user canceled startup approval")
	}})
	if !res.IsError || !strings.Contains(connectResultJSON(res), "still locked") {
		t.Errorf("got %s, want an error saying Proton is still locked", connectResultJSON(res))
	}
}

func TestProtonConnectNoRuntime(t *testing.T) {
	res := callConnect(t, Deps{})
	if !res.IsError {
		t.Errorf("got %s, want error when no runtime is wired", connectResultJSON(res))
	}
}
