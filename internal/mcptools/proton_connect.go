package mcptools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// connectTimeout bounds the whole unlock, Touch ID prompt included.
// The helper itself gives up after 60s; the extra margin covers the
// session resume against Proton that follows an approval.
const connectTimeout = 120 * time.Second

// protonConnect is the one tool that runs while the daemon is locked
// (AllowWhenLocked). It exists so "connect to Proton" in chat can end
// a lock without the user dropping to a terminal: the call fires the
// daemon's Touch ID prompt on the Mac and returns once the user
// approves. It is not a bypass. The Touch ID approval IS the gate, and
// a declined or timed-out prompt leaves the daemon locked.
func protonConnect(deps Deps) mcp.Tool {
	type result struct {
		Status  string `json:"status"` // connected | already_connected
		Email   string `json:"email,omitempty"`
		Message string `json:"message"`
	}
	return mcp.Tool{
		Name: "proton_connect",
		Description: "Connect / unlock Proton Mail. Call this when the user asks to connect to Proton, " +
			"or when another Proton tool fails with \"Proton is locked\". It shows a Touch ID prompt " +
			"on the user's Mac and waits up to ~2 minutes for them to approve. Tell the user to " +
			"approve the Touch ID prompt before or while calling. If already connected, returns " +
			"immediately without prompting.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {},
			"additionalProperties": false
		}`),
		OutputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"status":  {"type": "string", "enum": ["connected", "already_connected"]},
				"email":   {"type": "string"},
				"message": {"type": "string"}
			},
			"required": ["status", "message"]
		}`),
		AllowWhenLocked: true,
		Handler: func(ctx mcp.Context, _ json.RawMessage) (*mcp.ToolResult, error) {
			if deps.Connect == nil {
				return mcp.ErrorResult("proton_connect: unlock is not available in this server mode; " +
					"run `protonmcp unlock` in a terminal"), nil
			}
			cctx, cancel := context.WithTimeout(ctx.Std, connectTimeout)
			defer cancel()
			already, email, err := deps.Connect(cctx)
			if err != nil {
				return mcp.ErrorResult("proton_connect: Touch ID was not approved, so Proton is still "+
					"locked (%v). Ask the user to approve the prompt and call proton_connect again.", err), nil
			}
			if already {
				return mcp.StructuredResult(result{Status: "already_connected", Email: email,
					Message: "Proton is already connected; no Touch ID needed."})
			}
			return mcp.StructuredResult(result{Status: "connected", Email: email,
				Message: "Touch ID approved. Proton is connected."})
		},
	}
}
