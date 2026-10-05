package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

func TestCalendarTools_UnavailableScope(t *testing.T) {
	st := calStore(t)
	mustCal(t, st, "cal-1", "Work")
	sess := &protonclient.Session{}
	sess.MarkCalendarUnavailable(time.Now())
	deps := Deps{Store: st, Session: sess}
	ctx := mcp.Context{Std: context.Background()}

	for name, call := range map[string]func() (*mcp.ToolResult, error){
		"calendar_list":   func() (*mcp.ToolResult, error) { return calendarList(deps).Handler(ctx, nil) },
		"calendar_events": func() (*mcp.ToolResult, error) { return calendarEvents(deps).Handler(ctx, json.RawMessage(`{}`)) },
		"calendar_read_event": func() (*mcp.ToolResult, error) {
			return calendarReadEvent(deps).Handler(ctx, json.RawMessage(`{"event_id":"x","calendar_id":"cal-1"}`))
		},
	} {
		res, err := call()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.IsError || len(res.Content) == 0 ||
			!strings.Contains(res.Content[0].Text, "Proton Calendar isn't accessible with this login's token scope (Proton code 9100)") {
			t.Errorf("%s: want scope error, got %+v", name, res)
		}
	}
}
