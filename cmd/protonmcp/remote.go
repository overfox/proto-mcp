package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/remote"
)

// runRemote is `protonmcp remote …`: Remote mode control, talking to
// the daemon's 0600 control socket (internal/remote). Actions that need
// you at the Mac (setup, on, add-device) show Touch ID from the daemon.
func runRemote(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: protonmcp remote {status|setup [--port N]|on|off|add-device|remove-device <name>|test-notify} [--json]`)
	}
	asJSON := false
	var rest []string
	for _, a := range args[1:] {
		if a == "--json" {
			asJSON = true
			continue
		}
		rest = append(rest, a)
	}
	out := func(v any, human func()) error {
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(v)
		}
		human()
		return nil
	}

	switch args[0] {
	case "status":
		var st remote.Status
		if err := remoteCall(ctx, http.MethodGet, "/status", nil, &st); err != nil {
			return err
		}
		return out(st, func() { printRemoteStatus(st) })
	case "on", "off":
		var st remote.Status
		if err := remoteCall(ctx, http.MethodPost, "/"+args[0], nil, &st); err != nil {
			return err
		}
		return out(st, func() { printRemoteStatus(st) })
	case "setup":
		return remoteSetup(ctx, asJSON, rest)
	case "add-device":
		var res struct {
			URL string `json:"url"`
		}
		if err := remoteCall(ctx, http.MethodPost, "/enroll", nil, &res); err != nil {
			return err
		}
		return out(res, func() {
			fmt.Println("Open this link on the phone or tablet within 10 minutes (it works once):")
			fmt.Println("  " + res.URL)
			fmt.Println("The device must be signed in to Tailscale as you. After it creates its passkey, confirm the")
			fmt.Println("device (named with its Tailscale node) with Touch ID here. The menu bar's \"Add Remote Device…\" shows a QR code.")
		})
	case "remove-device":
		if len(rest) != 1 {
			return errors.New("usage: protonmcp remote remove-device <name>")
		}
		var st remote.Status
		if err := remoteCall(ctx, http.MethodPost, "/remove", map[string]string{"name": rest[0]}, &st); err != nil {
			return err
		}
		return out(st, func() { printRemoteStatus(st) })
	case "test-notify":
		if err := remoteCall(ctx, http.MethodPost, "/test-notify", nil, nil); err != nil {
			return err
		}
		fmt.Println("test alert sent")
		return nil
	}
	return fmt.Errorf("unknown remote command %q", args[0])
}

func printRemoteStatus(st remote.Status) {
	state := "off"
	switch {
	case st.Active:
		state = "ON — approvals go to your devices; screen lock doesn't lock the connector"
	case st.Enabled:
		state = "on, but inactive (needs setup and an enrolled device)"
	}
	fmt.Println("Remote mode:", state)
	switch {
	case st.Origin == "":
		fmt.Println("Address:     not set up — run `protonmcp remote setup`")
	case st.Serving:
		fmt.Println("Address:    ", st.Origin, "(listening on", st.Listen+")")
	default:
		fmt.Println("Address:    ", st.Origin, "(not listening yet — is Tailscale running? see the daemon log)")
	}
	if len(st.Devices) == 0 {
		fmt.Println("Devices:     none — run `protonmcp remote add-device`")
	} else {
		for i, d := range st.Devices {
			label := "Devices:    "
			if i > 0 {
				label = "            "
			}
			if node := st.DeviceNodes[d]; node != "" {
				d += " — tailscale node " + node
			}
			fmt.Println(label, d)
		}
	}
	auth := ""
	if st.NtfyToken {
		auth = " (with access token)"
	}
	fmt.Printf("Alerts:      ntfy topic %s on %s%s\n", st.NtfyTopic, st.NtfyServer, auth)
	fmt.Println("             Keep the topic name secret: anyone who knows it can see when approvals are pending.")
}

// remoteSetup has the daemon serve the approval page on this Mac's
// Tailscale address over HTTPS (a `tailscale cert` certificate) and
// record the origin. The daemon derives the address from its own
// Tailscale status; this side only checks Tailscale and cleans up the
// `tailscale serve` config older versions created.
func remoteSetup(ctx context.Context, asJSON bool, args []string) error {
	body := map[string]any{}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--port" && i+1 < len(args):
			port, err := strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("bad --port %q", args[i+1])
			}
			body["port"] = port
			i++
		default:
			return errors.New("usage: protonmcp remote setup [--port N] [--json]")
		}
	}
	ts, err := remote.TailscaleCLI()
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	raw, err := exec.CommandContext(sctx, ts, "status", "--json").Output()
	cancel()
	if err != nil {
		return fmt.Errorf("tailscale status failed (is Tailscale running and signed in?): %w", err)
	}
	var tsStatus struct{ BackendState string }
	if err := json.Unmarshal(raw, &tsStatus); err != nil {
		return fmt.Errorf("unexpected output from %s status: %q", ts, firstLine(string(raw)))
	}
	if tsStatus.BackendState != "Running" {
		return fmt.Errorf("Tailscale is %q — open the Tailscale app and sign in first", tsStatus.BackendState)
	}
	removeOldServe(ctx, ts)

	fmt.Fprintln(os.Stderr, "Getting an HTTPS certificate from Tailscale, then confirm with Touch ID on the Mac…")
	var st remote.Status
	if err := remoteCall(ctx, http.MethodPost, "/setup", body, &st); err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(st)
	}
	printRemoteStatus(st)
	fmt.Println("\nNext: `protonmcp remote add-device` (or the menu bar's \"Add Remote Device…\").")
	return nil
}

// removeOldServe drops the `tailscale serve` HTTPS proxy older versions
// set up to the loopback listener (best effort; only when it points at
// our old port).
func removeOldServe(ctx context.Context, ts string) {
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(sctx, ts, "serve", "status", "--json").Output()
	if err != nil || !strings.Contains(string(raw), "127.0.0.1:47811") {
		return
	}
	if err := exec.CommandContext(sctx, ts, "serve", "--https=443", "off").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Note: couldn't remove the old `tailscale serve` config (%v); run `%s serve --https=443 off`.\n", err, ts)
		return
	}
	fmt.Fprintln(os.Stderr, "Removed the old `tailscale serve` config (no longer used).")
}

// remoteCall does one JSON request on the daemon's control socket.
// Touch ID-gated calls can take up to a minute; setup also waits for
// the first certificate from Tailscale.
func remoteCall(ctx context.Context, method, path string, in, out any) error {
	sock, err := remote.ControlSocketPath()
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 5 * time.Minute, // setup: certificate issuance + Touch ID
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://protonmcp"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the protonmcp daemon's remote control (%v) — is protonmcpd running?", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("daemon returned HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
