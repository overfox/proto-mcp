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
	"strings"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/remote"
)

// runRemote is `protonmcp remote …`: Remote mode control, talking to
// the daemon's 0600 control socket (internal/remote). Actions that need
// you at the Mac (setup, on, add-device) show Touch ID from the daemon.
func runRemote(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: protonmcp remote {status|setup|on|off|add-device|remove-device <name>|test-notify} [--json]`)
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
		return remoteSetup(ctx, asJSON)
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
			fmt.Println("The device must be signed in to Tailscale. The menu bar's \"Add Remote Device…\" shows it as a QR code.")
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
	if st.Origin != "" {
		fmt.Println("Address:    ", st.Origin)
	} else {
		fmt.Println("Address:     not set up — run `protonmcp remote setup`")
	}
	if len(st.Devices) == 0 {
		fmt.Println("Devices:     none — run `protonmcp remote add-device`")
	} else {
		fmt.Println("Devices:    ", strings.Join(st.Devices, ", "))
	}
	fmt.Printf("Alerts:      ntfy topic %s on %s\n", st.NtfyTopic, st.NtfyServer)
}

// remoteSetup publishes the daemon's loopback web app on the tailnet
// with `tailscale serve` and records the HTTPS origin.
func remoteSetup(ctx context.Context, asJSON bool) error {
	ts, err := tailscaleCLI()
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	raw, err := exec.CommandContext(sctx, ts, "status", "--json").Output()
	cancel()
	if err != nil {
		return fmt.Errorf("tailscale status failed (is Tailscale running and signed in?): %w", err)
	}
	var tsStatus struct {
		BackendState string
		Self         struct{ DNSName string }
	}
	if err := json.Unmarshal(raw, &tsStatus); err != nil {
		return fmt.Errorf("unexpected output from %s status: %q", ts, firstLine(string(raw)))
	}
	if tsStatus.BackendState != "Running" {
		return fmt.Errorf("Tailscale is %q — open the Tailscale app and sign in first", tsStatus.BackendState)
	}
	host := strings.TrimSuffix(tsStatus.Self.DNSName, ".")
	if host == "" {
		return errors.New("Tailscale reports no DNS name for this Mac — enable MagicDNS in the Tailscale admin console")
	}

	var st remote.Status
	if err := remoteCall(ctx, http.MethodGet, "/status", nil, &st); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Publishing https://%s on your tailnet (tailscale serve → %s)…\n", host, st.Listen)
	serve := exec.CommandContext(ctx, ts, "serve", "--bg", "--https=443", "http://"+st.Listen)
	serve.Stdout, serve.Stderr = os.Stderr, os.Stderr
	if err := serve.Run(); err != nil {
		return fmt.Errorf("tailscale serve failed: %w — if it printed a link, open it to enable HTTPS for your tailnet, then rerun `protonmcp remote setup`", err)
	}

	fmt.Fprintln(os.Stderr, "Confirm with Touch ID on the Mac…")
	if err := remoteCall(ctx, http.MethodPost, "/setup", map[string]string{"origin": "https://" + host}, &st); err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(st)
	}
	printRemoteStatus(st)
	fmt.Println("\nNext: `protonmcp remote add-device` (or the menu bar's \"Add Remote Device…\").")
	return nil
}

// tailscaleCLI finds a working tailscale CLI. The app's own binary only
// acts as a CLI when started from a terminal (from the menu bar's
// launchd environment it prints "The Tailscale GUI failed to start"),
// so the wrapper the app installs in /usr/local/bin comes first — the
// menu bar's PATH doesn't include it.
func tailscaleCLI() (string, error) {
	for _, p := range []string{"/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	const app = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
	if _, err := os.Stat(app); err == nil {
		return app, nil
	}
	return "", errors.New("Tailscale isn't installed — install it from https://tailscale.com/download or `brew install --cask tailscale-app`")
}

// remoteCall does one JSON request on the daemon's control socket.
// Touch ID-gated calls can take up to a minute.
func remoteCall(ctx context.Context, method, path string, in, out any) error {
	sock, err := remote.ControlSocketPath()
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 90 * time.Second,
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
