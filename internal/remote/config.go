// Package remote implements Remote mode: while it is on, the daemon
// keeps working with the Mac's screen locked, and approvals that would
// show a Touch ID prompt on the Mac go to an enrolled phone or tablet
// instead, where they are approved with a passkey (fingerprint / face).
//
// Reachability: the daemon serves a small web app over HTTPS directly
// on the Mac's Tailscale IPv4 address (https://<mac>.<tailnet>.ts.net:
// 8443 by default) with a certificate from `tailscale cert`. Nothing
// listens on loopback or on a public interface.
//
// Trust model:
//
//   - Every request's peer is resolved from its real source address
//     with `tailscale whois`; request headers are never trusted.
//     Unknown peers, tagged nodes, other users' nodes and the Mac's own
//     node are refused — so local processes (including Claude) can't
//     use the web app at all, even by connecting to the Tailscale IP.
//   - Enrolling a device needs Touch ID at the Mac twice: once for the
//     one-time link, and again — naming the device, its Tailscale node
//     and login — before the passkey is saved.
//   - Each passkey is bound to the Tailscale node it was enrolled from;
//     an assertion is only accepted from that node. A credential
//     written into remote.json by another process is useless without
//     also controlling another node of the owner's tailnet.
//   - Approving, and turning Remote mode ON from a device, needs a
//     passkey assertion with user verification, bound server-side to
//     the specific approval being shown.
//   - Turning Remote mode OFF, declining and locking need no passkey
//     (only an enrolled node): they only ever reduce access.
//   - Notifications (ntfy) carry no mail content — only "approval
//     needed" and a link that resolves on the tailnet alone.
package remote

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// DefaultPort is the HTTPS port on the Mac's Tailscale address.
const DefaultPort = 8443

// DefaultNtfyServer is the public ntfy instance used for alerts.
const DefaultNtfyServer = "https://ntfy.sh"

// Device is one enrolled phone / tablet passkey, bound to the Tailscale
// node it was enrolled from.
type Device struct {
	Name     string              `json:"name"`
	AddedAt  time.Time           `json:"added_at"`
	LastUsed time.Time           `json:"last_used,omitempty"`
	NodeID   string              `json:"node_id"`
	NodeName string              `json:"node_name"`
	Login    string              `json:"login"`
	Cred     webauthn.Credential `json:"credential"`
}

// Config is remote.json (0600, written only by the daemon).
type Config struct {
	Enabled    bool      `json:"enabled"`
	EnabledAt  time.Time `json:"enabled_at,omitempty"`
	EnabledBy  string    `json:"enabled_by,omitempty"`
	Origin     string    `json:"origin,omitempty"` // https://mac.tailnet.ts.net:8443
	Port       int       `json:"port,omitempty"`
	NtfyServer string    `json:"ntfy_server,omitempty"`
	NtfyTopic  string    `json:"ntfy_topic,omitempty"`
	// NtfyToken is an optional access token for an authenticated or
	// self-hosted ntfy server (sent as Authorization: Bearer).
	NtfyToken string `json:"ntfy_token,omitempty"`
	// OwnerLogin is the Tailscale login (from whois) that enrolled the
	// first device; requests from any other tailnet identity are
	// refused. Until then only the Mac's own login is accepted.
	OwnerLogin string   `json:"owner_login,omitempty"`
	UserID     []byte   `json:"user_id"`
	Devices    []Device `json:"devices,omitempty"`
}

// DefaultPath is ~/Library/Application Support/protonmcp/remote.json.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "remote.json"), nil
}

// ControlSocketPath is the 0600 unix socket the CLI / menu bar use.
func ControlSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "protonmcp", "remote-control.sock"), nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return c, err
	default:
		if err := json.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if len(c.UserID) == 0 {
		c.UserID = randomBytes(32)
	}
	if c.Port <= 0 || c.Port > 65535 {
		c.Port = DefaultPort
	}
	if c.NtfyServer == "" {
		c.NtfyServer = DefaultNtfyServer
	}
	if c.NtfyTopic == "" {
		c.NtfyTopic = "pmcp-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(15)))
	}
	return c, nil
}

func saveConfig(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// parseOrigin validates an origin of the form https://host[:port] (no
// path, query, fragment or credentials; DNS-name characters only).
func parseOrigin(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(origin, "?#") {
		return nil, errors.New("remote: origin must be https://<host>[:port]")
	}
	for _, r := range u.Hostname() {
		if !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return nil, errors.New("remote: origin host has unexpected characters")
		}
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n <= 0 || n > 65535 {
			return nil, errors.New("remote: bad origin port")
		}
	}
	return u, nil
}

// originFor is the origin the web app is served at.
func originFor(host string, port int) string {
	return "https://" + host + ":" + strconv.Itoa(port)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}

func randomID() string {
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes(20)))
}
