// Package remote implements Remote mode: while it is on, the daemon
// keeps working with the Mac's screen locked, and approvals that would
// show a Touch ID prompt on the Mac go to an enrolled phone or tablet
// instead, where they are approved with a passkey (fingerprint / face).
//
// Reachability: the daemon serves a small web app on 127.0.0.1, which
// `tailscale serve` publishes over HTTPS on the user's private tailnet
// only (https://<mac>.<tailnet>.ts.net). Nothing listens on a public
// interface.
//
// Trust model:
//
//   - Enrolling a device needs Touch ID at the Mac (one-time token).
//   - Approving, and turning Remote mode ON from a device, needs a
//     passkey assertion with user verification, bound server-side to
//     the specific approval being shown.
//   - Turning Remote mode OFF, declining and locking need no passkey:
//     they only ever reduce access.
//   - Notifications (ntfy) carry no mail content — only "approval
//     needed" and a link that resolves on the tailnet alone.
//   - Local processes (including Claude) can reach the loopback port,
//     but can't produce a passkey assertion, so they can't approve or
//     enable anything.
package remote

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// DefaultListenAddr is the loopback address `tailscale serve` proxies to.
const DefaultListenAddr = "127.0.0.1:47811"

// DefaultNtfyServer is the public ntfy instance used for alerts.
const DefaultNtfyServer = "https://ntfy.sh"

// Device is one enrolled phone / tablet passkey.
type Device struct {
	Name     string              `json:"name"`
	AddedAt  time.Time           `json:"added_at"`
	LastUsed time.Time           `json:"last_used,omitempty"`
	Cred     webauthn.Credential `json:"credential"`
}

// Config is remote.json (0600, written only by the daemon).
type Config struct {
	Enabled    bool      `json:"enabled"`
	EnabledAt  time.Time `json:"enabled_at,omitempty"`
	EnabledBy  string    `json:"enabled_by,omitempty"`
	Origin     string    `json:"origin,omitempty"` // https://mac.tailnet.ts.net
	Listen     string    `json:"listen,omitempty"`
	NtfyServer string    `json:"ntfy_server,omitempty"`
	NtfyTopic  string    `json:"ntfy_topic,omitempty"`
	// OwnerLogin is the Tailscale login that enrolled the first
	// device; later requests from any other tailnet identity are refused.
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
	if c.Listen == "" {
		c.Listen = DefaultListenAddr
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
