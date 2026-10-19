package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SelfNode is this Mac's own Tailscale node.
type SelfNode struct {
	NodeID  string // stable node ID ("n…CNTRL")
	DNSName string // mac.tailnet.ts.net (no trailing dot)
	IPv4    string // 100.x.y.z
	Login   string // the Mac's Tailscale login
}

// Peer is the Tailscale identity behind a connection's source address.
type Peer struct {
	NodeID   string   `json:"node_id"`
	NodeName string   `json:"node_name"` // short machine name
	Login    string   `json:"login"`
	Tags     []string `json:"tags,omitempty"`
}

// Tailnet is what Remote mode needs from Tailscale. The production
// implementation shells out to the tailscale CLI; tests inject a fake.
type Tailnet interface {
	// Self describes this Mac's node. Errors when Tailscale isn't
	// running and signed in.
	Self(ctx context.Context) (SelfNode, error)
	// WhoIs resolves a connection's remote address ("ip:port") to
	// the node and user that own it, as Tailscale sees it.
	WhoIs(ctx context.Context, addr string) (Peer, error)
	// Cert returns a TLS certificate for this Mac's ts.net name
	// (issued and cached/renewed by tailscaled).
	Cert(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error)
}

// TailscaleCLI finds a working tailscale CLI. The app's own binary only
// acts as a CLI when started from a terminal (from launchd it prints
// "The Tailscale GUI failed to start"), so the wrapper the app installs
// in /usr/local/bin comes first — launchd's PATH doesn't include it.
func TailscaleCLI() (string, error) {
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

// HTTPSHelp explains the one-time tailnet setting `tailscale cert` needs.
const HTTPSHelp = "HTTPS certificates must be enabled for your tailnet: open https://login.tailscale.com/admin/dns, " +
	"turn on MagicDNS and \"HTTPS Certificates\", then rerun `protonmcp remote setup`"

// cliTailnet is Tailnet over the tailscale CLI.
type cliTailnet struct{}

func (cliTailnet) run(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	bin, err := TailscaleCLI()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return nil, fmt.Errorf("tailscale %s: %w: %s", args[0], err, msg)
	}
	return stdout.Bytes(), nil
}

func (c cliTailnet) Self(ctx context.Context) (SelfNode, error) {
	raw, err := c.run(ctx, 15*time.Second, "status", "--json")
	if err != nil {
		return SelfNode{}, err
	}
	return parseStatus(raw)
}

func parseStatus(raw []byte) (SelfNode, error) {
	var st struct {
		BackendState string
		Self         struct {
			ID           string
			DNSName      string
			TailscaleIPs []string
			UserID       int64
		}
		User map[string]struct{ LoginName string }
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return SelfNode{}, fmt.Errorf("tailscale status: unexpected output: %w", err)
	}
	if st.BackendState != "Running" {
		return SelfNode{}, fmt.Errorf("Tailscale is %q — open the Tailscale app and sign in", st.BackendState)
	}
	n := SelfNode{NodeID: st.Self.ID, DNSName: strings.TrimSuffix(st.Self.DNSName, ".")}
	for _, ip := range st.Self.TailscaleIPs {
		if a := net.ParseIP(ip); a != nil && a.To4() != nil {
			n.IPv4 = ip
			break
		}
	}
	if u, ok := st.User[fmt.Sprint(st.Self.UserID)]; ok {
		n.Login = u.LoginName
	}
	switch {
	case n.NodeID == "":
		return n, errors.New("tailscale status: no node ID for this Mac")
	case n.DNSName == "":
		return n, errors.New("Tailscale reports no DNS name for this Mac — enable MagicDNS in the Tailscale admin console")
	case n.IPv4 == "":
		return n, errors.New("Tailscale reports no IPv4 address for this Mac")
	}
	return n, nil
}

func (c cliTailnet) WhoIs(ctx context.Context, addr string) (Peer, error) {
	raw, err := c.run(ctx, 5*time.Second, "whois", "--json", addr)
	if err != nil {
		return Peer{}, err
	}
	return parseWhoIs(raw)
}

func parseWhoIs(raw []byte) (Peer, error) {
	var w struct {
		Node *struct {
			StableID     string
			Name         string
			ComputedName string
			Tags         []string
		}
		UserProfile *struct{ LoginName string }
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return Peer{}, fmt.Errorf("tailscale whois: unexpected output: %w", err)
	}
	if w.Node == nil || w.Node.StableID == "" || w.UserProfile == nil {
		return Peer{}, errors.New("tailscale whois: unknown peer")
	}
	name := w.Node.ComputedName
	if name == "" {
		name, _, _ = strings.Cut(w.Node.Name, ".")
	}
	return Peer{NodeID: w.Node.StableID, NodeName: name, Login: w.UserProfile.LoginName, Tags: w.Node.Tags}, nil
}

// Cert asks tailscaled for the certificate on stdout, so a sandboxed
// Tailscale build doesn't need write access to our directory.
func (c cliTailnet) Cert(ctx context.Context, domain string) ([]byte, []byte, error) {
	raw, err := c.run(ctx, 2*time.Minute, "cert", "--cert-file", "-", "--key-file", "-", domain)
	if err != nil {
		return nil, nil, err
	}
	var certPEM, keyPEM []byte
	for rest := raw; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		} else if strings.HasSuffix(b.Type, "PRIVATE KEY") {
			keyPEM = pem.EncodeToMemory(b)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, nil, errors.New("tailscale cert: no certificate/key in the output")
	}
	return certPEM, keyPEM, nil
}

// TLSDir is where the tailnet certificate is kept (0700 dir, 0600 files).
func tlsDir(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "remote-tls")
}

// fetchCert gets the certificate for domain, stores it 0600 under dir
// and returns it parsed.
func fetchCert(ctx context.Context, tn Tailnet, dir, domain string) (*tls.Certificate, error) {
	certPEM, keyPEM, err := tn.Cert(ctx, domain)
	if err != nil {
		return nil, err
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tailscale cert: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM} {
		p := filepath.Join(dir, name)
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, p); err != nil {
			return nil, err
		}
	}
	return &kp, nil
}
