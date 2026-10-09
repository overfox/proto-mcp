package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
)

// ApprovalTimeout is how long a remote approval waits for the phone.
// Longer than the Mac prompt's 30s: the phone has to be picked up and
// unlocked first.
const ApprovalTimeout = 120 * time.Second

const (
	enrollTokenTTL = 10 * time.Minute
	authSessionTTL = 3 * time.Minute
)

// Hooks connect the service to the daemon runtime.
type Hooks struct {
	// ConnectorState reports the daemon state for the phone page.
	ConnectorState func() (state, reason, email string)
	// Lock locks the connector (manual lock; never vetoed).
	Lock func(reason string)
	// MacApprove runs the Mac's own Touch ID prompt, never routed to
	// the phone. Used to gate enrolment and enabling from the Mac.
	MacApprove func(ctx context.Context, title, body string) error
	// OnChange is called after Remote mode is switched on or off.
	OnChange func()
}

// Pending is an approval waiting on a device.
type Pending struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Body    string    `json:"body"`
	Expires time.Time `json:"expires"`

	digest [32]byte
	done   chan bool
}

type authSession struct {
	data       webauthn.SessionData
	purpose    string // "approve" | "remote_on"
	approvalID string
	digest     [32]byte
	created    time.Time
}

type enrollToken struct {
	expires time.Time
	session *webauthn.SessionData
	name    string
}

// Service is Remote mode. Safe for concurrent use; a nil *Service is
// inactive.
type Service struct {
	path   string
	logger *slog.Logger
	hooks  Hooks

	mu       sync.Mutex
	cfg      Config
	wa       *webauthn.WebAuthn
	pending  map[string]*Pending
	sessions map[string]*authSession
	enroll   map[string]*enrollToken
	awake    *exec.Cmd

	httpClient *http.Client
	listeners  []func()
}

// Load reads remote.json (creating defaults in memory when absent).
func Load(path string, hooks Hooks, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, err
	}
	s := &Service{
		path:       path,
		logger:     logger,
		hooks:      hooks,
		cfg:        cfg,
		pending:    map[string]*Pending{},
		sessions:   map[string]*authSession{},
		enroll:     map[string]*enrollToken{},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	if cfg.Origin != "" {
		if err := s.initWebAuthn(cfg.Origin); err != nil {
			return nil, err
		}
	}
	if err := saveConfig(path, cfg); err != nil {
		return nil, err
	}
	if s.activeLocked() {
		s.startAwake()
	}
	return s, nil
}

func (s *Service) initWebAuthn(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("remote: origin must be https://<host>, got %q", origin)
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Proton MCP",
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return fmt.Errorf("remote: webauthn: %w", err)
	}
	s.wa = wa
	return nil
}

// Active reports whether approvals go to devices and auto-locks are
// suppressed: Remote mode on, configured, and at least one device.
func (s *Service) Active() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked()
}

func (s *Service) activeLocked() bool {
	return s.cfg.Enabled && s.wa != nil && len(s.cfg.Devices) > 0
}

// Status is the menu bar / CLI / state-file view.
type Status struct {
	Enabled    bool     `json:"enabled"`
	Active     bool     `json:"active"`
	Configured bool     `json:"configured"`
	Origin     string   `json:"origin,omitempty"`
	Devices    []string `json:"devices"`
	NtfyServer string   `json:"ntfy_server"`
	NtfyTopic  string   `json:"ntfy_topic"`
	Listen     string   `json:"listen"`
	Pending    int      `json:"pending"`
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled: s.cfg.Enabled, Active: s.activeLocked(), Configured: s.wa != nil,
		Origin: s.cfg.Origin, NtfyServer: s.cfg.NtfyServer, NtfyTopic: s.cfg.NtfyTopic,
		Listen: s.cfg.Listen, Pending: len(s.pending), Devices: []string{},
	}
	for _, d := range s.cfg.Devices {
		st.Devices = append(st.Devices, d.Name)
	}
	return st
}

// SetEnabled switches Remote mode. by is recorded ("mac", "phone:<name>").
func (s *Service) SetEnabled(on bool, by string) error {
	s.mu.Lock()
	if on && s.wa == nil {
		s.mu.Unlock()
		return errors.New("remote mode is not set up yet — run `protonmcp remote setup`")
	}
	if on && len(s.cfg.Devices) == 0 {
		s.mu.Unlock()
		return errors.New("no device enrolled yet — add one with `protonmcp remote add-device`")
	}
	s.cfg.Enabled = on
	if on {
		s.cfg.EnabledAt, s.cfg.EnabledBy = time.Now().UTC(), by
		s.startAwake()
	} else {
		s.stopAwake()
		// Pending approvals can't be answered remotely any more.
		for id, p := range s.pending {
			p.resolve(false)
			delete(s.pending, id)
		}
	}
	err := saveConfig(s.path, s.cfg)
	s.mu.Unlock()
	s.logger.Info("remote mode switched", "on", on, "by", by)
	if s.hooks.OnChange != nil {
		s.hooks.OnChange()
	}
	return err
}

// SetOrigin records the tailnet HTTPS origin. Changing it orphans
// existing passkeys (they're bound to the host name), so devices are
// dropped and Remote mode is switched off.
func (s *Service) SetOrigin(origin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if origin == s.cfg.Origin && s.wa != nil {
		return nil
	}
	if err := s.initWebAuthn(origin); err != nil {
		return err
	}
	if s.cfg.Origin != "" && s.cfg.Origin != origin {
		s.cfg.Devices = nil
		s.cfg.OwnerLogin = ""
		s.cfg.Enabled = false
		s.stopAwake()
	}
	s.cfg.Origin = origin
	return saveConfig(s.path, s.cfg)
}

// RemoveDevice drops an enrolled device by name. Removing the last one
// switches Remote mode off.
func (s *Service) RemoveDevice(name string) error {
	s.mu.Lock()
	out := s.cfg.Devices[:0]
	found := false
	for _, d := range s.cfg.Devices {
		if d.Name == name {
			found = true
			continue
		}
		out = append(out, d)
	}
	s.cfg.Devices = out
	if len(out) == 0 {
		s.cfg.Enabled = false
		s.cfg.OwnerLogin = ""
		s.stopAwake()
	}
	err := saveConfig(s.path, s.cfg)
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("no device named %q", name)
	}
	if s.hooks.OnChange != nil {
		s.hooks.OnChange()
	}
	return err
}

// NewEnrollToken returns a one-time enrolment URL (valid 10 minutes).
// The caller must have gated this with Touch ID at the Mac.
func (s *Service) NewEnrollToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wa == nil {
		return "", errors.New("remote mode is not set up yet — run `protonmcp remote setup`")
	}
	tok := randomID()
	s.enroll[tok] = &enrollToken{expires: time.Now().Add(enrollTokenTTL)}
	return s.cfg.Origin + "/#enroll=" + tok, nil
}

// Approve sends an approval to the enrolled devices and waits for a
// passkey-verified answer. Declines, timeouts and cancellation return
// mcperrors.ErrUserCanceled.
func (s *Service) Approve(ctx context.Context, title, body string) error {
	if !s.Active() {
		return fmt.Errorf("%w: remote mode is off", mcperrors.ErrAuthFailed)
	}
	p := &Pending{
		ID: randomID(), Title: title, Body: body,
		Expires: time.Now().Add(ApprovalTimeout),
		digest:  sha256.Sum256([]byte(title + "\x00" + body)),
		done:    make(chan bool, 1),
	}
	s.mu.Lock()
	s.pending[p.ID] = p
	origin, server, topic := s.cfg.Origin, s.cfg.NtfyServer, s.cfg.NtfyTopic
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, p.ID)
		s.mu.Unlock()
	}()

	go s.notify(server, topic, origin+"/#a="+p.ID)
	s.logger.Info("remote approval requested", "id", p.ID[:8])

	t := time.NewTimer(ApprovalTimeout)
	defer t.Stop()
	select {
	case ok := <-p.done:
		if ok {
			return nil
		}
		return mcperrors.ErrUserCanceled
	case <-t.C:
		s.logger.Warn("remote approval timed out", "id", p.ID[:8])
		return mcperrors.ErrUserCanceled
	case <-ctx.Done():
		return mcperrors.ErrUserCanceled
	}
}

func (p *Pending) resolve(ok bool) {
	select {
	case p.done <- ok:
	default:
	}
}

// notify posts a content-free alert to ntfy. Failures are logged only;
// the page still shows the pending approval.
func (s *Service) notify(server, topic, click string) {
	if topic == "" {
		return
	}
	req, err := http.NewRequest(http.MethodPost, server+"/"+topic,
		bytes.NewBufferString("Approval needed — tap to review on your device."))
	if err != nil {
		return
	}
	req.Header.Set("Title", "Proton MCP")
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "lock")
	req.Header.Set("Click", click)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Warn("ntfy notify failed", "err", err.Error())
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		s.logger.Warn("ntfy notify rejected", "status", resp.StatusCode)
	}
}

// TestNotify sends a test alert.
func (s *Service) TestNotify() {
	s.mu.Lock()
	server, topic, origin := s.cfg.NtfyServer, s.cfg.NtfyTopic, s.cfg.Origin
	s.mu.Unlock()
	s.notify(server, topic, origin+"/")
}

// startAwake keeps the Mac from idle/system sleep (on power) while
// Remote mode is on. The display may still sleep and the screen lock.
// caffeinate -w exits by itself if the daemon dies. Caller holds mu.
func (s *Service) startAwake() {
	if s.awake != nil {
		return
	}
	cmd := exec.Command("/usr/bin/caffeinate", "-i", "-s", "-w", strconv.Itoa(os.Getpid()))
	if err := cmd.Start(); err != nil {
		s.logger.Warn("caffeinate failed; the Mac may sleep in remote mode", "err", err.Error())
		return
	}
	s.awake = cmd
	go func() { _ = cmd.Wait() }()
}

// stopAwake ends the caffeinate child. Caller holds mu.
func (s *Service) stopAwake() {
	if s.awake == nil {
		return
	}
	if s.awake.Process != nil {
		_ = s.awake.Process.Kill()
	}
	s.awake = nil
}

// Close stops the listeners and the caffeinate child.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.stopAwake()
	for _, p := range s.pending {
		p.resolve(false)
	}
	stops := s.listeners
	s.listeners = nil
	s.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}
