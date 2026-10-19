package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
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

	// Bounds against approval spam and memory growth.
	maxPending         = 5
	maxApprovalsPerMin = 20
	maxAuthSessions    = 64
	notifyDebounce     = 10 * time.Second
	pruneInterval      = time.Minute

	// Tailscale lookups are cached briefly: whois per source IP, the
	// Mac's own node a little longer.
	whoisTTL = 30 * time.Second
	selfTTL  = 5 * time.Minute

	// certRefresh re-runs `tailscale cert` (tailscaled caches and
	// renews the certificate; this picks up the renewed one).
	certRefresh = 24 * time.Hour
)

// Hooks connect the service to the daemon runtime.
type Hooks struct {
	// ConnectorState reports the daemon state for the phone page.
	ConnectorState func() (state, reason, email string)
	// Lock locks the connector (manual lock; never vetoed).
	Lock func(reason string)
	// MacApprove runs the Mac's own Touch ID prompt, never routed to
	// the phone. Gates setup, enrolment (twice) and enabling from the Mac.
	MacApprove func(ctx context.Context, title, body string) error
	// OnChange is called after Remote mode is switched on or off.
	OnChange func()
	// Tailnet overrides the tailscale CLI (tests). nil → the CLI.
	Tailnet Tailnet
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
	nodeID     string // the peer node that began it
	created    time.Time
}

type enrollToken struct {
	expires time.Time
	session *webauthn.SessionData
	name    string
	nodeID  string // the peer node that began it
}

type whoisEntry struct {
	peer Peer
	err  error
	at   time.Time
}

// Service is Remote mode. Safe for concurrent use; a nil *Service is
// inactive.
type Service struct {
	path   string
	logger *slog.Logger
	hooks  Hooks
	tn     Tailnet

	mu         sync.Mutex
	cfg        Config
	wa         *webauthn.WebAuthn
	pending    map[string]*Pending
	sessions   map[string]*authSession
	enroll     map[string]*enrollToken
	awake      *exec.Cmd
	recent     []time.Time // approval request times (rate limit)
	lastNotify time.Time
	self       SelfNode
	selfAt     time.Time
	whois      map[string]whoisEntry
	listenAddr string // "" while the web listener is down

	cert atomic.Pointer[tls.Certificate]
	kick chan struct{} // restart the web listener (origin changed)
	done chan struct{} // closed by Close
	once sync.Once

	httpClient *http.Client
	listeners  []func()
}

// Load reads remote.json (creating defaults in memory when absent).
// Devices without a Tailscale node binding (the pre-whois format) are
// dropped: they could have been enrolled — or written into the file —
// by a local process.
func Load(path string, hooks Hooks, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, err
	}
	tn := hooks.Tailnet
	if tn == nil {
		tn = cliTailnet{}
	}
	s := &Service{
		path:       path,
		logger:     logger,
		hooks:      hooks,
		tn:         tn,
		cfg:        cfg,
		pending:    map[string]*Pending{},
		sessions:   map[string]*authSession{},
		enroll:     map[string]*enrollToken{},
		whois:      map[string]whoisEntry{},
		kick:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	kept := s.cfg.Devices[:0]
	for _, d := range s.cfg.Devices {
		if d.NodeID == "" || d.Login == "" {
			logger.Warn("remote: dropping a device without a Tailscale node binding — re-add it", "name", d.Name)
			continue
		}
		kept = append(kept, d)
	}
	s.cfg.Devices = kept
	if len(kept) == 0 {
		s.cfg.Enabled = false
		s.cfg.OwnerLogin = ""
	}
	if s.cfg.Origin != "" {
		u, perr := parseOrigin(s.cfg.Origin)
		if perr != nil || u.Port() != strconv.Itoa(s.cfg.Port) {
			logger.Warn("remote: stored address is from an older setup — run `protonmcp remote setup` again", "origin", s.cfg.Origin)
			s.cfg.Origin, s.cfg.Devices, s.cfg.Enabled, s.cfg.OwnerLogin = "", nil, false, ""
		} else if err := s.initWebAuthn(s.cfg.Origin); err != nil {
			return nil, err
		}
	}
	if err := saveConfig(path, s.cfg); err != nil {
		return nil, err
	}
	if s.activeLocked() {
		s.startAwake()
	}
	go s.pruneLoop()
	return s, nil
}

func (s *Service) initWebAuthn(origin string) error {
	u, err := parseOrigin(origin)
	if err != nil {
		return err
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
	// DeviceNodes maps each device name to its Tailscale node.
	DeviceNodes map[string]string `json:"device_nodes"`
	NtfyServer  string            `json:"ntfy_server"`
	NtfyTopic   string            `json:"ntfy_topic"`
	NtfyToken   bool              `json:"ntfy_token_set"`
	Listen      string            `json:"listen"` // Tailscale ip:port; "" while not serving
	Serving     bool              `json:"serving"`
	Pending     int               `json:"pending"`
}

func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled: s.cfg.Enabled, Active: s.activeLocked(), Configured: s.wa != nil,
		Origin: s.cfg.Origin, NtfyServer: s.cfg.NtfyServer, NtfyTopic: s.cfg.NtfyTopic,
		NtfyToken: s.cfg.NtfyToken != "", Listen: s.listenAddr, Serving: s.listenAddr != "",
		Pending: len(s.pending), Devices: []string{}, DeviceNodes: map[string]string{},
	}
	for _, d := range s.cfg.Devices {
		st.Devices = append(st.Devices, d.Name)
		st.DeviceNodes[d.Name] = d.NodeName + " (" + d.Login + ")"
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
		s.declineAllLocked()
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
// dropped, pending approvals declined and Remote mode switched off.
func (s *Service) SetOrigin(origin string) error {
	s.mu.Lock()
	if origin == s.cfg.Origin && s.wa != nil {
		s.mu.Unlock()
		return nil
	}
	if err := s.initWebAuthn(origin); err != nil {
		s.mu.Unlock()
		return err
	}
	if s.cfg.Origin != "" && s.cfg.Origin != origin {
		s.cfg.Devices = nil
		s.cfg.OwnerLogin = ""
		s.cfg.Enabled = false
		s.stopAwake()
	}
	s.declineAllLocked()
	s.sessions = map[string]*authSession{}
	s.enroll = map[string]*enrollToken{}
	s.cfg.Origin = origin
	err := saveConfig(s.path, s.cfg)
	s.mu.Unlock()
	select {
	case s.kick <- struct{}{}:
	default:
	}
	if s.hooks.OnChange != nil {
		s.hooks.OnChange()
	}
	return err
}

// RemoveDevice drops an enrolled device by name. Pending approvals are
// declined (the removed device may have been the one about to answer);
// removing the last device switches Remote mode off.
func (s *Service) RemoveDevice(name string) error {
	s.mu.Lock()
	out := s.cfg.Devices[:0]
	found := false
	for _, d := range s.cfg.Devices {
		if d.Name == name {
			found = true
			for k, as := range s.sessions {
				if as.nodeID == d.NodeID {
					delete(s.sessions, k)
				}
			}
			continue
		}
		out = append(out, d)
	}
	s.cfg.Devices = out
	if !found {
		s.mu.Unlock()
		return fmt.Errorf("no device named %q", name)
	}
	s.declineAllLocked()
	if len(out) == 0 {
		s.cfg.Enabled = false
		s.cfg.OwnerLogin = ""
		s.stopAwake()
	}
	err := saveConfig(s.path, s.cfg)
	s.mu.Unlock()
	s.logger.Info("remote device removed", "name", name)
	if s.hooks.OnChange != nil {
		s.hooks.OnChange()
	}
	return err
}

// declineAllLocked resolves every pending approval as declined. Caller
// holds mu.
func (s *Service) declineAllLocked() {
	for id, p := range s.pending {
		p.resolve(false)
		delete(s.pending, id)
	}
}

// NewEnrollToken returns a one-time enrolment URL (valid 10 minutes).
// The caller must have gated this with Touch ID at the Mac. The link
// alone isn't enough to enrol: finishing needs another tailnet node of
// the owner and a second Touch ID naming that node.
func (s *Service) NewEnrollToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wa == nil {
		return "", errors.New("remote mode is not set up yet — run `protonmcp remote setup`")
	}
	s.pruneLocked()
	tok := randomID()
	s.enroll[tok] = &enrollToken{expires: time.Now().Add(enrollTokenTTL)}
	return s.cfg.Origin + "/#enroll=" + tok, nil
}

// Approve sends an approval to the enrolled devices and waits for a
// passkey-verified answer. Declines, timeouts, cancellation and
// requests over the rate limits return mcperrors.ErrUserCanceled.
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
	now := time.Now()
	s.mu.Lock()
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		s.logger.Warn("remote approval refused: too many pending", "pending", maxPending)
		return fmt.Errorf("%w: %d approvals are already waiting on your device — answer or decline them first", mcperrors.ErrUserCanceled, maxPending)
	}
	recent := s.recent[:0]
	for _, t := range s.recent {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	s.recent = recent
	if len(s.recent) >= maxApprovalsPerMin {
		s.mu.Unlock()
		s.logger.Warn("remote approval refused: rate limit", "per_minute", maxApprovalsPerMin)
		return fmt.Errorf("%w: too many approval requests in the last minute — try again shortly", mcperrors.ErrUserCanceled)
	}
	s.recent = append(s.recent, now)
	s.pending[p.ID] = p
	origin, server, topic, token := s.cfg.Origin, s.cfg.NtfyServer, s.cfg.NtfyTopic, s.cfg.NtfyToken
	// Debounced: one alert per notifyDebounce; the page lists them all.
	push := now.Sub(s.lastNotify) >= notifyDebounce
	if push {
		s.lastNotify = now
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, p.ID)
		s.mu.Unlock()
	}()

	if push {
		go s.notify(server, topic, token, origin+"/#a="+p.ID)
	}
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
func (s *Service) notify(server, topic, token, click string) {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
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
	server, topic, token, origin := s.cfg.NtfyServer, s.cfg.NtfyTopic, s.cfg.NtfyToken, s.cfg.Origin
	s.lastNotify = time.Now()
	s.mu.Unlock()
	s.notify(server, topic, token, origin+"/")
}

// pruneLoop drops expired auth sessions and enrolment tokens.
func (s *Service) pruneLoop() {
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.mu.Lock()
			s.pruneLocked()
			s.mu.Unlock()
		}
	}
}

// pruneLocked drops expired sessions, tokens and whois entries. Caller
// holds mu.
func (s *Service) pruneLocked() {
	now := time.Now()
	for k, v := range s.sessions {
		if now.Sub(v.created) > authSessionTTL {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.enroll {
		if now.After(v.expires) {
			delete(s.enroll, k)
		}
	}
	for k, v := range s.whois {
		if now.Sub(v.at) > whoisTTL {
			delete(s.whois, k)
		}
	}
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
	s.once.Do(func() { close(s.done) })
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
