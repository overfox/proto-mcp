package remote

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web/index.html web/app.js
var webFS embed.FS

type waUser struct {
	id    []byte
	creds []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.id }
func (u waUser) WebAuthnName() string                       { return "Proton MCP" }
func (u waUser) WebAuthnDisplayName() string                { return "Proton MCP approvals" }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// userLocked snapshots the webauthn user with every credential (used
// for enrolment exclusions). Caller holds mu.
func (s *Service) userLocked() waUser {
	u := waUser{id: s.cfg.UserID}
	for _, d := range s.cfg.Devices {
		u.creds = append(u.creds, d.Cred)
	}
	return u
}

// nodeUserLocked is the webauthn user restricted to the credentials
// bound to one Tailscale node: a passkey only counts from the node it
// was enrolled on. Caller holds mu.
func (s *Service) nodeUserLocked(nodeID string) waUser {
	u := waUser{id: s.cfg.UserID}
	for _, d := range s.cfg.Devices {
		if nodeID != "" && d.NodeID == nodeID {
			u.creds = append(u.creds, d.Cred)
		}
	}
	return u
}

// Serve starts the 0600 control socket and the web listener on the
// Mac's Tailscale address. The web listener (re)starts in the
// background: Tailscale may not be up yet, and setup may come later.
// Both stop on Close.
func (s *Service) Serve() error {
	sock, err := ControlSocketPath()
	if err != nil {
		return err
	}
	_ = os.Remove(sock)
	cl, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("remote: control socket: %w", err)
	}
	_ = os.Chmod(sock, 0o600)
	ctl := &http.Server{Handler: s.ControlHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = ctl.Serve(cl) }()
	go s.webLoop()

	s.mu.Lock()
	s.listeners = append(s.listeners, func() {
		_ = ctl.Close()
		_ = os.Remove(sock)
	})
	s.mu.Unlock()
	s.logger.Info("remote mode control socket up", "control", sock)
	return nil
}

var errNotConfigured = errors.New("remote mode is not set up")

// webLoop keeps the tailnet HTTPS listener up: started once set up,
// retried with backoff while Tailscale is unavailable, restarted when
// the origin changes, certificate refreshed daily.
func (s *Service) webLoop() {
	var (
		srv     *http.Server
		errc    <-chan error
		backoff = time.Minute
	)
	retry := time.NewTimer(0)
	refresh := time.NewTicker(certRefresh)
	defer refresh.Stop()
	stop := func() {
		if srv != nil {
			_ = srv.Close()
			srv, errc = nil, nil
			s.mu.Lock()
			s.listenAddr = ""
			s.mu.Unlock()
		}
	}
	defer stop()
	for {
		select {
		case <-s.done:
			retry.Stop()
			return
		case <-s.kick:
			stop()
			backoff = time.Minute
			retry.Reset(0)
		case <-retry.C:
			if srv != nil {
				continue
			}
			var err error
			srv, errc, err = s.startWeb()
			switch {
			case err == nil:
				backoff = time.Minute
			case errors.Is(err, errNotConfigured):
				// Wait for setup (kick).
			default:
				s.logger.Warn("remote web listener unavailable; retrying", "err", err.Error(), "in", backoff)
				retry.Reset(backoff)
				backoff = min(backoff*2, 15*time.Minute)
			}
		case err := <-errc:
			s.logger.Warn("remote web listener stopped; restarting", "err", fmt.Sprint(err))
			srv, errc = nil, nil
			s.mu.Lock()
			s.listenAddr = ""
			s.mu.Unlock()
			retry.Reset(backoff)
		case <-refresh.C:
			if srv == nil {
				continue
			}
			s.mu.Lock()
			origin := s.cfg.Origin
			s.mu.Unlock()
			if u, err := parseOrigin(origin); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				if _, err := s.loadCert(ctx, u.Hostname()); err != nil {
					s.logger.Warn("remote certificate refresh failed", "err", err.Error())
				}
				cancel()
			}
		}
	}
}

// loadCert fetches the certificate via Tailscale, stores it 0600 and
// installs it for new TLS handshakes.
func (s *Service) loadCert(ctx context.Context, domain string) (*tls.Certificate, error) {
	c, err := fetchCert(ctx, s.tn, tlsDir(s.path), domain)
	if err != nil {
		return nil, err
	}
	s.cert.Store(c)
	return c, nil
}

// startWeb binds the HTTPS listener on this Mac's Tailscale IPv4.
func (s *Service) startWeb() (*http.Server, <-chan error, error) {
	s.mu.Lock()
	origin, port := s.cfg.Origin, s.cfg.Port
	s.mu.Unlock()
	if origin == "" {
		return nil, nil, errNotConfigured
	}
	u, err := parseOrigin(origin)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	self, err := s.selfNode(ctx, true)
	if err != nil {
		return nil, nil, err
	}
	if !strings.EqualFold(self.DNSName, u.Hostname()) {
		return nil, nil, fmt.Errorf("this Mac's Tailscale name is now %s, not %s — run `protonmcp remote setup` again", self.DNSName, u.Hostname())
	}
	if _, err := s.loadCert(ctx, self.DNSName); err != nil {
		return nil, nil, fmt.Errorf("%w — %s", err, HTTPSHelp)
	}
	addr := net.JoinHostPort(self.IPv4, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := s.cert.Load(); c != nil {
				return c, nil
			}
			return nil, errors.New("no certificate")
		},
	}
	srv := &http.Server{
		Handler:           s.WebHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0), // TLS handshake noise from scanners
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	s.mu.Lock()
	s.listenAddr = addr
	s.mu.Unlock()
	s.logger.Info("remote web listener up", "addr", addr, "origin", origin)
	return srv, errc, nil
}

// ---------------------------------------------------------------------
// Peer identity (tailscale whois on the connection's real address).

type peerKey struct{}

func peerFrom(r *http.Request) Peer {
	p, _ := r.Context().Value(peerKey{}).(Peer)
	return p
}

// selfNode returns this Mac's node, cached for selfTTL (fresh forces a
// lookup).
func (s *Service) selfNode(ctx context.Context, fresh bool) (SelfNode, error) {
	s.mu.Lock()
	if !fresh && s.self.NodeID != "" && time.Since(s.selfAt) < selfTTL {
		n := s.self
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()
	n, err := s.tn.Self(ctx)
	if err != nil {
		return SelfNode{}, err
	}
	s.mu.Lock()
	s.self, s.selfAt = n, time.Now()
	s.mu.Unlock()
	return n, nil
}

// whoisCached resolves addr ("ip:port"), cached per IP for whoisTTL
// (failures for a few seconds only).
func (s *Service) whoisCached(ctx context.Context, addr, ip string) (Peer, error) {
	s.mu.Lock()
	if e, ok := s.whois[ip]; ok {
		ttl := whoisTTL
		if e.err != nil {
			ttl = 5 * time.Second
		}
		if time.Since(e.at) < ttl {
			s.mu.Unlock()
			return e.peer, e.err
		}
	}
	s.mu.Unlock()
	p, err := s.tn.WhoIs(ctx, addr)
	s.mu.Lock()
	if len(s.whois) >= 256 {
		s.whois = map[string]whoisEntry{}
	}
	s.whois[ip] = whoisEntry{peer: p, err: err, at: time.Now()}
	s.mu.Unlock()
	return p, err
}

// authorizePeer decides whether the connection's peer may use the web
// app at all: a known, untagged tailnet node that isn't this Mac,
// signed in as the owner (or, before the first enrolment, as the
// Mac's own user). Request headers play no part.
func (s *Service) authorizePeer(r *http.Request) (Peer, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil {
		return Peer{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	self, err := s.selfNode(ctx, false)
	if err != nil {
		s.logger.Warn("remote request refused: Tailscale status unavailable", "err", err.Error())
		return Peer{}, false
	}
	if ip.IsLoopback() || ip.String() == self.IPv4 {
		s.logger.Warn("remote request from this Mac refused", "addr", ip.String())
		return Peer{}, false
	}
	peer, err := s.whoisCached(ctx, r.RemoteAddr, ip.String())
	if err != nil {
		s.logger.Warn("remote request from an unknown peer refused", "addr", ip.String(), "err", err.Error())
		return Peer{}, false
	}
	s.mu.Lock()
	owner := s.cfg.OwnerLogin
	s.mu.Unlock()
	if owner == "" {
		owner = self.Login
	}
	switch {
	case peer.NodeID == "" || peer.NodeID == self.NodeID:
		s.logger.Warn("remote request from this Mac's own node refused", "addr", ip.String())
		return Peer{}, false
	case len(peer.Tags) > 0:
		s.logger.Warn("remote request from a tagged node refused", "node", peer.NodeName, "tags", strings.Join(peer.Tags, ","))
		return Peer{}, false
	case owner == "" || !strings.EqualFold(owner, peer.Login):
		s.logger.Warn("remote request from a non-owner tailnet identity refused", "node", peer.NodeName, "login", peer.Login)
		return Peer{}, false
	}
	return peer, true
}

// deviceForNodeLocked is the enrolled device bound to nodeID, if any.
// Caller holds mu.
func (s *Service) deviceForNodeLocked(nodeID string) (Device, bool) {
	for _, d := range s.cfg.Devices {
		if nodeID != "" && d.NodeID == nodeID {
			return d, true
		}
	}
	return Device{}, false
}

func (s *Service) enrolledPeer(r *http.Request) (Peer, bool) {
	p := peerFrom(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.deviceForNodeLocked(p.NodeID)
	return p, ok
}

// ---------------------------------------------------------------------
// Device-facing web app (served on the Mac's Tailscale address).

// WebHandler serves the phone app and its API.
func (s *Service) WebHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.static("web/index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /app.js", s.static("web/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /api/state", s.apiState)
	mux.HandleFunc("POST /api/enroll/begin", s.apiEnrollBegin)
	mux.HandleFunc("POST /api/enroll/finish", s.apiEnrollFinish)
	mux.HandleFunc("POST /api/auth/begin", s.apiAuthBegin)
	mux.HandleFunc("POST /api/auth/finish", s.apiAuthFinish)
	mux.HandleFunc("POST /api/decline", s.apiDecline)
	mux.HandleFunc("POST /api/remote_off", s.apiRemoteOff)
	mux.HandleFunc("POST /api/lock", s.apiLock)
	return s.guard(mux)
}

// guard enforces: the peer (by its real address, via whois) is an
// allowed tailnet node; state-changing calls come from our own origin.
func (s *Service) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		peer, ok := s.authorizePeer(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			s.mu.Lock()
			origin := s.cfg.Origin
			s.mu.Unlock()
			if origin == "" || r.Header.Get("Origin") != origin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, peer)))
	})
}

func (s *Service) static(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := webFS.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write(data)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

const errNotEnrolled = "this device isn't enrolled — add it from the Mac menu"

type pageState struct {
	Enrolled   bool       `json:"enrolled"`
	Device     string     `json:"device,omitempty"`
	Remote     bool       `json:"remote"`
	Devices    int        `json:"devices"`
	Connector  string     `json:"connector,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Email      string     `json:"email,omitempty"`
	Pending    []*Pending `json:"pending"`
	NtfyServer string     `json:"ntfy_server,omitempty"`
	NtfyTopic  string     `json:"ntfy_topic,omitempty"`
}

// apiState shows pending approvals, connector state and the alert
// topic only to an enrolled node.
func (s *Service) apiState(w http.ResponseWriter, r *http.Request) {
	peer := peerFrom(r)
	st := pageState{Pending: []*Pending{}}
	s.mu.Lock()
	d, enrolled := s.deviceForNodeLocked(peer.NodeID)
	st.Remote = s.activeLocked()
	st.Devices = len(s.cfg.Devices)
	if enrolled {
		st.Enrolled, st.Device = true, d.Name
		st.NtfyServer, st.NtfyTopic = s.cfg.NtfyServer, s.cfg.NtfyTopic
		for _, p := range s.pending {
			st.Pending = append(st.Pending, p)
		}
	}
	s.mu.Unlock()
	if !enrolled {
		writeJSON(w, http.StatusOK, st)
		return
	}
	if s.hooks.ConnectorState != nil {
		st.Connector, st.Reason, st.Email = s.hooks.ConnectorState()
	}
	sort.Slice(st.Pending, func(i, j int) bool { return st.Pending[i].Expires.Before(st.Pending[j].Expires) })
	writeJSON(w, http.StatusOK, st)
}

func (s *Service) apiEnrollBegin(w http.ResponseWriter, r *http.Request) {
	peer := peerFrom(r)
	var in struct {
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	name := cleanName(in.Name)
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.enroll[in.Token]
	if !ok || time.Now().After(tok.expires) || s.wa == nil {
		delete(s.enroll, in.Token)
		jsonErr(w, http.StatusForbidden, "this enrolment link has expired — create a new one from the Mac menu")
		return
	}
	if tok.session != nil {
		// One begin per link: a second one (a replay, or another
		// device racing the real one) burns the link.
		delete(s.enroll, in.Token)
		s.logger.Warn("remote enrolment link used twice; revoked", "node", peer.NodeName)
		jsonErr(w, http.StatusForbidden, "this enrolment link was already used — create a new one from the Mac menu")
		return
	}
	if _, dup := s.deviceForNodeLocked(peer.NodeID); dup {
		jsonErr(w, http.StatusConflict, "this device is already enrolled — remove it on the Mac first")
		return
	}
	for _, d := range s.cfg.Devices {
		if d.Name == name {
			jsonErr(w, http.StatusConflict, "a device with that name is already enrolled")
			return
		}
	}
	u := s.userLocked()
	var exclude []protocol.CredentialDescriptor
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, sess, err := s.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	)
	if err != nil {
		s.logger.Warn("remote enrolment begin failed", "err", err.Error())
		jsonErr(w, http.StatusInternalServerError, "could not start enrolment")
		return
	}
	tok.session, tok.name, tok.nodeID = sess, name, peer.NodeID
	writeJSON(w, http.StatusOK, opts)
}

func (s *Service) apiEnrollFinish(w http.ResponseWriter, r *http.Request) {
	peer := peerFrom(r)
	token := r.URL.Query().Get("t")
	s.mu.Lock()
	tok, ok := s.enroll[token]
	if !ok || tok.session == nil || time.Now().After(tok.expires) {
		s.mu.Unlock()
		jsonErr(w, http.StatusForbidden, "this enrolment link has expired")
		return
	}
	delete(s.enroll, token) // single use, success or not
	if tok.nodeID != peer.NodeID {
		s.mu.Unlock()
		s.logger.Warn("remote enrolment finished from a different node; refused", "node", peer.NodeName)
		jsonErr(w, http.StatusForbidden, "enrolment failed")
		return
	}
	u, wa, sess, name := s.userLocked(), s.wa, *tok.session, tok.name
	s.mu.Unlock()

	cred, err := wa.FinishRegistration(u, sess, r)
	if err != nil {
		s.logger.Warn("remote enrolment failed", "err", err.Error())
		jsonErr(w, http.StatusBadRequest, "enrolment failed")
		return
	}

	// Second Touch ID at the Mac, naming exactly what is being added.
	node, login := cleanText(peer.NodeName, 64), cleanText(peer.Login, 96)
	if err := s.macGate(r.Context(), "Add a remote approver?",
		fmt.Sprintf("Add '%s' (Tailscale node %s, %s) as a remote approver? It will be able to approve sends and other protected actions with its passkey.",
			name, node, login)); err != nil {
		s.logger.Warn("remote enrolment not confirmed at the Mac", "name", name, "node", node, "err", err.Error())
		jsonErr(w, http.StatusForbidden, "not confirmed on the Mac")
		return
	}

	s.mu.Lock()
	if s.wa != wa { // setup changed meanwhile
		s.mu.Unlock()
		jsonErr(w, http.StatusConflict, "enrolment failed")
		return
	}
	if _, dup := s.deviceForNodeLocked(peer.NodeID); dup {
		s.mu.Unlock()
		jsonErr(w, http.StatusConflict, "this device is already enrolled")
		return
	}
	s.cfg.Devices = append(s.cfg.Devices, Device{
		Name: name, AddedAt: time.Now().UTC(),
		NodeID: peer.NodeID, NodeName: node, Login: peer.Login, Cred: *cred,
	})
	if s.cfg.OwnerLogin == "" {
		s.cfg.OwnerLogin = peer.Login
	}
	err = saveConfig(s.path, s.cfg)
	s.mu.Unlock()
	if err != nil {
		s.logger.Error("remote device save failed", "err", err.Error())
		jsonErr(w, http.StatusInternalServerError, "could not save the device")
		return
	}
	s.logger.Info("remote device enrolled", "name", name, "node", node, "login", login)
	if s.hooks.OnChange != nil {
		s.hooks.OnChange()
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Service) apiAuthBegin(w http.ResponseWriter, r *http.Request) {
	peer := peerFrom(r)
	var in struct {
		Purpose string `json:"purpose"`
		ID      string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.nodeUserLocked(peer.NodeID)
	if s.wa == nil || len(u.creds) == 0 {
		jsonErr(w, http.StatusForbidden, errNotEnrolled)
		return
	}
	as := &authSession{purpose: in.Purpose, nodeID: peer.NodeID, created: time.Now()}
	switch in.Purpose {
	case "approve":
		p, ok := s.pending[in.ID]
		if !ok {
			jsonErr(w, http.StatusNotFound, "this approval is no longer waiting")
			return
		}
		as.approvalID, as.digest = p.ID, p.digest
	case "remote_on":
	default:
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s.pruneLocked()
	for len(s.sessions) >= maxAuthSessions {
		s.evictOldestSessionLocked()
	}
	opts, sess, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.logger.Warn("remote passkey begin failed", "err", err.Error())
		jsonErr(w, http.StatusInternalServerError, "could not start verification")
		return
	}
	as.data = *sess
	sid := randomID()
	s.sessions[sid] = as
	writeJSON(w, http.StatusOK, map[string]any{"sid": sid, "options": opts})
}

// evictOldestSessionLocked drops the oldest auth session. Caller holds mu.
func (s *Service) evictOldestSessionLocked() {
	var oldest string
	var at time.Time
	for k, v := range s.sessions {
		if oldest == "" || v.created.Before(at) {
			oldest, at = k, v.created
		}
	}
	delete(s.sessions, oldest)
}

func (s *Service) apiAuthFinish(w http.ResponseWriter, r *http.Request) {
	peer := peerFrom(r)
	sid := r.URL.Query().Get("sid")
	s.mu.Lock()
	as, ok := s.sessions[sid]
	delete(s.sessions, sid) // single use
	if !ok || time.Since(as.created) > authSessionTTL {
		s.mu.Unlock()
		jsonErr(w, http.StatusForbidden, "verification expired — try again")
		return
	}
	if as.nodeID != peer.NodeID {
		s.mu.Unlock()
		s.logger.Warn("remote passkey finish from a different node; refused", "node", peer.NodeName)
		jsonErr(w, http.StatusForbidden, "passkey verification failed")
		return
	}
	u, wa := s.nodeUserLocked(peer.NodeID), s.wa
	s.mu.Unlock()
	if len(u.creds) == 0 {
		jsonErr(w, http.StatusForbidden, errNotEnrolled)
		return
	}

	cred, err := wa.FinishLogin(u, as.data, r)
	if err != nil {
		s.logger.Warn("remote passkey verification failed", "node", peer.NodeName, "err", err.Error())
		jsonErr(w, http.StatusForbidden, "passkey verification failed")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.logger.Error("remote passkey clone warning; refusing", "purpose", as.purpose, "node", peer.NodeName)
		jsonErr(w, http.StatusForbidden, "passkey looks cloned — remove and re-add this device")
		return
	}
	device, ok := s.recordUse(cred, peer.NodeID)
	if !ok {
		s.logger.Error("remote passkey not bound to the requesting node; refusing", "node", peer.NodeName)
		jsonErr(w, http.StatusForbidden, "passkey verification failed")
		return
	}

	switch as.purpose {
	case "approve":
		s.mu.Lock()
		p, ok := s.pending[as.approvalID]
		s.mu.Unlock()
		if !ok || p.digest != as.digest {
			jsonErr(w, http.StatusGone, "this approval is no longer waiting")
			return
		}
		p.resolve(true)
		s.logger.Info("remote approval granted", "id", p.ID[:8], "device", device, "node", peer.NodeName)
		writeJSON(w, http.StatusOK, map[string]string{"result": "approved"})
	case "remote_on":
		if err := s.SetEnabled(true, "device:"+device); err != nil {
			s.logger.Warn("remote mode on from device failed", "err", err.Error())
			jsonErr(w, http.StatusConflict, "could not turn Remote mode on")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"result": "remote mode on"})
	}
}

// recordUse stores the updated sign counter and returns the device
// name — only if the credential is bound to nodeID.
func (s *Service) recordUse(cred *webauthn.Credential, nodeID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.cfg.Devices {
		d := &s.cfg.Devices[i]
		if bytes.Equal(d.Cred.ID, cred.ID) {
			if d.NodeID == "" || d.NodeID != nodeID {
				return "", false
			}
			d.Cred.Authenticator = cred.Authenticator
			d.Cred.Flags = cred.Flags
			d.LastUsed = time.Now().UTC()
			_ = saveConfig(s.path, s.cfg)
			return d.Name, true
		}
	}
	return "", false
}

func (s *Service) apiDecline(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.enrolledPeer(r); !ok {
		jsonErr(w, http.StatusForbidden, errNotEnrolled)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	s.mu.Lock()
	p, ok := s.pending[in.ID]
	s.mu.Unlock()
	if ok {
		p.resolve(false)
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "declined"})
}

func (s *Service) apiRemoteOff(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.enrolledPeer(r); !ok {
		jsonErr(w, http.StatusForbidden, errNotEnrolled)
		return
	}
	_ = s.SetEnabled(false, "device")
	writeJSON(w, http.StatusOK, map[string]string{"result": "remote mode off"})
}

func (s *Service) apiLock(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.enrolledPeer(r); !ok {
		jsonErr(w, http.StatusForbidden, errNotEnrolled)
		return
	}
	if s.hooks.Lock != nil {
		s.hooks.Lock("locked from a remote device")
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "locked"})
}

// ---------------------------------------------------------------------
// Local control socket (CLI / menu bar).

// ControlHandler is served on the 0600 unix socket.
func (s *Service) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /on", func(w http.ResponseWriter, r *http.Request) {
		if err := s.macGate(r.Context(), "Turn on Remote mode?",
			"Approvals will go to your enrolled devices instead of this Mac, and the connector will keep working while the screen is locked."); err != nil {
			jsonErr(w, http.StatusForbidden, err.Error())
			return
		}
		if err := s.SetEnabled(true, "mac"); err != nil {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /off", func(w http.ResponseWriter, _ *http.Request) {
		_ = s.SetEnabled(false, "mac")
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /setup", s.ctlSetup)
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		if err := s.macGate(r.Context(), "Add a remote approval device?",
			"A one-time link (valid 10 minutes) will let a phone or tablet on your tailnet enrol a passkey. You'll confirm the device here again before it's added."); err != nil {
			jsonErr(w, http.StatusForbidden, err.Error())
			return
		}
		u, err := s.NewEnrollToken()
		if err != nil {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"url": u})
	})
	mux.HandleFunc("POST /remove", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		if err := s.RemoveDevice(in.Name); err != nil {
			jsonErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /test-notify", func(w http.ResponseWriter, _ *http.Request) {
		s.TestNotify()
		writeJSON(w, http.StatusOK, map[string]string{"result": "sent"})
	})
	return mux
}

// ctlSetup derives the origin from this Mac's own Tailscale status
// (never from the caller), checks that a certificate can be issued,
// confirms with Touch ID showing only the parsed host, then records it.
func (s *Service) ctlSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Origin string `json:"origin"` // optional; must match if given
		Port   int    `json:"port"`   // optional; default: current
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s.mu.Lock()
	port := s.cfg.Port
	s.mu.Unlock()
	if in.Port != 0 {
		if in.Port < 1024 || in.Port > 65535 {
			jsonErr(w, http.StatusBadRequest, "port must be between 1024 and 65535")
			return
		}
		port = in.Port
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	self, err := s.selfNode(ctx, true)
	if err != nil {
		jsonErr(w, http.StatusConflict, err.Error())
		return
	}
	origin := originFor(self.DNSName, port)
	u, err := parseOrigin(origin)
	if err != nil {
		jsonErr(w, http.StatusConflict, "unexpected Tailscale DNS name for this Mac")
		return
	}
	if in.Origin != "" {
		if _, err := parseOrigin(in.Origin); err != nil || in.Origin != origin {
			jsonErr(w, http.StatusBadRequest, "origin doesn't match this Mac's Tailscale address "+u.Host)
			return
		}
	}
	if _, err := s.loadCert(ctx, self.DNSName); err != nil {
		jsonErr(w, http.StatusConflict, "couldn't get an HTTPS certificate from Tailscale ("+err.Error()+"). "+HTTPSHelp)
		return
	}
	if err := s.macGate(r.Context(), "Set up Remote mode?", "Remote approvals will be served at "+u.Host+" on your tailnet."); err != nil {
		jsonErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.mu.Lock()
	s.cfg.Port = port // part of the origin; SetOrigin persists it
	s.mu.Unlock()
	if err := s.SetOrigin(origin); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	select { // (re)start the listener even if the origin is unchanged
	case s.kick <- struct{}{}:
	default:
	}
	writeJSON(w, http.StatusOK, s.Status())
}

func (s *Service) macGate(ctx context.Context, title, body string) error {
	if s.hooks.MacApprove == nil {
		return errors.New("Touch ID is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := s.hooks.MacApprove(ctx, title, body); err != nil {
		return fmt.Errorf("not approved with Touch ID: %w", err)
	}
	return nil
}

// cleanText strips control and invisible format characters (bidi
// overrides, zero-width) and caps the length: it is shown in Touch ID
// prompts and logs.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return strings.TrimSpace(s)
}

func cleanName(s string) string {
	s = strings.ReplaceAll(cleanText(s, 40), "'", "’")
	if s == "" {
		s = "Device"
	}
	return s
}
