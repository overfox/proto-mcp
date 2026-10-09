package remote

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

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

// userLocked snapshots the webauthn user. Caller holds mu.
func (s *Service) userLocked() waUser {
	u := waUser{id: s.cfg.UserID}
	for _, d := range s.cfg.Devices {
		u.creds = append(u.creds, d.Cred)
	}
	return u
}

// Serve starts the loopback web listener (published on the tailnet by
// `tailscale serve`) and the 0600 control socket. Both stop on Close.
func (s *Service) Serve() error {
	s.mu.Lock()
	addr := s.cfg.Listen
	s.mu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("remote: listen %s: %w", addr, err)
	}
	if host, _, _ := net.SplitHostPort(ln.Addr().String()); host != "127.0.0.1" && host != "::1" {
		_ = ln.Close()
		return fmt.Errorf("remote: refusing non-loopback listen address %s", addr)
	}
	web := &http.Server{Handler: s.WebHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = web.Serve(ln) }()

	sock, err := ControlSocketPath()
	if err != nil {
		_ = web.Close()
		return err
	}
	_ = os.Remove(sock)
	cl, err := net.Listen("unix", sock)
	if err != nil {
		_ = web.Close()
		return fmt.Errorf("remote: control socket: %w", err)
	}
	_ = os.Chmod(sock, 0o600)
	ctl := &http.Server{Handler: s.ControlHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = ctl.Serve(cl) }()

	s.mu.Lock()
	s.listeners = append(s.listeners, func() {
		_ = web.Close()
		_ = ctl.Close()
		_ = os.Remove(sock)
	})
	s.mu.Unlock()
	s.logger.Info("remote mode listeners up", "web", addr, "control", sock)
	return nil
}

// ---------------------------------------------------------------------
// Device-facing web app (reached only through `tailscale serve`).

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

// guard enforces: request came through tailscale serve from the owner's
// tailnet identity; state-changing calls come from our own origin.
func (s *Service) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		login := r.Header.Get("Tailscale-User-Login")
		if login == "" {
			http.Error(w, "reachable only through your tailnet", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		owner, origin := s.cfg.OwnerLogin, s.cfg.Origin
		s.mu.Unlock()
		if owner != "" && !strings.EqualFold(owner, login) {
			s.logger.Warn("remote request from a non-owner tailnet identity refused", "login", login)
			http.Error(w, "this tailnet identity is not allowed", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if origin == "" || r.Header.Get("Origin") != origin {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		next.ServeHTTP(w, r)
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

type pageState struct {
	Remote     bool       `json:"remote"`
	Devices    int        `json:"devices"`
	Connector  string     `json:"connector"`
	Reason     string     `json:"reason,omitempty"`
	Email      string     `json:"email,omitempty"`
	Pending    []*Pending `json:"pending"`
	NtfyServer string     `json:"ntfy_server"`
	NtfyTopic  string     `json:"ntfy_topic"`
}

func (s *Service) apiState(w http.ResponseWriter, _ *http.Request) {
	st := pageState{Pending: []*Pending{}}
	if s.hooks.ConnectorState != nil {
		st.Connector, st.Reason, st.Email = s.hooks.ConnectorState()
	}
	s.mu.Lock()
	st.Remote = s.activeLocked()
	st.Devices = len(s.cfg.Devices)
	st.NtfyServer, st.NtfyTopic = s.cfg.NtfyServer, s.cfg.NtfyTopic
	for _, p := range s.pending {
		st.Pending = append(st.Pending, p)
	}
	s.mu.Unlock()
	sort.Slice(st.Pending, func(i, j int) bool { return st.Pending[i].Expires.Before(st.Pending[j].Expires) })
	writeJSON(w, http.StatusOK, st)
}

func (s *Service) apiEnrollBegin(w http.ResponseWriter, r *http.Request) {
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
	if !ok || time.Now().After(tok.expires) {
		delete(s.enroll, in.Token)
		jsonErr(w, http.StatusForbidden, "this enrolment link has expired — create a new one from the Mac menu")
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
		jsonErr(w, http.StatusInternalServerError, "could not start enrolment")
		return
	}
	tok.session, tok.name = sess, name
	writeJSON(w, http.StatusOK, opts)
}

func (s *Service) apiEnrollFinish(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	s.mu.Lock()
	tok, ok := s.enroll[token]
	if !ok || tok.session == nil || time.Now().After(tok.expires) {
		s.mu.Unlock()
		jsonErr(w, http.StatusForbidden, "this enrolment link has expired")
		return
	}
	delete(s.enroll, token) // single use, success or not
	u, wa, sess, name := s.userLocked(), s.wa, *tok.session, tok.name
	s.mu.Unlock()

	cred, err := wa.FinishRegistration(u, sess, r)
	if err != nil {
		s.logger.Warn("remote enrolment failed", "err", err.Error())
		jsonErr(w, http.StatusBadRequest, "enrolment failed: "+errText(err))
		return
	}
	s.mu.Lock()
	s.cfg.Devices = append(s.cfg.Devices, Device{Name: name, AddedAt: time.Now().UTC(), Cred: *cred})
	if s.cfg.OwnerLogin == "" {
		s.cfg.OwnerLogin = r.Header.Get("Tailscale-User-Login")
	}
	err = saveConfig(s.path, s.cfg)
	s.mu.Unlock()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "could not save the device")
		return
	}
	s.logger.Info("remote device enrolled", "name", name)
	if s.hooks.OnChange != nil {
		s.hooks.OnChange()
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Service) apiAuthBegin(w http.ResponseWriter, r *http.Request) {
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
	if s.wa == nil || len(s.cfg.Devices) == 0 {
		jsonErr(w, http.StatusConflict, "no device enrolled")
		return
	}
	as := &authSession{purpose: in.Purpose, created: time.Now()}
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
		jsonErr(w, http.StatusBadRequest, "unknown purpose")
		return
	}
	s.pruneSessionsLocked()
	opts, sess, err := s.wa.BeginLogin(s.userLocked(), webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "could not start verification")
		return
	}
	as.data = *sess
	sid := randomID()
	s.sessions[sid] = as
	writeJSON(w, http.StatusOK, map[string]any{"sid": sid, "options": opts})
}

func (s *Service) apiAuthFinish(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	s.mu.Lock()
	as, ok := s.sessions[sid]
	delete(s.sessions, sid) // single use
	if !ok || time.Since(as.created) > authSessionTTL {
		s.mu.Unlock()
		jsonErr(w, http.StatusForbidden, "verification expired — try again")
		return
	}
	u, wa := s.userLocked(), s.wa
	s.mu.Unlock()

	cred, err := wa.FinishLogin(u, as.data, r)
	if err != nil {
		s.logger.Warn("remote passkey verification failed", "err", err.Error())
		jsonErr(w, http.StatusForbidden, "passkey verification failed")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.logger.Error("remote passkey clone warning; refusing", "purpose", as.purpose)
		jsonErr(w, http.StatusForbidden, "passkey looks cloned — remove and re-add this device")
		return
	}
	device := s.recordUse(cred)

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
		s.logger.Info("remote approval granted", "id", p.ID[:8], "device", device)
		writeJSON(w, http.StatusOK, map[string]string{"result": "approved"})
	case "remote_on":
		if err := s.SetEnabled(true, "device:"+device); err != nil {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"result": "remote mode on"})
	}
}

// recordUse stores the updated sign counter and returns the device name.
func (s *Service) recordUse(cred *webauthn.Credential) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.cfg.Devices {
		if bytes.Equal(s.cfg.Devices[i].Cred.ID, cred.ID) {
			s.cfg.Devices[i].Cred.Authenticator = cred.Authenticator
			s.cfg.Devices[i].Cred.Flags = cred.Flags
			s.cfg.Devices[i].LastUsed = time.Now().UTC()
			_ = saveConfig(s.path, s.cfg)
			return s.cfg.Devices[i].Name
		}
	}
	return "unknown"
}

func (s *Service) pruneSessionsLocked() {
	for k, v := range s.sessions {
		if time.Since(v.created) > authSessionTTL {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.enroll {
		if time.Now().After(v.expires) {
			delete(s.enroll, k)
		}
	}
}

func (s *Service) apiDecline(w http.ResponseWriter, r *http.Request) {
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

func (s *Service) apiRemoteOff(w http.ResponseWriter, _ *http.Request) {
	_ = s.SetEnabled(false, "device")
	writeJSON(w, http.StatusOK, map[string]string{"result": "remote mode off"})
}

func (s *Service) apiLock(w http.ResponseWriter, _ *http.Request) {
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
	mux.HandleFunc("POST /setup", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Origin string `json:"origin"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
			jsonErr(w, http.StatusBadRequest, "bad request")
			return
		}
		if err := s.macGate(r.Context(), "Set up Remote mode?", "Remote approvals will be served at "+in.Origin+" on your tailnet."); err != nil {
			jsonErr(w, http.StatusForbidden, err.Error())
			return
		}
		if err := s.SetOrigin(in.Origin); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.Status())
	})
	mux.HandleFunc("POST /enroll", func(w http.ResponseWriter, r *http.Request) {
		if err := s.macGate(r.Context(), "Add a remote approval device?",
			"A one-time link (valid 10 minutes) will let a phone or tablet approve sends and other protected actions with its fingerprint or face."); err != nil {
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

func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 40 {
		s = string(r[:40])
	}
	if s == "" {
		s = "Device"
	}
	return s
}

func errText(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Details != "" {
		return pe.Details
	}
	return err.Error()
}
