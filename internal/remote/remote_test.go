package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
)

const (
	testOrigin = "https://mac.tail1234.ts.net:8443"
	testRPID   = "mac.tail1234.ts.net"
	testLogin  = "owner@example.com"

	// Tailnet addresses as the fake whois sees them.
	addrSelf     = "100.64.0.1:51000" // the Mac's own Tailscale IP
	addrSelfAlt  = "100.64.0.6:51000" // another address of the Mac's node
	addrPhone    = "100.64.0.2:51000"
	addrTablet   = "100.64.0.3:51000"
	addrTagged   = "100.64.0.4:51000"
	addrStranger = "100.64.0.5:51000" // a node of another tailnet user
	addrUnknown  = "100.64.0.99:51000"
	addrLoopback = "127.0.0.1:51000"
	nodeSelf     = "nSELFCNTRL"
	nodePhone    = "nPHONECNTRL"
	nodeTablet   = "nTABLETCNTRL"
)

var b64u = base64.RawURLEncoding

// fakeTailnet stands in for the tailscale CLI.
type fakeTailnet struct {
	mu      sync.Mutex
	self    SelfNode
	peers   map[string]Peer // by IP
	whois   atomic.Int32
	certErr error
	certPEM []byte
	keyPEM  []byte
}

func newFakeTailnet() *fakeTailnet {
	return &fakeTailnet{
		self: SelfNode{NodeID: nodeSelf, DNSName: testRPID, IPv4: "100.64.0.1", Login: testLogin},
		peers: map[string]Peer{
			"100.64.0.1": {NodeID: nodeSelf, NodeName: "mac", Login: testLogin},
			"100.64.0.6": {NodeID: nodeSelf, NodeName: "mac", Login: testLogin},
			"100.64.0.2": {NodeID: nodePhone, NodeName: "galaxy-s24", Login: testLogin},
			"100.64.0.3": {NodeID: nodeTablet, NodeName: "ipad", Login: testLogin},
			"100.64.0.4": {NodeID: "nTAGGED", NodeName: "server", Login: "tagged-devices", Tags: []string{"tag:server"}},
			"100.64.0.5": {NodeID: "nSTRANGER", NodeName: "eve-phone", Login: "eve@example.com"},
		},
	}
}

func (f *fakeTailnet) Self(context.Context) (SelfNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.self, nil
}

func (f *fakeTailnet) WhoIs(_ context.Context, addr string) (Peer, error) {
	f.whois.Add(1)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return Peer{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.peers[host]
	if !ok {
		return Peer{}, errors.New("no such peer")
	}
	return p, nil
}

func (f *fakeTailnet) Cert(context.Context, string) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.certErr != nil {
		return nil, nil, f.certErr
	}
	if f.certPEM == nil {
		f.certPEM, f.keyPEM = selfSignedPEM(f.self.DNSName)
	}
	return f.certPEM, f.keyPEM, nil
}

func selfSignedPEM(host string) ([]byte, []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
}

// macPrompts records second-factor prompts at the Mac.
type macPrompts struct {
	mu      sync.Mutex
	bodies  []string
	decline bool
}

func (m *macPrompts) approve(_ context.Context, title, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, title+"\n"+body)
	if m.decline {
		return errors.New("declined")
	}
	return nil
}

func (m *macPrompts) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.bodies) == 0 {
		return ""
	}
	return m.bodies[len(m.bodies)-1]
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// newTestService fills in a fake tailnet and an approving Mac Touch ID
// unless the hooks set them.
func newTestService(t *testing.T, hooks Hooks) *Service {
	t.Helper()
	if hooks.Tailnet == nil {
		hooks.Tailnet = newFakeTailnet()
	}
	if hooks.MacApprove == nil {
		hooks.MacApprove = (&macPrompts{}).approve
	}
	s, err := Load(filepath.Join(t.TempDir(), "remote.json"), hooks, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetOrigin(testOrigin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// do sends a request from the phone node (addr overrides via mutate).
// Tailscale-* headers are deliberately absent: they're ignored.
func do(t *testing.T, h http.Handler, method, path string, body any, mutate func(*http.Request)) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = addrPhone
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func from(addr string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// softAuthenticator is a minimal platform authenticator (P-256, "none"
// attestation, user verification always performed).
type softAuthenticator struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftAuthenticator() *softAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softAuthenticator{key: k, id: id}
}

func (a *softAuthenticator) cose() []byte {
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	c, _ := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	return c
}

func (a *softAuthenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(testRPID))
	flags := byte(0x01 | 0x04) // UP | UV
	if attested {
		flags |= 0x40 // AT
	}
	a.count++
	var buf bytes.Buffer
	buf.Write(rp[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, a.count)
	if attested {
		buf.Write(make([]byte, 16)) // AAGUID
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(a.id)))
		buf.Write(a.id)
		buf.Write(a.cose())
	}
	return buf.Bytes()
}

func clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": testOrigin, "crossOrigin": false})
	return b
}

func (a *softAuthenticator) create(t *testing.T, opts map[string]any) map[string]any {
	t.Helper()
	pk := opts["publicKey"].(map[string]any)
	cd := clientData("webauthn.create", pk["challenge"].(string))
	att, _ := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	return map[string]any{
		"id": b64u.EncodeToString(a.id), "rawId": b64u.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd), "attestationObject": b64u.EncodeToString(att)},
	}
}

func (a *softAuthenticator) get(t *testing.T, opts map[string]any, origin string) map[string]any {
	t.Helper()
	pk := opts["publicKey"].(map[string]any)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": pk["challenge"], "origin": origin, "crossOrigin": false})
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": b64u.EncodeToString(a.id), "rawId": b64u.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64u.EncodeToString(cd), "authenticatorData": b64u.EncodeToString(ad),
			"signature": b64u.EncodeToString(sig),
		},
	}
}

func newEnrollTok(t *testing.T, s *Service) string {
	t.Helper()
	link, err := s.NewEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	return link[strings.Index(link, "#enroll=")+len("#enroll="):]
}

// enrollFrom runs begin+finish from addr and returns the finish status.
func enrollFrom(t *testing.T, s *Service, a *softAuthenticator, name, addr string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	tok := newEnrollTok(t, s)
	h := s.WebHandler()
	rec, opts := do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": name}, from(addr))
	if rec.Code != 200 {
		return rec, tok
	}
	rec, _ = do(t, h, "POST", "/api/enroll/finish?t="+tok, a.create(t, opts), from(addr))
	return rec, tok
}

func enrollDevice(t *testing.T, s *Service, a *softAuthenticator, name, addr string) {
	t.Helper()
	rec, tok := enrollFrom(t, s, a, name, addr)
	if rec.Code != 200 {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	// Single use.
	if rec, _ := do(t, s.WebHandler(), "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": "again"}, from(addr)); rec.Code != http.StatusForbidden {
		t.Errorf("reused enrolment token: %d", rec.Code)
	}
}

// approveFrom runs a passkey approval of pending id from addr.
func approveFrom(t *testing.T, h http.Handler, a *softAuthenticator, purpose, id, addr string) *httptest.ResponseRecorder {
	t.Helper()
	rec, begin := do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": purpose, "id": id}, from(addr))
	if rec.Code != 200 {
		return rec
	}
	rec, _ = do(t, h, "POST", "/api/auth/finish?sid="+begin["sid"].(string), a.get(t, begin["options"].(map[string]any), testOrigin), from(addr))
	return rec
}

func waitPending(t *testing.T, s *Service, n int) []string {
	t.Helper()
	for i := 0; i < 300; i++ {
		s.mu.Lock()
		var ids []string
		for k := range s.pending {
			ids = append(ids, k)
		}
		s.mu.Unlock()
		if len(ids) >= n {
			return ids
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never saw %d pending approvals", n)
	return nil
}

func TestGuard(t *testing.T) {
	s := newTestService(t, Hooks{})
	h := s.WebHandler()
	for _, tc := range []struct{ name, addr string }{
		{"unknown peer", addrUnknown},
		{"loopback", addrLoopback},
		{"the Mac's own IP", addrSelf},
		{"the Mac's own node (other address)", addrSelfAlt},
		{"tagged node", addrTagged},
		{"other tailnet user", addrStranger},
		{"garbage address", "nonsense"},
	} {
		forged := func(r *http.Request) {
			r.RemoteAddr = tc.addr
			r.Header.Set("Tailscale-User-Login", testLogin) // ignored
			r.Header.Set("Tailscale-User-Name", "Owner")
		}
		if rec, _ := do(t, h, "GET", "/api/state", nil, forged); rec.Code != http.StatusForbidden {
			t.Errorf("%s: GET %d", tc.name, rec.Code)
		}
		if rec, _ := do(t, h, "POST", "/api/remote_off", nil, forged); rec.Code != http.StatusForbidden {
			t.Errorf("%s: POST %d", tc.name, rec.Code)
		}
	}
	if rec, _ := do(t, h, "POST", "/api/remote_off", nil, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST: %d", rec.Code)
	}
	rec, _ := do(t, h, "GET", "/", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") ||
		!strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Errorf("index: %d headers=%v", rec.Code, rec.Header())
	}
}

func TestWhoisCached(t *testing.T) {
	tn := newFakeTailnet()
	s := newTestService(t, Hooks{Tailnet: tn})
	h := s.WebHandler()
	for i := 0; i < 5; i++ {
		do(t, h, "GET", "/api/state", nil, nil)
	}
	if n := tn.whois.Load(); n != 1 {
		t.Errorf("whois called %d times for one peer", n)
	}
}

func TestEnableRequiresDevice(t *testing.T) {
	s := newTestService(t, Hooks{})
	if err := s.SetEnabled(true, "mac"); err == nil {
		t.Fatal("enabled with no device")
	}
	if s.Active() {
		t.Fatal("active without device")
	}
}

// Full flow: enrol, enable, an approval arrives, the device approves it
// with a passkey; a wrong-origin assertion and a replayed session fail.
func TestApproveWithPasskey(t *testing.T) {
	changes := 0
	mac := &macPrompts{}
	s := newTestService(t, Hooks{OnChange: func() { changes++ }, MacApprove: mac.approve})
	a := newSoftAuthenticator()
	enrollDevice(t, s, a, "Galaxy S24 Ultra", addrPhone)
	if p := mac.last(); !strings.Contains(p, "Galaxy S24 Ultra") || !strings.Contains(p, "galaxy-s24") || !strings.Contains(p, testLogin) {
		t.Errorf("second Mac prompt doesn't name device/node/login: %q", p)
	}
	d := s.cfg.Devices[0]
	if d.NodeID != nodePhone || d.Login != testLogin || s.cfg.OwnerLogin != testLogin {
		t.Errorf("device binding: %+v owner=%q", d, s.cfg.OwnerLogin)
	}
	if err := s.SetEnabled(true, "mac"); err != nil {
		t.Fatal(err)
	}
	if !s.Active() || changes == 0 {
		t.Fatalf("active=%v changes=%d", s.Active(), changes)
	}
	h := s.WebHandler()

	result := make(chan error, 1)
	go func() {
		result <- s.Approve(context.Background(), "Approve mail_send?", "To: bo@example.com\nSubject: Hi")
	}()

	var id string
	for i := 0; i < 100 && id == ""; i++ {
		_, st := do(t, h, "GET", "/api/state", nil, nil)
		if p, _ := st["pending"].([]any); len(p) == 1 {
			id = p[0].(map[string]any)["id"].(string)
			if !strings.Contains(p[0].(map[string]any)["body"].(string), "bo@example.com") {
				t.Errorf("pending body not shown: %v", p[0])
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("approval never became visible")
	}

	// Wrong origin in the signed client data → refused, still pending.
	_, begin := do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": "approve", "id": id}, nil)
	sid := begin["sid"].(string)
	if rec, _ := do(t, h, "POST", "/api/auth/finish?sid="+sid, a.get(t, begin["options"].(map[string]any), "https://evil.example"), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong-origin assertion: %d %s", rec.Code, rec.Body)
	}
	// The session was consumed even though it failed.
	if rec, _ := do(t, h, "POST", "/api/auth/finish?sid="+sid, a.get(t, begin["options"].(map[string]any), testOrigin), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("replayed session: %d", rec.Code)
	}

	if rec := approveFrom(t, h, a, "approve", id, addrPhone); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if err := <-result; err != nil {
		t.Fatalf("Approve returned %v", err)
	}
	if s.cfg.Devices[0].LastUsed.IsZero() {
		t.Error("device last-used not recorded")
	}
}

func TestDeclineAndRemoteOff(t *testing.T) {
	locked := ""
	s := newTestService(t, Hooks{Lock: func(r string) { locked = r }})
	enrollDevice(t, s, newSoftAuthenticator(), "iPad", addrPhone)
	_ = s.SetEnabled(true, "mac")
	h := s.WebHandler()

	result := make(chan error, 1)
	go func() { result <- s.Approve(context.Background(), "t", "secret body") }()
	id := waitPending(t, s, 1)[0]

	// An owner node that isn't enrolled sees nothing and can't act.
	rec, st := do(t, h, "GET", "/api/state", nil, from(addrTablet))
	if rec.Code != 200 || st["enrolled"] != false || strings.Contains(rec.Body.String(), "secret body") || strings.Contains(rec.Body.String(), "pmcp-") {
		t.Errorf("non-enrolled node state: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := do(t, h, "POST", "/api/decline", map[string]string{"id": id}, from(addrTablet)); rec.Code != http.StatusForbidden {
		t.Errorf("non-enrolled decline: %d", rec.Code)
	}

	do(t, h, "POST", "/api/decline", map[string]string{"id": id}, nil)
	if err := <-result; !errors.Is(err, mcperrors.ErrUserCanceled) {
		t.Fatalf("decline → %v", err)
	}

	// Turning off needs no passkey; turning on from a device does.
	do(t, h, "POST", "/api/remote_off", nil, nil)
	if s.Active() {
		t.Fatal("still active after remote_off")
	}
	if err := s.Approve(context.Background(), "t", "b"); err == nil {
		t.Fatal("Approve succeeded with remote mode off")
	}
	if rec, _ := do(t, h, "POST", "/api/auth/finish?sid=bogus", map[string]any{}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("bogus session: %d", rec.Code)
	}
	do(t, h, "POST", "/api/lock", nil, nil)
	if locked == "" {
		t.Error("lock hook not called")
	}
}

func TestRemoteOnFromDevice(t *testing.T) {
	s := newTestService(t, Hooks{})
	a := newSoftAuthenticator()
	enrollDevice(t, s, a, "Galaxy", addrPhone)
	rec := approveFrom(t, s.WebHandler(), a, "remote_on", "", addrPhone)
	if rec.Code != 200 || !s.Active() {
		t.Fatalf("remote_on: %d %s active=%v", rec.Code, rec.Body, s.Active())
	}
	if s.cfg.EnabledBy != "device:Galaxy" {
		t.Errorf("enabled_by = %q", s.cfg.EnabledBy)
	}
}

func TestControlGatesOnMacTouchID(t *testing.T) {
	approve := errors.New("declined")
	s := newTestService(t, Hooks{MacApprove: func(context.Context, string, string) error { return approve }})
	ctl := s.ControlHandler()
	rec := httptest.NewRecorder()
	ctl.ServeHTTP(rec, httptest.NewRequest("POST", "/enroll", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("enroll without Touch ID: %d", rec.Code)
	}
	approve = nil
	rec = httptest.NewRecorder()
	ctl.ServeHTTP(rec, httptest.NewRequest("POST", "/enroll", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), testOrigin+"/#enroll=") {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
}

func TestOriginChangeDropsDevicesAndDeclinesPending(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy", addrPhone)
	_ = s.SetEnabled(true, "mac")
	result := make(chan error, 1)
	go func() { result <- s.Approve(context.Background(), "t", "b") }()
	waitPending(t, s, 1)
	if err := s.SetOrigin("https://other.tail1234.ts.net:8443"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, mcperrors.ErrUserCanceled) {
			t.Errorf("pending after origin change → %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending approval not resolved by origin change")
	}
	if s.Active() || len(s.cfg.Devices) != 0 || s.cfg.OwnerLogin != "" {
		t.Errorf("origin change kept devices/enabled: %+v", s.Status())
	}
	for _, bad := range []string{"http://insecure.example", "https://x.example/path", "https://x.example?q", "https://u@x.example", "https://x‮.example"} {
		if err := s.SetOrigin(bad); err == nil {
			t.Errorf("accepted origin %q", bad)
		}
	}
}

func TestRemoveDeviceDeclinesPending(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy", addrPhone)
	enrollDevice(t, s, newSoftAuthenticator(), "iPad", addrTablet)
	_ = s.SetEnabled(true, "mac")
	result := make(chan error, 1)
	go func() { result <- s.Approve(context.Background(), "t", "b") }()
	waitPending(t, s, 1)
	if err := s.RemoveDevice("Galaxy"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, mcperrors.ErrUserCanceled) {
			t.Errorf("pending after remove → %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending approval not resolved by RemoveDevice")
	}
	if !s.Active() {
		t.Error("removing one of two devices switched Remote mode off")
	}
	if err := s.RemoveDevice("nope"); err == nil {
		t.Error("removed a device that doesn't exist")
	}
}

// --- C1 regression: a same-user process writes remote.json -----------

func writeConfig(t *testing.T, cfg Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "remote.json")
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The PoC's file (no node binding) is dropped on Load.
func TestC1_UnboundDeviceDroppedOnLoad(t *testing.T) {
	a := newSoftAuthenticator()
	path := writeConfig(t, Config{
		Enabled: true, Origin: testOrigin, Port: DefaultPort, UserID: []byte("u"),
		Devices: []Device{{Name: "evil", Cred: webauthn.Credential{ID: a.id, PublicKey: a.cose(), AttestationType: "none"}}},
	})
	s, err := Load(path, Hooks{Tailnet: newFakeTailnet()}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Active() || len(s.cfg.Devices) != 0 || s.cfg.Enabled {
		t.Fatalf("unbound device kept: active=%v devices=%d", s.Active(), len(s.cfg.Devices))
	}
	var onDisk Config
	b, _ := os.ReadFile(path)
	_ = json.Unmarshal(b, &onDisk)
	if onDisk.Enabled || len(onDisk.Devices) != 0 {
		t.Error("tampered config not rewritten")
	}
}

// Even a credential bound to a node (the Mac's own, or the real phone's
// — both visible in `tailscale status`) can't be used from this Mac:
// loopback, the Mac's Tailscale IP and forged headers are all refused.
func TestC1_TamperedConfigCannotApproveFromMac(t *testing.T) {
	for _, bindTo := range []string{nodeSelf, nodePhone} {
		t.Run(bindTo, func(t *testing.T) {
			a := newSoftAuthenticator()
			path := writeConfig(t, Config{
				Enabled: true, Origin: testOrigin, Port: DefaultPort, UserID: []byte("u"), OwnerLogin: testLogin,
				Devices: []Device{{Name: "evil", NodeID: bindTo, NodeName: "x", Login: testLogin,
					Cred: webauthn.Credential{ID: a.id, PublicKey: a.cose(), AttestationType: "none"}}},
			})
			s, err := Load(path, Hooks{Tailnet: newFakeTailnet()}, quiet)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			res := make(chan error, 1)
			go func() { res <- s.Approve(ctx, "Send mail", "to: victim") }()
			id := waitPending(t, s, 1)[0]

			h := s.WebHandler()
			for _, addr := range []string{addrLoopback, addrSelf, addrSelfAlt} {
				forged := func(r *http.Request) {
					r.RemoteAddr = addr
					r.Header.Set("Tailscale-User-Login", testLogin)
				}
				if rec, st := do(t, h, "GET", "/api/state", nil, forged); rec.Code != http.StatusForbidden || st["pending"] != nil {
					t.Errorf("%s: state %d (pending leaked?)", addr, rec.Code)
				}
				if rec := approveFrom(t, h, a, "approve", id, addr); rec.Code != http.StatusForbidden {
					t.Errorf("%s: approve %d %s", addr, rec.Code, rec.Body)
				}
			}
			// The original PoC: a real loopback HTTP server, forged headers.
			srv := httptest.NewServer(h)
			defer srv.Close()
			req, _ := http.NewRequest("POST", srv.URL+"/api/auth/begin", strings.NewReader(`{"purpose":"approve","id":"`+id+`"}`))
			req.Header.Set("Tailscale-User-Login", "anything@forged")
			req.Header.Set("Origin", testOrigin)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("loopback PoC begin: %d", resp.StatusCode)
			}
			cancel()
			if err := <-res; err == nil {
				t.Fatal("approval granted")
			}
		})
	}
}

// --- H4 regression: the enrolment link leaks to a local process --------

func TestH4_EnrolFromMacRefused(t *testing.T) {
	s := newTestService(t, Hooks{})
	a := newSoftAuthenticator()
	for _, addr := range []string{addrLoopback, addrSelf, addrSelfAlt, addrStranger, addrTagged} {
		if rec, _ := enrollFrom(t, s, a, "iPhone", addr); rec.Code != http.StatusForbidden {
			t.Errorf("enrol from %s: %d", addr, rec.Code)
		}
	}
	// The PoC over a real loopback listener with forged headers.
	srv := httptest.NewServer(s.WebHandler())
	defer srv.Close()
	tok := newEnrollTok(t, s)
	req, _ := http.NewRequest("POST", srv.URL+"/api/enroll/begin", strings.NewReader(`{"token":"`+tok+`","name":"iPhone"}`))
	req.Header.Set("Tailscale-User-Login", "anything@forged")
	req.Header.Set("Origin", testOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("loopback PoC enrol: %d", resp.StatusCode)
	}
	if len(s.cfg.Devices) != 0 || s.cfg.OwnerLogin != "" {
		t.Fatalf("device enrolled from the Mac: %+v owner=%q", s.cfg.Devices, s.cfg.OwnerLogin)
	}
}

// Begin from the phone, finish from the Mac (the attacker races with the
// leaked token) → refused.
func TestH4_FinishFromOtherNodeRefused(t *testing.T) {
	s := newTestService(t, Hooks{})
	h := s.WebHandler()
	tok := newEnrollTok(t, s)
	_, opts := do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": "phone"}, from(addrPhone))
	rec, _ := do(t, h, "POST", "/api/enroll/finish?t="+tok, newSoftAuthenticator().create(t, opts), from(addrTablet))
	if rec.Code != http.StatusForbidden || len(s.cfg.Devices) != 0 {
		t.Fatalf("finish from another node: %d devices=%d", rec.Code, len(s.cfg.Devices))
	}
}

func TestH4_SecondMacApprovalDeclined(t *testing.T) {
	mac := &macPrompts{decline: true}
	s := newTestService(t, Hooks{MacApprove: mac.approve})
	rec, _ := enrollFrom(t, s, newSoftAuthenticator(), "Galaxy S24 Ultra", addrPhone)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("finish with declined Mac prompt: %d %s", rec.Code, rec.Body)
	}
	if len(s.cfg.Devices) != 0 || s.cfg.OwnerLogin != "" {
		t.Fatalf("device saved without the second Touch ID: %+v", s.cfg.Devices)
	}
	if p := mac.last(); !strings.Contains(p, "Add 'Galaxy S24 Ultra' (Tailscale node galaxy-s24, "+testLogin+")") {
		t.Errorf("prompt = %q", p)
	}
}

// One begin per link: a replay burns it, so the legit finish fails too.
func TestEnrollBeginOnce(t *testing.T) {
	s := newTestService(t, Hooks{})
	h := s.WebHandler()
	tok := newEnrollTok(t, s)
	legit := newSoftAuthenticator()
	_, opts := do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": "phone"}, nil)
	if rec, _ := do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": "attacker"}, from(addrTablet)); rec.Code != http.StatusForbidden {
		t.Errorf("second begin: %d", rec.Code)
	}
	if rec, _ := do(t, h, "POST", "/api/enroll/finish?t="+tok, legit.create(t, opts), nil); rec.Code != http.StatusForbidden {
		t.Errorf("finish after replayed begin: %d", rec.Code)
	}
	if len(s.cfg.Devices) != 0 {
		t.Error("device saved")
	}
}

func TestEnrollErrorsAreGeneric(t *testing.T) {
	s := newTestService(t, Hooks{})
	h := s.WebHandler()
	tok := newEnrollTok(t, s)
	do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": "phone"}, nil)
	rec, out := do(t, h, "POST", "/api/enroll/finish?t="+tok, map[string]any{"id": "x", "type": "public-key"}, nil)
	if rec.Code != http.StatusBadRequest || out["error"] != "enrolment failed" {
		t.Errorf("finish garbage: %d %s", rec.Code, rec.Body)
	}
}

func TestOneDevicePerNode(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy", addrPhone)
	if rec, _ := enrollFrom(t, s, newSoftAuthenticator(), "Galaxy 2", addrPhone); rec.Code != http.StatusConflict {
		t.Errorf("second device on the same node: %d", rec.Code)
	}
}

// --- node binding -------------------------------------------------------

func TestNodeBinding(t *testing.T) {
	s := newTestService(t, Hooks{})
	phone, tablet := newSoftAuthenticator(), newSoftAuthenticator()
	enrollDevice(t, s, phone, "Galaxy", addrPhone)
	enrollDevice(t, s, tablet, "iPad", addrTablet)
	_ = s.SetEnabled(true, "mac")
	h := s.WebHandler()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- s.Approve(ctx, "t", "b") }()
	id := waitPending(t, s, 1)[0]

	// The phone's passkey, used from the tablet's node → refused.
	if rec := approveFrom(t, h, phone, "approve", id, addrTablet); rec.Code != http.StatusForbidden {
		t.Errorf("phone credential from tablet node: %d %s", rec.Code, rec.Body)
	}
	// A session begun on the phone can't be finished from the tablet.
	_, begin := do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": "approve", "id": id}, from(addrPhone))
	if rec, _ := do(t, h, "POST", "/api/auth/finish?sid="+begin["sid"].(string), phone.get(t, begin["options"].(map[string]any), testOrigin), from(addrTablet)); rec.Code != http.StatusForbidden {
		t.Errorf("cross-node session finish: %d", rec.Code)
	}
	// Belt and braces: recordUse refuses a credential from another node.
	if _, ok := s.recordUse(&webauthn.Credential{ID: phone.id}, nodeTablet); ok {
		t.Error("recordUse accepted a cross-node credential")
	}
	select {
	case err := <-res:
		t.Fatalf("approval resolved: %v", err)
	default:
	}
	// The right node works.
	if rec := approveFrom(t, h, tablet, "approve", id, addrTablet); rec.Code != 200 {
		t.Fatalf("tablet approve: %d %s", rec.Code, rec.Body)
	}
	if err := <-res; err != nil {
		t.Fatal(err)
	}
}

// --- rate limits and bounds -----------------------------------------------

func TestMaxPending(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy", addrPhone)
	_ = s.SetEnabled(true, "mac")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < maxPending; i++ {
		go func() { _ = s.Approve(ctx, "t", "b") }()
	}
	waitPending(t, s, maxPending)
	start := time.Now()
	err := s.Approve(context.Background(), "t", "b")
	if !errors.Is(err, mcperrors.ErrUserCanceled) || !strings.Contains(err.Error(), "already waiting") || time.Since(start) > time.Second {
		t.Fatalf("6th approval: %v after %v", err, time.Since(start))
	}
}

func TestApprovalRateLimit(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy", addrPhone)
	_ = s.SetEnabled(true, "mac")
	s.mu.Lock()
	for i := 0; i < maxApprovalsPerMin; i++ {
		s.recent = append(s.recent, time.Now())
	}
	s.mu.Unlock()
	if err := s.Approve(context.Background(), "t", "b"); !errors.Is(err, mcperrors.ErrUserCanceled) || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("over the rate limit: %v", err)
	}
	s.mu.Lock()
	for i := range s.recent {
		s.recent[i] = time.Now().Add(-2 * time.Minute)
	}
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Approve(ctx, "t", "b"); err == nil || strings.Contains(err.Error(), "too many") {
		t.Fatalf("after the window: %v", err)
	}
}

func TestAuthSessionCap(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "d", addrPhone)
	h := s.WebHandler()
	for i := 0; i < 500; i++ {
		do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": "remote_on"}, nil)
	}
	if n := len(s.sessions); n > maxAuthSessions {
		t.Fatalf("sessions held: %d", n)
	}
	s.mu.Lock()
	for _, as := range s.sessions {
		as.created = time.Now().Add(-time.Hour)
	}
	s.pruneLocked()
	n := len(s.sessions)
	s.mu.Unlock()
	if n != 0 {
		t.Errorf("expired sessions not pruned: %d", n)
	}
	// A non-enrolled node can't create sessions at all.
	if rec, _ := do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": "remote_on"}, from(addrTablet)); rec.Code != http.StatusForbidden {
		t.Errorf("non-enrolled begin: %d", rec.Code)
	}
}

func TestNtfyDebounceAndToken(t *testing.T) {
	var (
		mu    sync.Mutex
		posts []string
	)
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts = append(posts, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer ntfy.Close()
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy", addrPhone)
	_ = s.SetEnabled(true, "mac")
	s.mu.Lock()
	s.cfg.NtfyServer, s.cfg.NtfyToken = ntfy.URL, "tk_secret"
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 3; i++ {
		go func() { _ = s.Approve(ctx, "t", "b") }()
	}
	waitPending(t, s, 3)
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 1 || posts[0] != "Bearer tk_secret" {
		t.Errorf("ntfy posts = %q (want one, with the bearer token)", posts)
	}
	if !s.Status().NtfyToken {
		t.Error("status doesn't report the token")
	}
}

// --- setup, TLS listener, parsing ------------------------------------------

func TestSetupDerivesOriginAndValidates(t *testing.T) {
	tn := newFakeTailnet()
	mac := &macPrompts{}
	s, err := Load(filepath.Join(t.TempDir(), "remote.json"), Hooks{Tailnet: tn, MacApprove: mac.approve}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctl := s.ControlHandler()
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		ctl.ServeHTTP(rec, httptest.NewRequest("POST", "/setup", strings.NewReader(body)))
		return rec
	}
	if rec := post(`{"origin":"https://evil.example‮/approve?x"}`); rec.Code != http.StatusBadRequest || mac.last() != "" {
		t.Errorf("bad origin: %d prompt=%q", rec.Code, mac.last())
	}
	tn.certErr = errors.New("HTTPS not enabled")
	if rec := post(`{}`); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "login.tailscale.com/admin/dns") || mac.last() != "" {
		t.Errorf("cert failure: %d %s", rec.Code, rec.Body)
	}
	tn.certErr = nil
	if rec := post(`{}`); rec.Code != 200 {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	if s.cfg.Origin != testOrigin || !strings.HasSuffix(mac.last(), "served at "+testRPID+":8443 on your tailnet.") {
		t.Errorf("origin=%q prompt=%q", s.cfg.Origin, mac.last())
	}
	for _, f := range []string{"cert.pem", "key.pem"} {
		fi, err := os.Stat(filepath.Join(tlsDir(s.path), f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, err, fi)
		}
	}
	if rec := post(`{"port":9443}`); rec.Code != 200 || s.cfg.Origin != "https://"+testRPID+":9443" || s.cfg.Port != 9443 {
		t.Errorf("port change: %d origin=%q", rec.Code, s.cfg.Origin)
	}
}

// The real listener: TLS on the "Tailscale" address (127.0.0.1 here),
// and a connection from this machine is refused as the Mac's own node.
func TestTLSListenerRefusesSelf(t *testing.T) {
	tn := newFakeTailnet()
	tn.self.IPv4 = "127.0.0.1"
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	path := writeConfig(t, Config{Origin: fmt.Sprintf("https://%s:%d", testRPID, port), Port: port, UserID: []byte("u")})
	s, err := Load(path, Hooks{Tailnet: tn}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv, _, err := s.startWeb()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/state", port))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.TLS == nil || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Errorf("self over TLS: %d tls=%v", resp.StatusCode, resp.TLS != nil)
	}
	if st := s.Status(); !st.Serving || st.Listen == "" {
		t.Errorf("status: %+v", st)
	}
}

func TestLoadDropsOldOrigin(t *testing.T) {
	path := writeConfig(t, Config{Origin: "https://" + testRPID, UserID: []byte("u")})
	s, err := Load(path, Hooks{Tailnet: newFakeTailnet()}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Status().Configured || s.cfg.Origin != "" || s.cfg.Port != DefaultPort {
		t.Errorf("old-style origin kept: %+v", s.Status())
	}
}

func TestParseTailscaleJSON(t *testing.T) {
	n, err := parseStatus([]byte(`{"BackendState":"Running","Self":{"ID":"nX","DNSName":"mac.t.ts.net.","TailscaleIPs":["fd7a::1","100.1.2.3"],"UserID":7},"User":{"7":{"LoginName":"me@x"}}}`))
	if err != nil || n.NodeID != "nX" || n.DNSName != "mac.t.ts.net" || n.IPv4 != "100.1.2.3" || n.Login != "me@x" {
		t.Errorf("status: %+v %v", n, err)
	}
	if _, err := parseStatus([]byte(`{"BackendState":"Stopped"}`)); err == nil {
		t.Error("stopped backend accepted")
	}
	p, err := parseWhoIs([]byte(`{"Node":{"StableID":"nP","Name":"phone.t.ts.net.","Tags":["tag:x"]},"UserProfile":{"LoginName":"me@x"}}`))
	if err != nil || p.NodeID != "nP" || p.NodeName != "phone" || p.Login != "me@x" || len(p.Tags) != 1 {
		t.Errorf("whois: %+v %v", p, err)
	}
	if _, err := parseWhoIs([]byte(`{}`)); err == nil {
		t.Error("empty whois accepted")
	}
}

func TestCleanName(t *testing.T) {
	if got := cleanName("  Gal‮axy​'s\nphone  "); got != "Galaxy’sphone" {
		t.Errorf("cleanName = %q", got)
	}
	if cleanName("​") != "Device" {
		t.Error("empty name not defaulted")
	}
}
