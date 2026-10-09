package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
)

const (
	testOrigin = "https://mac.tail1234.ts.net"
	testRPID   = "mac.tail1234.ts.net"
	testLogin  = "owner@example.com"
)

var b64u = base64.RawURLEncoding

func newTestService(t *testing.T, hooks Hooks) *Service {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "remote.json"), hooks, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetOrigin(testOrigin); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// do sends a request as it would arrive from tailscale serve.
func do(t *testing.T, h http.Handler, method, path string, body any, mutate func(*http.Request)) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Tailscale-User-Login", testLogin)
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
		x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
		y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
		cose, _ := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		buf.Write(cose)
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

func enrollDevice(t *testing.T, s *Service, a *softAuthenticator, name string) {
	t.Helper()
	link, err := s.NewEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	tok := link[strings.Index(link, "#enroll=")+len("#enroll="):]
	h := s.WebHandler()
	rec, opts := do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": name}, nil)
	if rec.Code != 200 {
		t.Fatalf("enroll begin: %d %s", rec.Code, rec.Body)
	}
	rec, _ = do(t, h, "POST", "/api/enroll/finish?t="+tok, a.create(t, opts), nil)
	if rec.Code != 200 {
		t.Fatalf("enroll finish: %d %s", rec.Code, rec.Body)
	}
	// Single use.
	if rec, _ := do(t, h, "POST", "/api/enroll/begin", map[string]string{"token": tok, "name": "again"}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("reused enrolment token: %d", rec.Code)
	}
}

func TestGuard(t *testing.T) {
	s := newTestService(t, Hooks{})
	h := s.WebHandler()
	if rec, _ := do(t, h, "GET", "/api/state", nil, func(r *http.Request) { r.Header.Del("Tailscale-User-Login") }); rec.Code != http.StatusForbidden {
		t.Errorf("no tailnet identity: %d", rec.Code)
	}
	if rec, _ := do(t, h, "POST", "/api/remote_off", nil, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST: %d", rec.Code)
	}
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy")
	if rec, _ := do(t, h, "GET", "/api/state", nil, func(r *http.Request) { r.Header.Set("Tailscale-User-Login", "intruder@example.com") }); rec.Code != http.StatusForbidden {
		t.Errorf("non-owner identity after enrolment: %d", rec.Code)
	}
	rec, _ := do(t, h, "GET", "/", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("index: %d csp=%q", rec.Code, rec.Header().Get("Content-Security-Policy"))
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
	s := newTestService(t, Hooks{OnChange: func() { changes++ }})
	a := newSoftAuthenticator()
	enrollDevice(t, s, a, "Galaxy S24 Ultra")
	if err := s.SetEnabled(true, "mac"); err != nil {
		t.Fatal(err)
	}
	if !s.Active() || changes == 0 {
		t.Fatalf("active=%v changes=%d", s.Active(), changes)
	}
	h := s.WebHandler()

	result := make(chan error, 1)
	go func() { result <- s.Approve(context.Background(), "Approve mail_send?", "To: bo@example.com\nSubject: Hi") }()

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

	_, begin = do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": "approve", "id": id}, nil)
	rec, out := do(t, h, "POST", "/api/auth/finish?sid="+begin["sid"].(string), a.get(t, begin["options"].(map[string]any), testOrigin), nil)
	if rec.Code != 200 || out["result"] != "approved" {
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
	enrollDevice(t, s, newSoftAuthenticator(), "iPad")
	_ = s.SetEnabled(true, "mac")
	h := s.WebHandler()

	result := make(chan error, 1)
	go func() { result <- s.Approve(context.Background(), "t", "b") }()
	var id string
	for i := 0; i < 100 && id == ""; i++ {
		s.mu.Lock()
		for k := range s.pending {
			id = k
		}
		s.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
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
	enrollDevice(t, s, a, "Galaxy")
	h := s.WebHandler()
	_, begin := do(t, h, "POST", "/api/auth/begin", map[string]string{"purpose": "remote_on"}, nil)
	rec, _ := do(t, h, "POST", "/api/auth/finish?sid="+begin["sid"].(string), a.get(t, begin["options"].(map[string]any), testOrigin), nil)
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
	req := httptest.NewRequest("POST", "/enroll", nil)
	rec := httptest.NewRecorder()
	ctl.ServeHTTP(rec, req)
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

func TestOriginChangeDropsDevices(t *testing.T) {
	s := newTestService(t, Hooks{})
	enrollDevice(t, s, newSoftAuthenticator(), "Galaxy")
	_ = s.SetEnabled(true, "mac")
	if err := s.SetOrigin("https://other.tail1234.ts.net"); err != nil {
		t.Fatal(err)
	}
	if s.Active() || len(s.cfg.Devices) != 0 || s.cfg.OwnerLogin != "" {
		t.Errorf("origin change kept devices/enabled: %+v", s.Status())
	}
	if err := s.SetOrigin("http://insecure.example"); err == nil {
		t.Error("accepted non-https origin")
	}
}
