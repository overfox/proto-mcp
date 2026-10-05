package proton

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"
)

func apiErr(status int, code gpa.Code) error {
	// Same shape go-proton-api produces: "<status> GET /route: <APIError>".
	return fmt.Errorf("%d GET /core/v4/users: %w", status, &gpa.APIError{Status: status, Code: code, Message: "x"})
}

func respErr(status int, inner error) error {
	return &resty.ResponseError{
		Response: &resty.Response{RawResponse: &http.Response{StatusCode: status}},
		Err:      inner,
	}
}

// Only an unambiguous dead-token signal may map to ErrSessionExpired —
// that sentinel makes TryResume DELETE the Keychain entry. A 429 used to
// match (any 4xx did) and wiped the session on a rate limit.
func TestClassifyResumeErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"401", apiErr(401, 0), ErrSessionExpired},
		{"422 invalid refresh token", apiErr(422, gpa.AuthRefreshTokenInvalid), ErrSessionExpired},
		{"422 via refresh path", fmt.Errorf("failed to refresh auth, de-auth: %w",
			respErr(422, apiErr(422, gpa.AuthRefreshTokenInvalid))), ErrSessionExpired},
		{"422 other code", apiErr(422, 2001), nil},
		{"400", apiErr(400, 0), nil},
		{"403", apiErr(403, 0), nil},
		{"429", apiErr(429, 0), ErrTransient},
		{"429 via refresh path", fmt.Errorf("failed to refresh auth, server issues: %w",
			respErr(429, apiErr(429, 0))), ErrTransient},
		{"500", apiErr(500, 0), ErrTransient},
		{"503 resty only", respErr(503, errors.New("unavailable")), ErrTransient},
		{"401 resty only", respErr(401, errors.New("unauthorized")), ErrSessionExpired},
		{"no response", errors.New("dial tcp: connection refused"), nil},
		{"resty without raw response", &resty.ResponseError{Response: &resty.Response{}, Err: errors.New("x")}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyResumeErr(tc.err)
			if got != tc.want {
				t.Errorf("classifyResumeErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestSessionCloseKeepsClient(t *testing.T) {
	m := gpa.New()
	defer m.Close()
	s := &Session{Client: m.NewClient("uid", "acc", "ref")}
	if s.Closed() {
		t.Fatal("fresh session reports Closed")
	}
	s.Close()
	if !s.Closed() {
		t.Fatal("Closed() = false after Close")
	}
	if s.Client == nil {
		t.Fatal("Close nilled Client; concurrent holders would nil-deref (lock-during-sync crash)")
	}
	s.Close() // idempotent
	var nilSess *Session
	if !nilSess.Closed() {
		t.Fatal("nil session should report Closed")
	}
}
