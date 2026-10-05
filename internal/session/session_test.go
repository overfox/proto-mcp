package session

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	protonclient "github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// TestLoginRequiredMatchesSentinel — D44 depends on protonmcpd being
// able to errors.Is-match every "a human must run `protonmcp login`"
// failure. Guard the wrapping contract so a refactor that drops the
// %w doesn't silently turn clean exits back into crash loops.
func TestLoginRequiredMatchesSentinel(t *testing.T) {
	cases := []error{
		loginRequired(noStoredSessionMsg),
		loginRequired("stored session unusable (%v) — run `protonmcp logout && protonmcp login` "+
			"from a terminal to refresh credentials", errors.New("boom")),
	}
	for _, err := range cases {
		if !errors.Is(err, ErrLoginRequired) {
			t.Errorf("errors.Is(%q, ErrLoginRequired) = false; want true", err)
		}
	}
}

// TestLoginRequiredKeepsRemediationText — the message is what the
// operator sees in daemon.log; it must keep pointing at the fix.
func TestLoginRequiredKeepsRemediationText(t *testing.T) {
	err := loginRequired("stored session unusable (%v) — run `protonmcp logout && protonmcp login` "+
		"from a terminal to refresh credentials", errors.New("boom"))
	if !strings.Contains(err.Error(), "protonmcp logout && protonmcp login") {
		t.Errorf("remediation text missing from %q", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("underlying cause missing from %q", err)
	}
}

// 429 / 5xx during resume are transient: AcquireResumeOnly must report
// ErrNetworkUnavailable (protonmcpd retries) — not ErrLoginRequired
// (clean exit, daemon dead until a human intervenes).
func TestClassifyResumeFailure(t *testing.T) {
	transient := fmt.Errorf("%w: resume get user: 429 Too Many Requests", protonclient.ErrTransient)
	if err := classifyResumeFailure(transient); !errors.Is(err, ErrNetworkUnavailable) || errors.Is(err, ErrLoginRequired) {
		t.Errorf("transient: got %v, want ErrNetworkUnavailable only", err)
	}
	expired := fmt.Errorf("%w: resume get user: 401", protonclient.ErrSessionExpired)
	if err := classifyResumeFailure(expired); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("expired: got %v, want ErrLoginRequired", err)
	}
	if err := classifyResumeFailure(keystore.ErrNotFound); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("not found: got %v, want ErrLoginRequired", err)
	}
}
