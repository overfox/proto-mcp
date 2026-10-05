package proton

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/go-resty/resty/v2"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// ErrSessionExpired wraps the family of errors that mean "the stored
// refresh token is no longer valid — the user must re-authenticate".
// Callers detect this with errors.Is and respond by wiping the
// Keychain entry and falling back to a full Login.
var ErrSessionExpired = errors.New("proton: stored session expired or revoked")

// ResumeArgs is the minimum state needed to rebuild a Session without
// running the full SRP + 2FA + salt-fetch flow. All fields are
// populated from a Keychain blob.
type ResumeArgs struct {
	Email         string
	UID           string
	AccessToken   string // current access token (may still be valid)
	RefreshToken  string // refresh token (single-use on Proton's side)
	SaltedKeyPass secret.Secret
}

// Resume rebuilds a Session from a previously-stored access + refresh
// token pair and salted mailbox password.
//
// Implementation note (this was hard to find):
//
// Proton's refresh tokens are SINGLE-USE — calling /auth/v4/refresh
// rotates both the access and refresh tokens, and the old refresh
// token becomes invalid immediately. proton-bridge gets away with
// NewClientWithRefresh because they keep one Client alive for the
// entire daemon lifetime and only rotate when an access token actually
// expires.
//
// Our model is one process per CLI invocation. If every invocation
// called NewClientWithRefresh, we'd burn a refresh token every time;
// the first whoami would work (it consumed the login-issued refresh
// token), and the second would 400 because the rotated token from
// the first refresh is itself one-time-use that the first whoami
// already burned implicitly... well, more accurately: there's a
// race in our persistence that no amount of patching can solve as
// long as we keep refreshing.
//
// Resume now builds a Client with mgr.NewClient(uid, acc, ref) — no
// refresh call. The SDK's auto-refresh-on-401 path inside Client.do
// only fires when the access token has actually expired. If our
// stored access token is still valid (the common case for a tight
// CLI loop), no refresh happens, no token rotation, nothing to
// persist.
//
// On expiry the auto-refresh fires, the AuthHandler captures the
// rotated bundle, and the keystore-sync OnAuthUpdate hook writes the
// new pair back to disk so the next process can pick up where we
// left off.
//
// Resume does NOT retry on network errors — a single attempt is the
// right policy. The caller (CLI shell) is the natural retry
// boundary; a buggy MCP client looping on auth failure should not
// hammer Proton's anti-abuse.
func Resume(ctx context.Context, mgr *gpa.Manager, args ResumeArgs) (*Session, error) {
	if args.UID == "" || args.RefreshToken == "" {
		return nil, errors.New("proton: resume requires UID + RefreshToken")
	}
	if args.SaltedKeyPass.Empty() {
		return nil, errors.New("proton: resume requires saltedKeyPass — re-login required")
	}

	client := mgr.NewClient(args.UID, args.AccessToken, args.RefreshToken)

	// Build the Session and install the AuthHandler IMMEDIATELY, before
	// any API call. If GetUser / GetAddresses below trigger the
	// auto-refresh-on-401 path (because the stored access token has
	// expired), the SDK fires AuthHandler with the rotated bundle —
	// our handler keeps Session.AccessToken / RefreshToken current and
	// the OnAuthUpdate hook (wired by the caller) writes the new pair
	// back to the Keychain.
	sess := &Session{
		Client:       client,
		Email:        args.Email,
		UID:          args.UID,
		AccessToken:  args.AccessToken,
		RefreshToken: args.RefreshToken,
		// Deep copy: a secret.Secret struct copy shares its backing
		// array, and the caller (session.TryResume) Zero()s its copy on
		// return. Sharing left this session holding all-zero key
		// material of full length; the next token refresh then re-saved
		// those zeros to the Keychain, and the following resume failed
		// with "private key checksum failure".
		SaltedKeyPass: secret.New(args.SaltedKeyPass.Bytes()),
	}
	sess.installAuthHandler()

	closeAndWrap := func(format string, vals ...any) error {
		// Close locally only; never revoke the server session here. A
		// resume can fail for reasons that say nothing about the stored
		// credentials (a network blip, a transient API error), and a
		// revoke turns those into a forced re-login. It also destroys
		// the evidence when key unlock fails. Explicit logout is the
		// only path that revokes (Session.CloseAndRevoke).
		client.Close()
		return fmt.Errorf(format, vals...)
	}

	user, err := client.GetUser(ctx)
	if err != nil {
		// If the access token had expired AND the auto-refresh failed
		// (refresh token is dead), the SDK surfaces a 401 / 422(10013)
		// here. Map those to ErrSessionExpired so the CLI clears the
		// Keychain and re-prompts cleanly; 429 / 5xx map to ErrTransient
		// so the daemon waits them out instead.
		if sentinel := classifyResumeErr(err); sentinel != nil {
			return nil, closeAndWrap("%w: resume get user: %w", sentinel, err)
		}
		return nil, closeAndWrap("resume get user: %w", err)
	}
	addrs, err := client.GetAddresses(ctx)
	if err != nil {
		if sentinel := classifyResumeErr(err); sentinel != nil {
			return nil, closeAndWrap("%w: resume get addresses: %w", sentinel, err)
		}
		return nil, closeAndWrap("resume get addresses: %w", err)
	}

	userKR, addrKRs, err := gpa.Unlock(user, addrs, args.SaltedKeyPass.Bytes(), nil)
	if err != nil {
		return nil, closeAndWrap("resume unlock: %w — keystore blob may be stale, run `protonmcp login` again", err)
	}

	sess.User = user
	sess.Addresses = addrs
	sess.UserKR = userKR
	sess.AddrKRs = addrKRs
	return sess, nil
}

// ErrTransient marks a resume failure the server says is temporary
// (rate limiting, 5xx). The stored credentials are fine; callers should
// back off and retry instead of wiping the Keychain or demanding a
// re-login.
var ErrTransient = errors.New("proton: transient server error")

// isAuthExpired distinguishes "token dead" from other failure modes
// (network down, rate limiting, server 500, etc.) so callers know
// whether to wipe the keystore or retry later.
//
// Only two shapes mean the stored refresh token is genuinely dead:
//
//   - HTTP 401 (classic unauthorized — the auto-refresh-on-401 path
//     itself failed to recover)
//   - HTTP 422 with Code=10013 ("Invalid refresh token") — what
//     /auth/v4/refresh returns once the token was rotated or revoked
//
// Everything else — notably 429 (rate limited) and any other 4xx —
// used to be lumped in as "expired", and TryResume then DELETED the
// Keychain entry on a transient throttle, forcing a full re-login.
// Wiping is irreversible, so we only do it on an unambiguous signal.
func isAuthExpired(err error) bool {
	status, code, ok := responseStatus(err)
	if !ok {
		return false
	}
	switch status {
	case http.StatusUnauthorized:
		return true
	case http.StatusUnprocessableEntity:
		return code == gpa.AuthRefreshTokenInvalid
	}
	return false
}

// isTransient reports a server answer that says "try again later":
// 429 Too Many Requests or any 5xx.
func isTransient(err error) bool {
	status, _, ok := responseStatus(err)
	if !ok {
		return false
	}
	return status == http.StatusTooManyRequests || status >= 500
}

// responseStatus digs the HTTP status (and Proton API code, when the
// body parsed) out of an SDK error chain. go-proton-api surfaces API
// failures as *gpa.APIError, sometimes behind a *resty.ResponseError;
// either may be wrapped by fmt.Errorf. ok=false means the error carried
// no HTTP response (transport failure, local error).
func responseStatus(err error) (status int, code gpa.Code, ok bool) {
	var apiErr *gpa.APIError
	if errors.As(err, &apiErr) && apiErr.Status != 0 {
		return apiErr.Status, apiErr.Code, true
	}
	var respErr *resty.ResponseError
	if errors.As(err, &respErr) && respErr.Response != nil && respErr.Response.RawResponse != nil {
		return respErr.Response.StatusCode(), 0, true
	}
	return 0, 0, false
}

// classifyResumeErr maps an SDK error from the resume calls onto the
// sentinel callers act on: ErrSessionExpired (wipe + re-login),
// ErrTransient (retry later), or nil (unclassified — surface as-is).
func classifyResumeErr(err error) error {
	switch {
	case isAuthExpired(err):
		return ErrSessionExpired
	case isTransient(err):
		return ErrTransient
	}
	return nil
}
