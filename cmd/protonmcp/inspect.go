package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
)

// runInspect prints the SHAPE of the current Keychain blob (presence
// and lengths of each field, never any of their characters) so you can
// verify whether persistSession is actually updating it across
// subcommand calls.
//
// Diagnostic only — not a stable interface.
//
// SECURITY B-11 / H2: still gated behind PROTONMCP_DEBUG=1, and the
// Keychain read goes through the same Touch ID gate as every other CLI
// session load. It used to print 12–16-char prefixes of the access /
// refresh tokens and cookie values; it now prints none.
func runInspect(ctx context.Context, _ []string) error {
	if os.Getenv("PROTONMCP_DEBUG") == "" {
		return fmt.Errorf(
			"inspect reads the stored session — set PROTONMCP_DEBUG=1 to acknowledge and re-run")
	}
	stored, err := loadStoredSession(ctx, "inspect")
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			fmt.Println("(no session stored — run `protonmcp login`)")
			return nil
		}
		return err
	}
	// SECURITY B-3. Inspect doesn't hand ownership of the secret
	// material to a Session that would zero it on Close, so do it
	// here.
	defer stored.Zero()

	fmt.Println("Keychain blob contents:")
	fmt.Printf("  Email:        %s\n", stored.Email)
	fmt.Printf("  UID:          %s\n", describeSecret(stored.UID))
	fmt.Printf("  AccessToken:  %s\n", describeSecret(stored.AccessToken))
	fmt.Printf("  RefreshToken: %s\n", describeSecret(stored.RefreshToken))
	fmt.Printf("  SaltedKeyPass: %d bytes\n", len(stored.SaltedKeyPass.Bytes()))
	fmt.Printf("  Cookies:      %d cookie(s)\n", len(stored.Cookies))
	for i, c := range stored.Cookies {
		fmt.Printf("    [%d] %s = %s  (domain=%q path=%q)\n",
			i, c.Name, describeSecret(c.Value), c.Domain, c.Path)
	}
	return nil
}

// describeSecret reports presence + length only — no characters of the
// value, not even a prefix.
func describeSecret(s string) string {
	if s == "" {
		return "(empty)"
	}
	return fmt.Sprintf("set (len=%d)", len(s))
}
