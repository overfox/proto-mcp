package keystore

import (
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// A key password wiped in place keeps its length, so the empty-check
// alone let all-zero key material reach the Keychain. Both guards
// return before any Keychain access, so this test touches no real
// credentials.
func TestSaveRefusesZeroedKeyPass(t *testing.T) {
	err := Save(Live{
		Email:         "me@proton.me",
		UID:           "uid",
		RefreshToken:  "refresh",
		SaltedKeyPass: secret.New(make([]byte, 32)),
	})
	if err == nil || !strings.Contains(err.Error(), "zeroed SaltedKeyPass") {
		t.Fatalf("Save with all-zero key password: err = %v, want zeroed-key refusal", err)
	}
}
