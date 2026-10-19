package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"

	keychain "github.com/keybase/go-keychain"
)

// PolicyHMACAccount is the Keychain account (under Service) holding
// the random key that authenticates policy.approved — the record of
// the last policy weakening the user approved with Touch ID (SECURITY
// H6). Kept in its own item so it never travels with the session blob.
const PolicyHMACAccount = "policy-hmac"

const policyHMACLabel = "Proton MCP policy approval key"

// PolicyHMACKey returns the 32-byte policy-approval HMAC key. With
// create=true a missing key is generated (crypto/rand) and stored;
// with create=false a missing key is an error (callers treat that as
// "nothing approved").
func PolicyHMACKey(create bool) ([]byte, error) {
	data, err := keychain.GetGenericPassword(Service, PolicyHMACAccount, "", "")
	if err != nil {
		return nil, fmt.Errorf("keychain get: %w", err)
	}
	if len(data) == 32 {
		return data, nil
	}
	if !create {
		return nil, errors.New("keystore: no policy approval key")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate policy key: %w", err)
	}
	item := keychain.NewGenericPassword(Service, PolicyHMACAccount, policyHMACLabel, key, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	err = keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		// Present but malformed (wrong length): replace it.
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(Service)
		query.SetAccount(PolicyHMACAccount)
		update := keychain.NewItem()
		update.SetData(key)
		err = keychain.UpdateItem(query, update)
	}
	if err != nil {
		return nil, fmt.Errorf("keychain store policy key: %w", err)
	}
	return key, nil
}
