package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrWeakeningNotApproved is returned (wrapped) when an override that
// loosens the embedded defaults was not approved: the user declined
// the Touch ID prompt, the prompt failed, or no approver is available.
var ErrWeakeningNotApproved = errors.New("policy override loosens the built-in defaults and was not approved with Touch ID")

// Gate approves an override that loosens the defaults. weakenings is
// the human-readable list (computeWeakenings); contentHash binds the
// approval to the exact override bytes (ContentHash). Returning nil
// lets the override take effect.
type Gate func(ctx context.Context, weakenings []string, contentHash string) error

// ContentHash is the hex SHA-256 of the override file's bytes.
func ContentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ApprovalStore remembers the content hash of the last weakening the
// user approved with Touch ID, so an unchanged policy.yaml (daemon
// restart, a reload with no edit, Keep Alive toggled off and back on)
// doesn't re-prompt.
//
// Integrity: the file (policy.approved, 0600) holds the hash plus an
// HMAC-SHA256 over it, keyed by a random 32-byte key kept in its own
// Keychain item (see keystore.PolicyHMACKey). A same-user process can
// write the file but can't mint a valid MAC for its own hash without
// reading the key — and reading the Keychain is outside the file-write
// capability this defends against. A missing / mismatched MAC simply
// means "not approved" → re-prompt.
type ApprovalStore struct {
	Path string
	// Key returns the HMAC key; create=true generates and stores it on
	// first use.
	Key func(create bool) ([]byte, error)
}

const approvedFileVersion = "v1"

// DefaultApprovalPath is policy.approved next to policy.yaml.
func DefaultApprovalPath() (string, error) {
	p, err := DefaultOverridePath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "policy.approved"), nil
}

func approvalMAC(key []byte, hash string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("protonmcp-policy-approval-" + approvedFileVersion + "\x00"))
	m.Write([]byte(hash))
	return m.Sum(nil)
}

// Approved reports whether hash is the recorded, MAC-valid approval.
// Never creates the key.
func (s ApprovalStore) Approved(hash string) bool {
	if s.Path == "" || s.Key == nil || hash == "" {
		return false
	}
	f, err := os.OpenFile(s.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != approvedFileVersion || fields[1] != hash {
		return false
	}
	got, err := hex.DecodeString(fields[2])
	if err != nil {
		return false
	}
	key, err := s.Key(false)
	if err != nil || len(key) == 0 {
		return false
	}
	return hmac.Equal(got, approvalMAC(key, hash))
}

// Record stores hash as the approved weakening (atomic, 0600).
func (s ApprovalStore) Record(hash string) error {
	if s.Path == "" || s.Key == nil {
		return errors.New("policy: approval store not configured")
	}
	key, err := s.Key(true)
	if err != nil {
		return fmt.Errorf("policy approval key: %w", err)
	}
	line := fmt.Sprintf("%s %s %s\n", approvedFileVersion, hash, hex.EncodeToString(approvalMAC(key, hash)))
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".policy-approved-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(line); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.Path)
}

// TouchIDGate returns the daemon's weakening gate: an override whose
// hash matches the stored approval passes silently; otherwise prompt
// (the Mac's own Touch ID — never Remote mode) lists the loosenings
// and, on approval, the hash is recorded. A declined prompt returns
// ErrWeakeningNotApproved.
func TouchIDGate(store ApprovalStore, prompt func(ctx context.Context, title, body string) error, logger *slog.Logger) Gate {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, ws []string, hash string) error {
		if store.Approved(hash) {
			logger.Info("policy override loosens defaults; previously approved with Touch ID",
				"weakenings", len(ws))
			return nil
		}
		if prompt == nil {
			return fmt.Errorf("%w: no Touch ID approver available", ErrWeakeningNotApproved)
		}
		title, body := WeakeningPrompt(ws)
		if err := prompt(ctx, title, body); err != nil {
			logger.Warn("policy weakening not approved", "weakenings", strings.Join(ws, "; "), "err", err.Error())
			return fmt.Errorf("%w: %v", ErrWeakeningNotApproved, err)
		}
		if err := store.Record(hash); err != nil {
			// Approved for this load; the next load re-prompts.
			logger.Warn("could not record policy approval; the next reload will ask again", "err", err.Error())
		}
		logger.Info("policy weakening approved with Touch ID", "weakenings", strings.Join(ws, "; "))
		return nil
	}
}
