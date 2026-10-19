package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
)

// H6: `policy show` prints every field and the weakenings with their
// approval status, and shows an unapproved weakening as not in force.
func TestShowPolicy_WeakeningsAndStatus(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("keep_alive: true\ntools:\n  labels_create: {decision: allow}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	store := policy.ApprovalStore{
		Path: filepath.Join(dir, "policy.approved"),
		Key: func(create bool) ([]byte, error) {
			if !create && key == nil {
				return nil, errors.New("none")
			}
			return key, nil
		},
	}

	var out bytes.Buffer
	if err := showPolicy(context.Background(), &out, p, store); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"keep_alive: false", "idle_lock_minutes:", "max_attachment_bytes:",
		"attachment_path_allowlist:", "NOT approved", "labels_create: prompt → allow", "keep_alive: on"} {
		if !strings.Contains(s, want) {
			t.Errorf("show output missing %q:\n%s", want, s)
		}
	}

	// Once approved, show reports it and the override is in force.
	_, hash, _ := policy.AnalyzeOverride(p)
	if err := store.Record(hash); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := showPolicy(context.Background(), &out, p, store); err != nil {
		t.Fatal(err)
	}
	s = out.String()
	if !strings.Contains(s, "approved with Touch ID") || !strings.Contains(s, "keep_alive: true") {
		t.Errorf("approved show output:\n%s", s)
	}
}
