package mcptools

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckSaveName(t *testing.T) {
	for _, bad := range []string{"CLAUDE.md", "agents.md", "settings.json", "tasks.json", "run.command", "x.app", "a.terminal"} {
		if checkSaveName(bad) == nil {
			t.Errorf("checkSaveName(%q) = nil, want refusal", bad)
		}
	}
	for _, ok := range []string{"statement.pdf", "contract.docx", "notes.md", "data.json"} {
		if err := checkSaveName(ok); err != nil {
			t.Errorf("checkSaveName(%q) = %v, want ok", ok, err)
		}
	}
}

func TestCheckSaveDir(t *testing.T) {
	if checkSaveDir("/Users/x/Documents/Claude/.claude") == nil {
		t.Error("hidden dir accepted")
	}
	if err := checkSaveDir("/Users/x/Documents/Claude/project"); err != nil {
		t.Errorf("normal dir refused: %v", err)
	}
}

func TestSetQuarantine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.pdf")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setQuarantine(p); err != nil {
		t.Fatalf("setQuarantine: %v", err)
	}
	buf := make([]byte, 128)
	n, err := unix.Getxattr(p, "com.apple.quarantine", buf)
	if err != nil || n == 0 {
		t.Fatalf("quarantine xattr missing: n=%d err=%v", n, err)
	}
}
