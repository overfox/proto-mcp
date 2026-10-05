package mcptools

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Files this server writes to disk come from untrusted email. Two
// shared defenses live here so every writer (attachment save, .eml
// export, ...) applies them identically.

// blockedSaveNames are filenames an AI agent or IDE treats as
// instructions or config when it opens the folder. Writing one from an
// email turns a single prompt injection into a persistent one (or code
// execution via hooks/tasks), so writers refuse them outright.
var blockedSaveNames = map[string]bool{
	"claude.md":           true,
	"claude.local.md":     true,
	"agents.md":           true,
	"gemini.md":           true,
	".cursorrules":        true,
	".windsurfrules":      true,
	"settings.json":       true,
	"settings.local.json": true,
	"tasks.json":          true,
	"launch.json":         true,
	".mcp.json":           true,
	"mcp.json":            true,
	"makefile":            true,
	".envrc":              true,
}

// blockedSaveExts launch code when double-clicked in Finder.
var blockedSaveExts = map[string]bool{
	".command":     true,
	".terminal":    true,
	".app":         true,
	".tool":        true,
	".workflow":    true,
	".scpt":        true,
	".scptd":       true,
	".applescript": true,
	".inetloc":     true,
	".webloc":      true,
	".fileloc":     true,
	".pkg":         true,
	".mpkg":        true,
}

// checkSaveName refuses names an agent would treat as instructions and
// extensions that execute on open. name is the final (sanitized) base
// filename.
func checkSaveName(name string) error {
	lower := strings.ToLower(filepath.Base(name))
	if blockedSaveNames[lower] {
		return fmt.Errorf("refusing to write %q: AI-agent / IDE config filenames can't be saved from email (rename it)", name)
	}
	if blockedSaveExts[filepath.Ext(lower)] {
		return fmt.Errorf("refusing to write %q: files that run code when opened can't be saved from email", name)
	}
	return nil
}

// checkSaveDir refuses target directories under a hidden path
// component (.claude, .vscode, .git, ...): those hold tool config that
// executes or steers agents, and nothing legitimate needs email
// attachments written into them.
func checkSaveDir(dir string) error {
	for _, part := range strings.Split(filepath.Clean(dir), string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return fmt.Errorf("refusing to write into hidden directory %q", dir)
		}
	}
	return nil
}

// setQuarantine tags a written file the way a browser download is
// tagged, so Gatekeeper warns before anything from it runs.
// Best-effort: a failure is returned for logging, never fatal.
func setQuarantine(path string) error {
	val := fmt.Sprintf("0081;%08x;protonmcp;", time.Now().Unix())
	return unix.Setxattr(path, "com.apple.quarantine", []byte(val), 0)
}
