package mcptools

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Files this server writes to disk come from untrusted email. Two
// shared defenses live here so every writer (attachment save, .eml
// export, ...) applies them identically.

// canonName folds a name (or path) the way the filesystem may when it
// compares names, so a denylist can't be dodged with a spelling the
// filesystem treats as equal but strings.ToLower doesn't: APFS is
// case-insensitive with Unicode case folding, so U+017F "ſ" (long s)
// opens the same file as "s" and U+212A KELVIN SIGN the same as "k".
// NFKC on both sides additionally collapses compatibility forms
// (fullwidth letters, ligatures) — a superset of what APFS equates,
// which only ever makes a denylist match more, never less. Apply it
// to BOTH the candidate and the list entries.
func canonName(s string) string {
	s = norm.NFKC.String(s)
	s = cases.Fold().String(s)
	return norm.NFKC.String(s)
}

func canonSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[canonName(n)] = true
	}
	return m
}

// blockedSaveNames are filenames an AI agent, IDE, shell or build tool
// treats as instructions, config or code when it opens / enters / builds
// the folder. Writing one from an email turns a single prompt injection
// into a persistent one (or code execution via hooks, tasks, test
// collection, install scripts), so writers refuse them outright.
// Matched after canonName.
var blockedSaveNames = canonSet(
	// AI agents.
	"claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md",
	".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md",
	// Editor / agent settings and MCP config.
	"settings.json", "settings.local.json", "tasks.json", "launch.json",
	".mcp.json", "mcp.json",
	// Shell / package-manager hooks.
	".envrc", ".npmrc", ".pypirc",
	// Build / test entry points that run on a routine command.
	"makefile", "gnumakefile", "conftest.py", "package.json", "pyproject.toml",
	"setup.py", "dockerfile",
	"build.rs", "justfile", "rakefile", "gemfile", "taskfile.yml", "taskfile.yaml",
	"cmakelists.txt", "meson.build", "build", "build.bazel", "workspace",
	"workspace.bazel", "module.bazel",
	"gradlew", "gradlew.bat", "build.gradle", "build.gradle.kts",
	"settings.gradle", "settings.gradle.kts", "pom.xml",
	// sanitize.Filename strips the leading dot, so both spellings.
	".pre-commit-config.yaml", "pre-commit-config.yaml",
)

// blockedSaveNamePatterns are filepath.Match patterns (after canonName)
// for test files a routine `pytest` / `go test` collects and runs.
var blockedSaveNamePatterns = canonList(
	"test_*.py", "*_test.py", "*_test.go",
)

// blockedSaveExts launch code (or install something) when opened from
// Finder or handed to Launch Services. Matched after canonName.
var blockedSaveExts = canonSet(
	".command", ".terminal", ".tool",
	".app", ".workflow", ".wflow", ".action", ".definition",
	".scpt", ".scptd", ".applescript", ".osax",
	".shortcut",
	".inetloc", ".webloc", ".fileloc", ".url", ".desktop",
	".pkg", ".mpkg", ".dmg", ".mobileconfig",
	".prefpane", ".saver", ".kext", ".qlgenerator", ".mdimporter",
	".jar",
	// Bundles / plug-ins a host app loads, and shell scripts.
	".bundle", ".plugin", ".xip", ".appex", ".xpc", ".component", ".vst", ".vst3",
	".sh", ".zsh", ".bash", ".fish", ".ps1",
)

// launchdDirs are directory names whose .plist files launchd loads at
// login: never a save target.
var launchdDirs = canonSet("launchagents", "launchdaemons")

// checkSaveName refuses names an agent would treat as instructions and
// extensions that execute on open. name is the final (sanitized) base
// filename. Matching is on canonName, so "AGENTſ.md" (which APFS opens
// as AGENTS.md) is refused like "AGENTS.md".
func checkSaveName(name string) error {
	c := canonName(filepath.Base(name))
	// sanitize.Filename drops trailing dots / spaces; trim here too so
	// a direct caller can't slip "Makefile." past the list.
	c = strings.TrimRight(c, ". ")
	if blockedSaveNames[c] {
		return fmt.Errorf("refusing to write %q: AI-agent / IDE / build config filenames can't be saved from email (rename it)", name)
	}
	for _, pat := range blockedSaveNamePatterns {
		if ok, _ := filepath.Match(pat, c); ok {
			return fmt.Errorf("refusing to write %q: test files a test runner would collect can't be saved from email (rename it)", name)
		}
	}
	if blockedSaveExts[filepath.Ext(c)] {
		return fmt.Errorf("refusing to write %q: files that run code when opened can't be saved from email", name)
	}
	return nil
}

// checkSaveDir refuses target directories under a hidden path
// component (.claude, .vscode, .git, ...): those hold tool config that
// executes or steers agents, and nothing legitimate needs email
// attachments written into them. LaunchAgents / LaunchDaemons are
// refused too (a .plist there runs at login).
func checkSaveDir(dir string) error {
	for _, part := range strings.Split(filepath.Clean(dir), string(filepath.Separator)) {
		c := canonName(part)
		if strings.HasPrefix(c, ".") && c != "." && c != ".." {
			return fmt.Errorf("refusing to write into hidden directory %q", dir)
		}
		if launchdDirs[c] {
			return fmt.Errorf("refusing to write into launchd directory %q", dir)
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
