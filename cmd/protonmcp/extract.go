package main

import "github.com/just-an-oldsalt/proto-mcp/internal/mcptools"

// Hidden `protonmcp __extract-text <pdf|docx|xlsx> <max_chars>`: the
// sandboxed document-text child for mail_attachment_text when the MCP
// server runs as `protonmcp serve-stdio` (SECURITY H5; the daemon has
// the same hook). Runs from init, before main touches the session,
// Keychain or store, and exits there.
func init() {
	mcptools.MaybeRunExtractTextChild()
}
