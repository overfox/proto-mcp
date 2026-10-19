package main

import "github.com/just-an-oldsalt/proto-mcp/internal/mcptools"

// Hidden `protonmcpd __extract-text <pdf|docx|xlsx> <max_chars>`:
// mail_attachment_text re-executes this binary to parse untrusted
// documents in a resource-limited child (SECURITY H5). The dispatch
// runs from init — before main, so before the umask, logging, the
// integrity check, the store, the Keychain or the session are touched —
// and exits there; in the normal daemon it only marks the subcommand
// as available.
func init() {
	mcptools.MaybeRunExtractTextChild()
}
