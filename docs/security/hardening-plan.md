# Security hardening plan (Oct 2026 assessment)

Source: the 2026-10-19 read-only assessment (live probes, log/Keychain/
network checks, govulncheck, four parallel code reviews with PoC tests).
Finding IDs (C1, H1–H7, M1–M8, L*) refer to that report.

## Threat model we harden against

1. **Hostile email content** (prompt injection, malformed attachments,
   spoofed subjects/filenames) — the primary threat.
2. **A semi-trusted LLM with a same-user shell** (Claude Desktop has
   shell-capable connectors). It can read/write user-owned files, talk to
   loopback sockets, send signals, run our CLI.
3. **Other tailnet devices / network observers** for Remote mode.

Out of scope for this round (architectural, tracked separately): a
same-user attacker replacing our binaries; OS-level Keychain biometric
ACL (needs a provisioned, Developer-ID-signed .app — H1/H3 full fix).

## Workstreams (parallel, disjoint files)

| WS | Scope | Findings | Primary files |
|----|-------|----------|---------------|
| 0 | Toolchain | M8 | go.mod (done: go 1.26.9, x/net 0.60.0) |
| A | Remote mode trust | C1, H4, M7, Remote lows | internal/remote/**, cmd/protonmcp/remote.go, helpers/menubar (remote section) |
| B | Mail actions & approval dialogs | H7, M3, M6 | internal/mcptools/{mail_state,drafts,send_prompt,prompt_helpers,mail_list,mail_search,triage,mail_read_thread,untrusted,attachment_send(display only)}.go, internal/mcp/middleware.go (SanitizePromptText), internal/sanitize/{text,filename}.go |
| C | Files, parsers, data at rest | H5, M1, M2, file lows | internal/mcptools/{filesafety,attachment_paths,attachment_save,attachment_text_extract}.go, internal/store/** (attachment-cache retention), backup exclusion |
| D | Gates, CLI, policy, daemon | H2, H6, M4, M5, daemon lows | cmd/protonmcp/{session,main,...}.go, internal/serve/{startup_gate,lockwatch,runtime(gate/umask/lock-purge only)}.go, internal/approval/path.go, internal/policy/**, internal/mcptools/rules*.go, cmd/protonmcpd, internal/redact |

## Key design decisions

- **Remote mode stops trusting loopback.** The web listener binds the
  Mac's Tailscale address with a `tailscale cert` TLS certificate instead
  of 127.0.0.1 + `tailscale serve`; every request's peer is resolved with
  `tailscale whois`. Requests from the Mac's own node are refused, and an
  enrolled device is bound to its Tailscale node ID. A local process (or a
  forged remote.json) therefore can't approve: it would need a passkey AND
  another tailnet node. Enrolment completion needs a second Mac Touch ID
  naming the device and node.
- **`mail_trash` really moves to Trash** (label), permanent delete stays
  denied.
- **Dialogs fail closed** when what must be shown doesn't fit; line/
  paragraph separators and invisible format characters are stripped.
- **Every Keychain load is Touch-ID-gated** (CLI included) and the helper
  is hash-verified on every exec, startup gate included.
- **Weakening policy needs Touch ID**: a reload that loosens anything vs.
  the embedded defaults is held until approved at the Mac.

## Testing strategy

1. **Regression tests from the assessment PoCs** — each confirmed finding
   gets a failing-before / passing-after test (PoCs live in the session
   scratchpad: sec-remote, sec-mcp, sec-files).
2. **Unit tests** per workstream; `go test ./...` and `go vet` green.
3. **govulncheck** clean for reachable code.
4. **Live re-probe** after deploy: loopback/forged-header probes, socket
   access, file permissions, log scan, cache retention.
5. **Independent verification review** of the merged result (fresh
   reviewers re-run the original attack scenarios).
6. **Manual checks needing the user**: Touch ID prompts (CLI gate, policy
   weakening), Remote enrolment from the Galaxy over Tailscale.

## Status

- [x] WS0 toolchain
- [x] WS-A Remote mode trust (merged 6f29dd7)
- [x] WS-B Mail actions & dialogs (merged 5f79e2c)
- [x] WS-C Files, parsers, data at rest (merged)
- [x] WS-D Gates, CLI, policy, daemon (merged 22abff7)
- [x] Merge + full test + govulncheck (0 vulnerabilities)
- [x] Deploy + live re-probe (b0d3d9b; H1 still open by design)
- [x] Verification review (2 independent reviewers): C1 partial → fixed
      (Remote never arms from disk), H6 latent rate_limit gap → fixed,
      M2/M3/M6 bypasses → round 2
- [x] Round 2: visible-text-only HTML (72 hiding techniques), filler
      chars, look-alike fence markers, full fencing; /Users anywhere +
      backup stores denied, ctime binding, more refused save names,
      extraction concurrency cap

## Open (needs a signed .app / later)
- H1 any same-user process can use the unlocked connector
- H3 Keychain item without OS biometric ACL
- folders_delete: confirm Proton's handling of contained messages
- @media hiding rules applied conservatively (may drop responsive copy)
