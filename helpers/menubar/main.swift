// protonmcp-menubar — NSStatusItem indicator + kill switch for protonmcpd.
//
// Lives in the macOS menu bar (next to the clock) and shows, at a glance,
// what the MCP daemon is doing:
//
//   🟢  daemon running, session unlocked (Claude has access)
//   🔵  in use — a tool call completed within the last 5 s
//   🟠  connecting — daemon up but no session yet (starting / offline)
//   🟡  daemon running but LOCKED (screen-lock / idle / manual lock)
//   ⚪  daemon not running (crashed, stopped, or its state file is stale)
//       but launchd job enabled
//   🔴  KILL SWITCH engaged — launchd job disabled + booted out; Claude
//       cannot reach the socket until re-enabled from this menu
//
// The kill switch uses `launchctl disable` + `bootout`, so it survives
// reboots: the daemon will not come back until "Switch On" runs
// `launchctl enable` + `bootstrap`. Re-enabling triggers protonmcpd's
// Touch ID startup gate, so turning access back on always costs a
// biometric.
//
// No sockets are opened and no MCP calls are made: state is derived
// passively from `launchctl print-disabled` and the daemon's state file
// (state.json — written atomically on every transition plus a 30 s
// heartbeat). Daemons that predate state.json are still handled by the
// old heuristics (pgrep + daemon.log transition markers + audit-log
// growth). This keeps the indicator itself out of the audit trail and
// out of the daemon's peer-cred path.
//
// Signals (Lock Now → SIGUSR1, Connect/Unlock → SIGUSR2) are only sent
// to a PID whose executable is verified (proc_pidpath) to be the
// protonmcpd installed next to this helper.

import AppKit
import Darwin
import Foundation

let daemonLabel = "zone.dort.protonmcpd"
let home = FileManager.default.homeDirectoryForCurrentUser.path
let plistPath = "\(home)/Library/LaunchAgents/\(daemonLabel).plist"
let daemonLogPath = "\(home)/Library/Logs/protonmcp/daemon.log"
let appSupport = "\(home)/Library/Application Support/protonmcp"
let auditLogPath = "\(appSupport)/audit.log"
let statePath = "\(appSupport)/state.json"
let policyPath = "\(appSupport)/policy.yaml"
let inUseWindow: TimeInterval = 5.0
// state.json older than this means the daemon stopped heartbeating
// (it rewrites the file at least every 30 s while alive).
let stateStaleAfter: TimeInterval = 90.0
// idle_lock_minutes value restored when Keep Alive is switched OFF.
let defaultIdleLockMinutes = 15

// binDir is the directory this helper's executable really lives in
// (symlinks resolved — Homebrew links bin/ into the Cellar). make and
// brew put every product in the same bin dir, so the CLI and the
// daemon are siblings of this binary.
let binDir: String = {
    let exe = URL(fileURLWithPath: Bundle.main.executablePath!).resolvingSymlinksInPath()
    return exe.deletingLastPathComponent().path
}()

// protonmcpCLI is the CLI binary installed next to this helper —
// used for `policy reload` after a Keep Alive toggle.
let protonmcpCLI = binDir + "/protonmcp"

// expectedDaemonPath is the only executable this helper will signal.
let expectedDaemonPath = URL(fileURLWithPath: binDir + "/protonmcpd")
    .resolvingSymlinksInPath().standardizedFileURL.path

// runCmd executes a binary with args and returns (exit code, stdout).
// Absolute paths only; nothing here interpolates user input into a shell.
@discardableResult
func runCmd(_ path: String, _ args: [String]) -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = Pipe() // discard
    do { try p.run() } catch { return (127, "") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

// executablePath returns the on-disk executable of pid via libproc,
// or nil if the process is gone / not ours to inspect.
func executablePath(_ pid: Int32) -> String? {
    var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN)) // PROC_PIDPATHINFO_MAXSIZE
    let n = proc_pidpath(pid, &buf, UInt32(buf.count))
    guard n > 0 else { return nil }
    return URL(fileURLWithPath: String(cString: buf))
        .resolvingSymlinksInPath().standardizedFileURL.path
}

// isOurDaemon: pid is alive AND is the protonmcpd sibling of this
// helper. Guards against PID reuse and against signalling some other
// process that happens to be named protonmcpd (another checkout, an
// old build elsewhere on disk).
func isOurDaemon(_ pid: Int32) -> Bool {
    guard pid > 0 else { return false }
    return executablePath(pid) == expectedDaemonPath
}

// isLiveDaemon: pid is alive and is *a* protonmcpd (PID-reuse guard
// for the status display). Looser than isOurDaemon on purpose: a menu
// bar run from a dev checkout should still show the installed
// daemon's state; only signalling demands the exact sibling binary.
func isLiveDaemon(_ pid: Int32) -> Bool {
    guard pid > 0, kill(pid, 0) == 0 || errno == EPERM else { return false }
    guard let path = executablePath(pid) else { return false }
    return (path as NSString).lastPathComponent == "protonmcpd"
}

// parseRFC3339 accepts timestamps with or without fractional seconds
// (Go's time.RFC3339Nano drops trailing zeros, so both occur).
func parseRFC3339(_ s: String) -> Date? {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = f.date(from: s) { return d }
    f.formatOptions = [.withInternetDateTime]
    return f.date(from: s)
}

// DaemonStateFile mirrors state.json:
// {"state":"starting|connecting|locked|unlocked","reason":"...",
//  "email":"...","pid":123,"keep_alive":true,"last_tool":"name",
//  "last_tool_at":"RFC3339","updated_at":"RFC3339"}
struct DaemonStateFile {
    var state: String
    var reason: String
    var email: String
    var pid: Int32
    var keepAlive: Bool
    var lastTool: String
    var lastToolAt: Date?
    var updatedAt: Date?

    // load returns nil when the file is absent (older daemon) or
    // unparseable.
    static func load() -> DaemonStateFile? {
        guard let data = FileManager.default.contents(atPath: statePath),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return DaemonStateFile(
            state: obj["state"] as? String ?? "",
            reason: obj["reason"] as? String ?? "",
            email: obj["email"] as? String ?? "",
            pid: (obj["pid"] as? NSNumber)?.int32Value ?? 0,
            keepAlive: obj["keep_alive"] as? Bool ?? false,
            lastTool: obj["last_tool"] as? String ?? "",
            lastToolAt: (obj["last_tool_at"] as? String).flatMap(parseRFC3339),
            updatedAt: (obj["updated_at"] as? String).flatMap(parseRFC3339))
    }

    // needsTouchID: the session is waiting on a biometric — plainly
    // locked, or still connecting because the keys are locked (the
    // reason says so). SIGUSR2 runs the daemon's Touch ID unlock flow.
    var needsTouchID: Bool {
        if state == "locked" { return true }
        guard state == "connecting" || state == "starting" else { return false }
        let r = reason.lowercased()
        return r.contains("lock") || r.contains("touch id")
    }
}

enum DaemonState {
    case killSwitched   // 🔴 disabled by the user
    case notRunning     // ⚪ enabled but no live process / stale state file
    case connecting     // 🟠 process up, session not established (offline / startup)
    case locked         // 🟡 running, session locked
    case inUse          // 🔵 running, unlocked, recent tool call
    case connected      // 🟢 running, unlocked, idle

    var emoji: String {
        switch self {
        case .killSwitched: return "🔴"
        case .notRunning:   return "⚪"
        case .connecting:   return "🟠"
        case .locked:       return "🟡"
        case .inUse:        return "🔵"
        case .connected:    return "🟢"
        }
    }

    var label: String {
        switch self {
        case .killSwitched: return "SWITCHED OFF — Claude access blocked"
        case .notRunning:   return "Disconnected (daemon not running)"
        case .connecting:   return "Connecting — waiting for Proton (network unreachable or starting up)"
        case .locked:       return "Connected — locked (Touch ID to unlock)"
        case .inUse:        return "Connected — IN USE"
        case .connected:    return "Connected — logged in"
        }
    }
}

final class StatusPoller {
    private(set) var state: DaemonState = .notRunning
    private(set) var lastTool: String = "—"
    private(set) var lastToolAt: String = ""
    // reason / email from state.json; empty in legacy mode.
    private(set) var reason: String = ""
    private(set) var email: String = ""
    // needsTouchID: show "Connect (Touch ID)…".
    private(set) var needsTouchID = false
    private var lastAuditSize: UInt64 = 0
    private var activeUntil: Date = .distantPast

    private let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    // pgrepPIDs lists every process named protonmcpd. Names are
    // untrusted — callers verify with isOurDaemon before signalling.
    func pgrepPIDs() -> [Int32] {
        let (code, out) = runCmd("/usr/bin/pgrep", ["-x", "protonmcpd"])
        guard code == 0 else { return [] }
        return out.split(separator: "\n").compactMap {
            Int32($0.trimmingCharacters(in: .whitespaces))
        }
    }

    // verifiedDaemonPID returns a PID that is safe to signal: the one
    // state.json names if it checks out, else a pgrep match that does.
    // nil means no running process is provably our protonmcpd.
    func verifiedDaemonPID() -> Int32? {
        if let pid = DaemonStateFile.load()?.pid, isOurDaemon(pid) { return pid }
        return pgrepPIDs().first(where: isOurDaemon)
    }

    private func isDisabled() -> Bool {
        let (code, out) = runCmd("/bin/launchctl", ["print-disabled", "gui/\(getuid())"])
        guard code == 0 else { return false }
        // Output lines look like:  "zone.dort.protonmcpd" => disabled
        // (older launchctl prints `=> true`).
        for line in out.split(separator: "\n") where line.contains(daemonLabel) {
            if line.contains("=> true") || line.contains("=> disabled") { return true }
        }
        return false
    }

    // tailFile reads the last `bytes` of a file without loading the whole
    // thing; both logs are append-only.
    private func tailFile(_ path: String, bytes: UInt64 = 65536) -> String {
        guard let fh = FileHandle(forReadingAtPath: path) else { return "" }
        defer { try? fh.close() }
        let size = (try? fh.seekToEnd()) ?? 0
        let offset = size > bytes ? size - bytes : 0
        try? fh.seek(toOffset: offset)
        let data = (try? fh.readToEnd()) ?? Data()
        return String(data: data, encoding: .utf8) ?? ""
    }

    // MARK: state.json (current daemons)

    private func pollStateFile(_ sf: DaemonStateFile) {
        reason = sf.reason
        email = sf.email
        if !sf.lastTool.isEmpty {
            lastTool = sf.lastTool
            lastToolAt = sf.lastToolAt.map { timeFormatter.string(from: $0) } ?? ""
        }
        // Stale: the daemon stopped heartbeating, or the PID it wrote
        // is gone (crash without a final write) / now belongs to some
        // other program.
        let fresh = sf.updatedAt.map { Date().timeIntervalSince($0) < stateStaleAfter } ?? false
        guard fresh, isLiveDaemon(sf.pid) else {
            state = .notRunning
            email = ""
            needsTouchID = false
            return
        }
        needsTouchID = sf.needsTouchID
        switch sf.state {
        case "unlocked":
            if let at = sf.lastToolAt, Date().timeIntervalSince(at) < inUseWindow {
                state = .inUse
            } else {
                state = .connected
            }
        case "locked":
            state = .locked
        default: // "starting", "connecting", or anything newer we don't know
            state = .connecting
        }
    }

    // MARK: legacy heuristics (daemons without state.json)

    // scanDaemonLog derives (locked, serving) from the daemon log's
    // transition markers; the most recent marker of each kind wins.
    // "protonmcpd ready" implies an unlocked, serving session (startup
    // gate approved + keys acquired + socket open). "will retry
    // session resume" means the process is alive but has no session —
    // typically Proton unreachable — so the socket is not serving yet
    // and the icon must NOT read green.
    private func scanDaemonLog() -> (locked: Bool, serving: Bool) {
        let tail = tailFile(daemonLogPath)
        var locked = false
        var serving = false
        for line in tail.split(separator: "\n") {
            if line.contains("msg=\"daemon locked\"") { locked = true }
            if line.contains("msg=\"daemon unlocked\"") { locked = false }
            if line.contains("msg=\"protonmcpd ready\"") {
                locked = false
                serving = true
            }
            if line.contains("will retry session resume") ||
                line.contains("msg=\"daemon drained gracefully\"") {
                serving = false
            }
        }
        return (locked, serving)
    }

    private func checkActivity() {
        let attrs = try? FileManager.default.attributesOfItem(atPath: auditLogPath)
        let size = (attrs?[.size] as? NSNumber)?.uint64Value ?? 0
        defer { lastAuditSize = size }
        // Grew since last poll → a tool call completed. Shrank → rotation.
        guard size != lastAuditSize, size > 0, lastAuditSize > 0 || size > 0 else { return }
        if size < lastAuditSize { return } // rotated; re-baseline only
        guard lastAuditSize != 0 else { return } // first poll: baseline, not activity
        activeUntil = Date().addingTimeInterval(inUseWindow)
        // Surface the most recent tool name + time in the menu.
        if let lastLine = tailFile(auditLogPath, bytes: 8192)
            .split(separator: "\n").last,
           let obj = try? JSONSerialization.jsonObject(with: Data(lastLine.utf8)) as? [String: Any] {
            lastTool = obj["tool"] as? String ?? "—"
            let ts = (obj["completed_at"] as? String ?? "")
            lastToolAt = String(ts.dropFirst(11).prefix(8)) // HH:MM:SS
        }
    }

    private func pollLegacy() {
        reason = ""
        email = ""
        checkActivity()
        guard !pgrepPIDs().isEmpty else {
            state = .notRunning
            needsTouchID = false
            return
        }
        let log = scanDaemonLog()
        if !log.serving {
            state = .connecting
        } else if log.locked {
            state = .locked
        } else if Date() < activeUntil {
            state = .inUse
        } else {
            state = .connected
        }
        needsTouchID = state == .locked
    }

    func poll() {
        if isDisabled() {
            state = .killSwitched
            needsTouchID = false
            return
        }
        if let sf = DaemonStateFile.load() {
            pollStateFile(sf)
        } else {
            pollLegacy()
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let poller = StatusPoller()
    private var timer: Timer?

    func applicationDidFinishLaunching(_ note: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.menu = buildMenu()
        statusItem.menu?.delegate = self
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    private func refresh() {
        poller.poll()
        statusItem.button?.title = "\(poller.state.emoji)\u{FE0E} ✉︎"
        statusItem.button?.toolTip = "Proton MCP: \(statusLabel())"
    }

    // statusLabel appends the daemon's own reason (state.json) for the
    // states where it explains something: why it's locked, or what
    // it's waiting on while connecting.
    private func statusLabel() -> String {
        let base = poller.state.label
        guard poller.state == .locked || poller.state == .connecting,
              !poller.reason.isEmpty else { return base }
        return "\(base) — \(poller.reason)"
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        menu.removeAllItems()
        populate(menu)
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu()
        populate(menu)
        return menu
    }

    private func populate(_ menu: NSMenu) {
        let status = NSMenuItem(title: "\(poller.state.emoji) Proton MCP — \(statusLabel())",
                                action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

        if !poller.email.isEmpty {
            let account = NSMenuItem(title: "Account: \(poller.email)", action: nil, keyEquivalent: "")
            account.isEnabled = false
            menu.addItem(account)
        }

        let last = NSMenuItem(title: "Last tool: \(poller.lastTool) \(poller.lastToolAt)",
                              action: nil, keyEquivalent: "")
        last.isEnabled = false
        menu.addItem(last)
        menu.addItem(.separator())

        if poller.state == .killSwitched {
            let on = NSMenuItem(title: "Switch On (Touch ID required)…",
                                action: #selector(switchOn), keyEquivalent: "")
            on.target = self
            menu.addItem(on)
        } else {
            let off = NSMenuItem(title: "Switch Off — block Claude access",
                                 action: #selector(switchOff), keyEquivalent: "")
            off.target = self
            menu.addItem(off)
            if poller.state == .locked || (poller.state == .connecting && poller.needsTouchID) {
                // One item for both cases: SIGUSR2 runs the daemon's
                // Touch ID unlock flow, which also completes a connect
                // that is only waiting on locked keys.
                let connect = NSMenuItem(title: "Connect (Touch ID)…",
                                         action: #selector(unlockNow), keyEquivalent: "")
                connect.target = self
                menu.addItem(connect)
            } else if poller.state == .connected || poller.state == .inUse {
                // Lock Now only makes sense with a live session —
                // .connecting has no keys to zero yet.
                let lock = NSMenuItem(title: "Lock Now",
                                      action: #selector(lockNow), keyEquivalent: "")
                lock.target = self
                menu.addItem(lock)
            }
        }
        menu.addItem(.separator())

        let keepAlive = NSMenuItem(title: "Keep Alive — stay connected, no attachment prompts",
                                   action: #selector(toggleKeepAlive), keyEquivalent: "")
        keepAlive.target = self
        keepAlive.state = keepAliveEnabled() ? .on : .off
        keepAlive.toolTip = "On: Proton stays connected through screen lock, sleep and idle, " +
            "and attachment download/save don't ask for Touch ID. " +
            "Off: the session locks on screen lock, sleep, or \(defaultIdleLockMinutes) min idle. " +
            "Keep Alive never removes Touch ID from sending, moving, labeling, trashing or deleting; " +
            "Lock Now and Switch Off always work."
        menu.addItem(keepAlive)
        menu.addItem(.separator())

        let audit = NSMenuItem(title: "Open Audit Log",
                               action: #selector(openAudit), keyEquivalent: "")
        audit.target = self
        menu.addItem(audit)

        let quit = NSMenuItem(title: "Quit Indicator (daemon unaffected)",
                              action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)
    }

    // MARK: - Keep Alive (idle-timeout toggle)

    // topLevelValue returns the value of an unindented `key:` line in
    // YAML text, with any trailing `# comment` and CR stripped. Only
    // top-level lines count: an indented `keep_alive:` belongs to some
    // nested block and must not be mistaken for the policy flag.
    static func topLevelValue(_ key: String, in text: String) -> String? {
        // components(separatedBy:) splits on the \n code unit; Swift's
        // Character-based split would treat "\r\n" as one grapheme and
        // never split CRLF files.
        for raw in text.components(separatedBy: "\n") {
            let line = raw.hasSuffix("\r") ? String(raw.dropLast()) : raw
            guard line.hasPrefix("\(key):") else { continue }
            let rest = String(line.dropFirst(key.count + 1))
            return stripComment(rest).trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    // stripComment removes a YAML comment: `#` at the start or after
    // whitespace (`a#b` is a plain scalar, not a comment).
    static func stripComment(_ s: String) -> String {
        var prev: Character = " "
        for (i, c) in zip(s.indices, s) {
            if c == "#" && (prev == " " || prev == "\t") {
                return String(s[..<i])
            }
            prev = c
        }
        return s
    }

    // keepAliveEnabled reads the keep_alive flag from policy.yaml.
    // Absent / false → OFF (the secure default: attachments prompt
    // and the idle timer runs). The toggle keeps keep_alive and
    // idle_lock_minutes in lockstep, so keep_alive alone is the
    // authoritative UI state. Accepts the spellings yaml.v3 decodes
    // into a true bool.
    private func keepAliveEnabled() -> Bool {
        guard let text = try? String(contentsOfFile: policyPath, encoding: .utf8),
              let v = AppDelegate.topLevelValue("keep_alive", in: text) else {
            return false
        }
        return ["true", "yes", "on", "y"].contains(v.lowercased())
    }

    // setScalarKey upserts a single top-level `key: value` line in
    // policy.yaml, preserving every other line byte-for-byte
    // (idle_lock_minutes, the attachment allowlist, comments, CRLF
    // endings). Indented lines inside nested blocks like `tools:` are
    // never matched; a trailing comment on the replaced line is kept.
    private func setScalarKey(_ key: String, _ value: String) {
        let text = (try? String(contentsOfFile: policyPath, encoding: .utf8)) ?? ""
        try? AppDelegate.upsertTopLevel(key, value, in: text)
            .write(toFile: policyPath, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: policyPath)
    }

    static func upsertTopLevel(_ key: String, _ value: String, in text: String) -> String {
        let crlf = text.contains("\r\n")
        var lines = text.isEmpty ? [] : text.components(separatedBy: "\n")
        for i in lines.indices {
            let hasCR = lines[i].hasSuffix("\r")
            let line = hasCR ? String(lines[i].dropLast()) : lines[i]
            guard line.hasPrefix("\(key):") else { continue }
            let rest = String(line.dropFirst(key.count + 1))
            let stripped = stripComment(rest)
            let comment = rest.count > stripped.count ? " " + String(rest.dropFirst(stripped.count)) : ""
            lines[i] = "\(key): \(value)\(comment)" + (hasCR ? "\r" : "")
            return lines.joined(separator: "\n")
        }
        // Not present: append, keeping the file's newline convention
        // and its trailing newline (split leaves a final "" for it).
        let newLine = "\(key): \(value)" + (crlf ? "\r" : "")
        if let lastLine = lines.last, lastLine.isEmpty {
            lines.insert(newLine, at: lines.count - 1)
        } else {
            if let lastLine = lines.last, crlf && !lastLine.hasSuffix("\r") {
                lines[lines.count - 1] = lastLine + "\r"
            }
            lines.append(newLine)
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }

    @objc private func toggleKeepAlive() {
        let turningOn = !keepAliveEnabled()
        // keep_alive drives attachment-prompt suppression; idle timer
        // moves with it (0 = never idle-lock when on, 15 when off).
        // Both written before a single hot reload so the daemon sees
        // a consistent policy.
        setScalarKey("keep_alive", turningOn ? "true" : "false")
        setScalarKey("idle_lock_minutes", turningOn ? "0" : "\(defaultIdleLockMinutes)")
        // Hot-reload: the daemon re-reads policy.yaml on SIGHUP via
        // `protonmcp policy reload` (finds protonmcpd since the PROTO
        // fork fix). Failure is non-fatal — a later daemon restart
        // picks the file up anyway.
        runCmd(protonmcpCLI, ["policy", "reload"])
        refresh()
    }

    // MARK: - Actions

    @objc private func switchOff() {
        // Disable survives reboots; bootout kills the running instance.
        runCmd("/bin/launchctl", ["disable", "gui/\(getuid())/\(daemonLabel)"])
        runCmd("/bin/launchctl", ["bootout", "gui/\(getuid())/\(daemonLabel)"])
        refresh()
    }

    @objc private func switchOn() {
        // D39-class race: launchd refuses a bootstrap for a short
        // window after the same label was booted out. The old
        // single-shot version swallowed that failure via runCmd,
        // leaving the job enabled but UNLOADED — the kill switch
        // looked toggled back on while the daemon stayed dead.
        // Retry with growing delays, off the main thread so the
        // menu doesn't beachball.
        DispatchQueue.global(qos: .userInitiated).async {
            runCmd("/bin/launchctl", ["enable", "gui/\(getuid())/\(daemonLabel)"])
            for attempt in 1...5 {
                let (code, _) = runCmd("/bin/launchctl", ["bootstrap", "gui/\(getuid())", plistPath])
                // Success, or already bootstrapped (a previous attempt
                // landed): verify via print rather than trusting the
                // exit code alone.
                let (pcode, _) = runCmd("/bin/launchctl", ["print", "gui/\(getuid())/\(daemonLabel)"])
                if code == 0 || pcode == 0 { break }
                Thread.sleep(forTimeInterval: Double(attempt))
            }
            runCmd("/bin/launchctl", ["kickstart", "gui/\(getuid())/\(daemonLabel)"])
            DispatchQueue.main.async { self.refresh() }
        }
    }

    @objc private func lockNow() {
        signalDaemon(SIGUSR1, action: "lock")
    }

    @objc private func unlockNow() {
        // SIGUSR2 → daemon runs its Touch ID unlock flow in-process.
        signalDaemon(SIGUSR2, action: "connect")
    }

    // signalDaemon sends sig only to a PID verified (proc_pidpath) to
    // be the protonmcpd next to this helper; anything else — a stale
    // PID reused by another program, a protonmcpd from some other
    // install — is refused with an explanation instead of signalled.
    private func signalDaemon(_ sig: Int32, action: String) {
        guard let pid = poller.verifiedDaemonPID() else {
            let alert = NSAlert()
            alert.messageText = "Couldn't \(action) Proton MCP"
            alert.informativeText = "No running protonmcpd matches \(expectedDaemonPath), " +
                "so no signal was sent."
            alert.alertStyle = .warning
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
            refresh()
            return
        }
        kill(pid, sig)
        refresh()
    }

    @objc private func openAudit() {
        NSWorkspace.shared.open(URL(fileURLWithPath: auditLogPath))
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory) // menu bar only; no Dock icon
let delegate = AppDelegate()
app.delegate = delegate
app.run()
