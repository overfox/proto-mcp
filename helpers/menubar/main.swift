// protonmcp-menubar — NSStatusItem indicator + kill switch for protonmcpd.
//
// Lives in the macOS menu bar (next to the clock) and shows, at a glance,
// what the MCP daemon is doing:
//
//   🟢  daemon running, session unlocked (Claude has access)
//   🔵  in use — a tool call landed in the audit log within the last 5 s
//   🟡  daemon running but LOCKED (screen-lock / idle / manual lock)
//   ⚪  daemon not running (crashed or stopped) but launchd job enabled
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
// passively from pgrep, `launchctl print-disabled`, the daemon log
// (locked/unlocked transitions), and the audit log (activity). This
// keeps the indicator itself out of the audit trail and out of the
// daemon's peer-cred path.

import AppKit
import Foundation

let daemonLabel = "zone.dort.protonmcpd"
let home = FileManager.default.homeDirectoryForCurrentUser.path
let plistPath = "\(home)/Library/LaunchAgents/\(daemonLabel).plist"
let daemonLogPath = "\(home)/Library/Logs/protonmcp/daemon.log"
let appSupport = "\(home)/Library/Application Support/protonmcp"
let auditLogPath = "\(appSupport)/audit.log"
let policyPath = "\(appSupport)/policy.yaml"
let inUseWindow: TimeInterval = 5.0
// idle_lock_minutes value restored when Keep Alive is switched OFF.
let defaultIdleLockMinutes = 15

// protonmcpCLI is the CLI binary installed next to this helper
// (make/brew put every product in the same bin dir) — used for
// `policy reload` after a Keep Alive toggle.
let protonmcpCLI: String = {
    let dir = (Bundle.main.executablePath! as NSString).deletingLastPathComponent
    return dir + "/protonmcp"
}()

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

enum DaemonState {
    case killSwitched   // 🔴 disabled by the user
    case notRunning     // ⚪ enabled but no process
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
    private var lastAuditSize: UInt64 = 0
    private var activeUntil: Date = .distantPast

    func daemonPID() -> Int32? {
        let (code, out) = runCmd("/usr/bin/pgrep", ["-x", "protonmcpd"])
        guard code == 0, let pid = Int32(out.split(separator: "\n").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? "") else { return nil }
        return pid
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

    func poll() {
        checkActivity()
        if isDisabled() {
            state = .killSwitched
            return
        }
        if daemonPID() == nil {
            state = .notRunning
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
        statusItem.button?.toolTip = "Proton MCP: \(poller.state.label)"
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
        let status = NSMenuItem(title: "\(poller.state.emoji) Proton MCP — \(poller.state.label)",
                                action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)

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
            if poller.state == .locked {
                let unlock = NSMenuItem(title: "Unlock (Touch ID)…",
                                        action: #selector(unlockNow), keyEquivalent: "")
                unlock.target = self
                menu.addItem(unlock)
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

        let keepAlive = NSMenuItem(title: "Keep Alive — no idle timeout",
                                   action: #selector(toggleKeepAlive), keyEquivalent: "")
        keepAlive.target = self
        keepAlive.state = keepAliveEnabled() ? .on : .off
        keepAlive.toolTip = "On: the session never locks from inactivity. " +
            "Off: auto-lock after \(defaultIdleLockMinutes) min idle. " +
            "Screen lock and sleep always lock the session either way."
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

    // keepAliveEnabled reads policy.yaml: idle_lock_minutes 0 (or
    // absent) means the idle timer is off → session never idle-locks.
    // Screen-lock / sleep locking is separate (lockwatch) and is
    // deliberately NOT touched by this toggle.
    private func keepAliveEnabled() -> Bool {
        guard let text = try? String(contentsOfFile: policyPath, encoding: .utf8) else {
            return true // no policy file → daemon default is 0/disabled
        }
        for line in text.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("idle_lock_minutes:") {
                let v = t.dropFirst("idle_lock_minutes:".count)
                    .trimmingCharacters(in: .whitespaces)
                return Int(v) == 0
            }
        }
        return true // key absent → 0/disabled
    }

    private func setIdleLockMinutes(_ minutes: Int) {
        var lines: [String]
        if let text = try? String(contentsOfFile: policyPath, encoding: .utf8) {
            lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        } else {
            lines = []
        }
        var replaced = false
        for i in lines.indices {
            if lines[i].trimmingCharacters(in: .whitespaces).hasPrefix("idle_lock_minutes:") {
                lines[i] = "idle_lock_minutes: \(minutes)"
                replaced = true
                break
            }
        }
        if !replaced {
            lines.append("idle_lock_minutes: \(minutes)")
        }
        let out = lines.joined(separator: "\n")
        try? out.write(toFile: policyPath, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: policyPath)
        // Hot-reload: the daemon re-reads policy.yaml on SIGHUP via
        // `protonmcp policy reload` (finds protonmcpd since PROTO
        // fork fix). Failure is non-fatal — next daemon restart
        // picks the file up anyway.
        runCmd(protonmcpCLI, ["policy", "reload"])
    }

    @objc private func toggleKeepAlive() {
        setIdleLockMinutes(keepAliveEnabled() ? defaultIdleLockMinutes : 0)
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
        runCmd("/bin/launchctl", ["enable", "gui/\(getuid())/\(daemonLabel)"])
        runCmd("/bin/launchctl", ["bootstrap", "gui/\(getuid())", plistPath])
        runCmd("/bin/launchctl", ["kickstart", "gui/\(getuid())/\(daemonLabel)"])
        refresh()
    }

    @objc private func lockNow() {
        if let pid = poller.daemonPID() { kill(pid, SIGUSR1) }
        refresh()
    }

    @objc private func unlockNow() {
        // SIGUSR2 → daemon runs its Touch ID unlock flow in-process.
        if let pid = poller.daemonPID() { kill(pid, SIGUSR2) }
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
