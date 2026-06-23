import { spawn, type ChildProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createInterface } from 'node:readline'

import { logForDebugging } from '../utils/debug.js'
import type {
  SandboxViolationCallback,
  SandboxViolationEvent,
} from './macos-sandbox-utils.js'
import type { IgnoreViolationsConfig } from './sandbox-config.js'
import { decodeSandboxedCommand } from './sandbox-utils.js'

export interface LinuxViolationMonitorOptions {
  /** Path to the srt-seccomp-supervisor binary. */
  supervisorPath: string
  /**
   * Paths bwrap mounts read-write. The supervisor reports every write-intent
   * syscall (allowed or not, since the BPF filter cannot see the mount
   * table); a path is treated as a violation only when it is *not* under any
   * of these prefixes, or when it falls under {@link denyWritePaths}.
   */
  allowWritePaths: string[]
  /** Paths bwrap re-mounts read-only inside an allowWrite region. */
  denyWritePaths: string[]
  ignoreViolations?: IgnoreViolationsConfig
}

export interface LinuxViolationMonitor {
  /** Filesystem unix-socket path the supervisor is listening on. Bind-mount
   *  this into each bwrap sandbox and pass it to apply-seccomp via
   *  SRT_OBSERVE_SOCK. `undefined` if the supervisor failed to start (the
   *  caller should proceed without observation). */
  observeSocketPath: string | undefined
  /** Resolves once the supervisor has bound its listener and printed READY,
   *  or resolves anyway on startup failure. */
  ready: Promise<void>
  stop: () => void
}

interface SupervisorEvent {
  nr?: number
  syscall?: string
  pid?: number
  path?: string
  encodedCommand?: string
  observe_init_error?: string
}

/**
 * Linux equivalent of {@link startMacOSSandboxLogMonitor}. Spawns a single
 * long-lived `srt-seccomp-supervisor` that owns a filesystem unix socket;
 * each `apply-seccomp` instance connects to it and hands over a
 * SECCOMP_RET_USER_NOTIF listener fd. The supervisor poll()s every listener,
 * answers every notification with CONTINUE (so the workload is never
 * blocked), and writes one JSON line per observed write-intent syscall to
 * stdout, which this function parses and feeds to {@link callback}.
 *
 * Unlike Seatbelt's `log stream`, the kernel reports *attempts* here, not
 * denials, so this function intersects each path against the configured
 * allow/deny set before forwarding it as a violation.
 *
 * The transport is a *filesystem* unix socket because bwrap runs with
 * `--unshare-net` (abstract sockets are net-namespace-scoped) and bwrap
 * closes inherited fds (so a socketpair cannot be threaded through).
 * Filesystem sockets survive across net + user + mount namespaces as long as
 * the path is bind-mounted into the sandbox.
 */
export function startLinuxSandboxViolationMonitor(
  callback: SandboxViolationCallback,
  opts: LinuxViolationMonitorOptions,
): LinuxViolationMonitor {
  const { supervisorPath, allowWritePaths, denyWritePaths, ignoreViolations } =
    opts

  if (!supervisorPath || !existsSync(supervisorPath)) {
    logForDebugging(
      `[Sandbox Linux Monitor] supervisor binary not found at ${supervisorPath} - violation monitoring disabled`,
      { level: 'warn' },
    )
    return {
      observeSocketPath: undefined,
      ready: Promise.resolve(),
      stop: () => {},
    }
  }

  // sun_path is 108 bytes; mkdtemp under tmpdir() keeps us well under.
  const sockDir = mkdtempSync(join(tmpdir(), 'srt-obs-'))
  const sockPath = join(sockDir, `s${randomBytes(4).toString('hex')}.sock`)

  let proc: ChildProcess | undefined = spawn(supervisorPath, [sockPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  let resolveReady: () => void
  let isReady = false
  const ready = new Promise<void>(res => {
    resolveReady = res
  })

  const wildcardPaths = ignoreViolations?.['*'] ?? []
  const commandPatterns = ignoreViolations
    ? Object.entries(ignoreViolations).filter(([k]) => k !== '*')
    : []

  const underPrefix = (p: string, prefix: string): boolean =>
    p === prefix || p.startsWith(prefix.endsWith('/') ? prefix : prefix + '/')

  /** A write attempt is a violation iff bwrap would refuse it: outside every
   *  allowWrite prefix, or back inside a denyWrite carve-out. Relative paths
   *  (dirfd-relative) are reported as-is — we can't resolve them without the
   *  tracee's cwd, so err on the side of reporting. */
  const isDenied = (p: string): boolean => {
    if (!p.startsWith('/')) return true
    if (denyWritePaths.some(d => underPrefix(p, d))) return true
    return !allowWritePaths.some(a => underPrefix(p, a))
  }

  const shouldIgnore = (path: string, command: string | undefined): boolean => {
    if (wildcardPaths.some(w => path.includes(w))) return true
    if (command) {
      for (const [pattern, paths] of commandPatterns) {
        if (command.includes(pattern) && paths.some(w => path.includes(w))) {
          return true
        }
      }
    }
    return false
  }

  const rl = createInterface({ input: proc.stdout! })
  rl.on('line', raw => {
    if (!raw) return
    if (raw === 'READY') {
      isReady = true
      resolveReady()
      return
    }
    let ev: SupervisorEvent
    try {
      ev = JSON.parse(raw) as SupervisorEvent
    } catch {
      return
    }
    if (ev.observe_init_error) {
      logForDebugging(
        `[Sandbox Linux Monitor] observe filter not installed: ${ev.observe_init_error}`,
      )
      return
    }
    if (typeof ev.path !== 'string') return
    if (!isDenied(ev.path)) return

    let command: string | undefined
    if (ev.encodedCommand) {
      try {
        command = decodeSandboxedCommand(ev.encodedCommand)
      } catch {
        /* ignore */
      }
    }
    if (shouldIgnore(ev.path, command)) return

    const violation: SandboxViolationEvent = {
      line: `deny ${ev.syscall ?? 'syscall'} ${ev.path}`,
      command,
      encodedCommand: ev.encodedCommand,
      timestamp: new Date(),
    }
    callback(violation)
  })

  proc.stderr?.on('data', (d: Buffer) => {
    logForDebugging(`[Sandbox Linux Monitor] stderr: ${d.toString().trim()}`)
  })
  proc.on('error', err => {
    logForDebugging(
      `[Sandbox Linux Monitor] failed to start supervisor: ${err.message}`,
    )
    proc = undefined
    resolveReady()
  })
  proc.on('exit', code => {
    logForDebugging(
      `[Sandbox Linux Monitor] supervisor exited with code ${code}`,
    )
    proc = undefined
    if (!isReady) resolveReady()
  })

  const stop = (): void => {
    logForDebugging('[Sandbox Linux Monitor] stopping')
    rl.close()
    try {
      proc?.kill('SIGTERM')
    } catch {
      /* already dead */
    }
    try {
      rmSync(sockDir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }

  return { observeSocketPath: sockPath, ready, stop }
}
