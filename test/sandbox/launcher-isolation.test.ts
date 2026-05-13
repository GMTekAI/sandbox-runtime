import { describe, it, expect, beforeAll } from 'bun:test'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { getSrtLauncherPath } from '../../src/sandbox/srt-launcher.js'
import { isLinux } from '../helpers/platform.js'

/**
 * Tests for srt-launcher's isolation guarantees.
 *
 * srt-launcher uses a single PID namespace layer (it is PID 1 inside the
 * sandbox) and sets PR_SET_DUMPABLE=0 on itself before exec'ing the worker.
 * That means the worker (a) sees only its own process tree in /proc, (b)
 * cannot ptrace / open /proc/1/mem of the launcher init, and (c) when
 * --seccomp-unix-block is on, gets EPERM on socket(AF_UNIX, ...).
 *
 * These tests invoke srt-launcher directly so they don't depend on the rest
 * of the sandbox plumbing.
 */

let launcher: string | null = null

function runLauncher(
  script: string,
  opts: { timeout?: number } = {},
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(
    launcher!,
    [
      'run',
      '--ro-bind',
      '/',
      '/',
      '--proc',
      '/proc',
      '--dev',
      '/dev',
      '--seccomp-unix-block',
      '--',
      '/bin/sh',
      '-c',
      script,
    ],
    { stdio: 'pipe', timeout: opts.timeout ?? 10000 },
  )
  return {
    status: r.status,
    stdout: r.stdout?.toString() ?? '',
    stderr: r.stderr?.toString() ?? '',
  }
}

describe.if(isLinux)('srt-launcher isolation', () => {
  beforeAll(() => {
    launcher = getSrtLauncherPath()
    // On Linux CI with the vendor binary present this always resolves.
    // If null, every test below would silently no-op — fail here.
    expect(launcher).toBeTruthy()
    expect(existsSync(launcher!)).toBe(true)
  })

  // ------------------------------------------------------------------
  // PID namespace
  // ------------------------------------------------------------------

  it('shows only the inner namespace in /proc', () => {
    const r = runLauncher('ls /proc | grep -E "^[0-9]+$" | sort -n')
    expect(r.status).toBe(0)
    const pids = r.stdout
      .trim()
      .split('\n')
      .map(s => parseInt(s, 10))
    // PID 1 is srt-launcher init, PID 2 is sh; ls/grep/sort add a few more.
    // What matters is that none of the host's PIDs leak in.
    expect(pids[0]).toBe(1)
    expect(Math.max(...pids)).toBeLessThan(20)
  })

  it('forwards exit codes from the inner command', () => {
    expect(runLauncher('exit 0').status).toBe(0)
    expect(runLauncher('exit 1').status).toBe(1)
    expect(runLauncher('exit 42').status).toBe(42)
    expect(runLauncher('exit 127').status).toBe(127)
  })

  // ------------------------------------------------------------------
  // PID 1 is not controllable from the worker (PR_SET_DUMPABLE=0)
  // ------------------------------------------------------------------

  it('denies opening /proc/1/mem for writing', () => {
    const r = runLauncher(
      [
        'python3 -c "',
        'try:',
        '    open(\\"/proc/1/mem\\", \\"r+b\\")',
        '    print(\\"OPENED\\")',
        '    exit(1)',
        'except PermissionError:',
        '    print(\\"DENIED\\")',
        '    exit(0)',
        '"',
      ].join('\n'),
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('DENIED')
  })

  it('denies ptrace(PTRACE_ATTACH) against PID 1', () => {
    const r = runLauncher(
      [
        'python3 -c "',
        'import ctypes',
        'libc = ctypes.CDLL(None, use_errno=True)',
        'r = libc.ptrace(16, 1, 0, 0)  # PTRACE_ATTACH',
        'err = ctypes.get_errno()',
        'print(f\\"r={r} errno={err}\\")',
        'exit(0 if r != 0 else 1)',
        '"',
      ].join('\n'),
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toMatch(/r=-1 errno=(1|13)/) // EPERM or EACCES
  })

  // ------------------------------------------------------------------
  // Seccomp filter
  // ------------------------------------------------------------------

  it('blocks AF_UNIX socket creation', () => {
    const r = runLauncher(
      'python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"',
    )
    expect(r.status).not.toBe(0)
    expect(r.stderr.toLowerCase()).toMatch(
      /permission denied|operation not permitted/,
    )
  })

  it('allows AF_INET socket creation', () => {
    const r = runLauncher(
      'python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM); print(\\"ok\\")"',
    )
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('ok')
  })
})
