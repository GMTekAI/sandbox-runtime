//! `srt-launcher run` — the per-command sandbox.
//!
//! Process tree (one wrapped command, network restrictions on):
//!
//!   srt-launcher run [stub]            host pidns/mountns, sandbox netns
//!   │   NO_NEW_PRIVS; PDEATHSIG; DUMPABLE=0
//!   │   unshare(USER?|NET) → lo up → fork relays → unshare(NS|PID) → fork
//!   ├─ relay (3128)                    host pidns/mountns, sandbox netns
//!   ├─ relay (1080)                    (same — invisible to the workload)
//!   ══════════════════════════════════ mount + PID ns boundary
//!   └─ srt-launcher run [PID 1]        sandbox pidns/mountns; pivot_root; reaper
//!      └─ worker                       seccomp applied, then execvp
//!
//! The relays fork from the stub *between* the NET unshare and the NS|PID
//! unshare, so they're in the host pidns and host mountns but the sandbox
//! netns: they listen on the sandbox's loopback yet the workload has no PID
//! for them (kill/ptrace/ /proc all return ESRCH/ENOENT), and they resolve
//! the bridge unix-socket path in the host's mount view (the workload cannot
//! swap that path). DUMPABLE=0 is inherited as defense-in-depth for the
//! `--host-proc` mode where they're visible at host PIDs.
//!
//! Three processes (stub → PID 1 → worker) is the floor: unshare(CLONE_NEWPID)
//! requires a fork to enter, and execve resets signal handlers — so a PID 1
//! that *is* the workload can't receive SIGTERM. PID-namespace, session, and
//! parent-death-signal isolation are not flag-gated; they're correctness
//! properties.

use crate::mount::{self, MountOp};
use crate::net::{self, RelaySpec};
use crate::{die, die_errno, errno};
use std::ffi::CString;
use std::io::Write as _;
use std::mem::zeroed;
use std::process::ExitCode;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

// ---------------------------------------------------------------------------
// Config + argv parsing
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Config {
    unshare_net: bool,
    /// Force the userns path even when EUID == 0. Needed in unprivileged
    /// containers (Docker default: EUID=0 without CAP_SYS_ADMIN) where direct
    /// unshare EPERMs and the userns path is the only way in.
    unshare_user: bool,
    seccomp_unix: bool,
    ops: Vec<MountOp>,
    relays: Vec<RelaySpec>,
    env: Vec<(String, String)>,
    /// argv for the worker. CStrings are built before fork so the post-fork
    /// path doesn't allocate.
    cmd: Vec<CString>,
}

fn parse(args: Vec<String>) -> Config {
    let mut c = Config::default();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        macro_rules! next {
            ($flag:literal) => {
                it.next().unwrap_or_else(|| die!(concat!($flag, " needs a value")))
            };
        }
        match a.as_str() {
            "--unshare-net" => c.unshare_net = true,
            "--unshare-user" => c.unshare_user = true,
            "--seccomp-unix-block" => c.seccomp_unix = true,
            "--bind" => {
                let src = next!("--bind");
                let dst = next!("--bind");
                c.ops.push(MountOp::Bind { src, dst });
            }
            "--ro-bind" => {
                let src = next!("--ro-bind");
                let dst = next!("--ro-bind");
                c.ops.push(MountOp::RoBind { src, dst });
            }
            "--tmpfs" => c.ops.push(MountOp::Tmpfs { dst: next!("--tmpfs") }),
            "--dev" => c.ops.push(MountOp::Dev { dst: next!("--dev") }),
            "--proc" => c.ops.push(MountOp::Proc { dst: next!("--proc"), host: false }),
            "--host-proc" => c.ops.push(MountOp::Proc { dst: next!("--host-proc"), host: true }),
            "--relay" => {
                let port: u16 = next!("--relay").parse().unwrap_or_else(|_| die!("--relay PORT must be numeric"));
                let unix_path = next!("--relay");
                c.relays.push(RelaySpec { port, unix_path });
            }
            "--setenv" => {
                let k = next!("--setenv");
                let v = next!("--setenv");
                c.env.push((k, v));
            }
            "--" => {
                for rest in it.by_ref() {
                    c.cmd.push(CString::new(rest).unwrap_or_else(|_| die!("argv contains NUL")));
                }
                break;
            }
            other => die!("run: unknown option {other}"),
        }
    }
    if c.cmd.is_empty() {
        die!("run: missing -- COMMAND");
    }
    c
}

// ---------------------------------------------------------------------------
// Signal forwarding + PID-1 reaper
// ---------------------------------------------------------------------------

static FORWARD_TARGET: AtomicI32 = AtomicI32::new(-1);

extern "C" fn forward_signal(sig: libc::c_int) {
    let t = FORWARD_TARGET.load(Ordering::Relaxed);
    if t > 0 {
        unsafe { libc::kill(t, sig) };
    }
}

fn install_forwarders(target: libc::pid_t) {
    FORWARD_TARGET.store(target, Ordering::Relaxed);
    unsafe {
        let mut sa: libc::sigaction = zeroed();
        sa.sa_sigaction = forward_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT, libc::SIGUSR1, libc::SIGUSR2] {
            libc::sigaction(s, &sa, ptr::null_mut());
        }
    }
}

fn wait_status_to_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Wait for `main_child`, reaping any other children that exit first. Returns
/// an exit(3)-style status. PID 1 ignores signals it has no handler for, so
/// the caller MUST install_forwarders first or SIGTERM is silently dropped.
fn reap_until(main_child: libc::pid_t) -> i32 {
    let mut status = 0i32;
    loop {
        let r = unsafe { libc::waitpid(-1, &mut status, 0) };
        if r < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return 1; // ECHILD without seeing main_child — shouldn't happen.
        }
        if r == main_child {
            return wait_status_to_code(status);
        }
        // Reaped an orphan that died before main_child; keep waiting.
    }
}

// ---------------------------------------------------------------------------
// Namespace entry + uid/gid map (when CLONE_NEWUSER is taken)
// ---------------------------------------------------------------------------

fn write_file(path: &str, content: &str) {
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(content.as_bytes()) {
                die!("write {path}: {e}");
            }
        }
        Err(e) => die!("open {path}: {e}"),
    }
}

/// Namespace entry happens in two phases so the relays can fork in between:
///
///   phase 1 (USER? + NET):  relays land in the host pidns/mountns but the
///                           sandbox netns — they listen on the sandbox's
///                           loopback yet are structurally invisible to the
///                           workload (no PID, no /proc entry).
///   phase 2 (NS + PID):     PID 1 (and thus the workload) gets the fresh
///                           mount + PID namespaces.
///
/// Phase 1 also handles the optional userns: try the direct unshare first
/// (succeeds with CAP_SYS_ADMIN), fall back to a userns to acquire it.
/// `force_userns` (the --unshare-user flag) takes the userns path even at
/// EUID 0, for unprivileged-container hosts.
fn enter_net_namespace(unshare_net: bool, force_userns: bool) {
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };

    let flags = if unshare_net { libc::CLONE_NEWNET } else { 0 };
    // Even if there's no NET to unshare, we may still need the userns for the
    // phase-2 NS|PID unshare. Probe with a no-op (flags=0 → unshare succeeds
    // trivially) only when forced; otherwise defer the userns decision to the
    // first actual unshare.
    if flags == 0 && !force_userns {
        return;
    }

    let need_userns = force_userns || unsafe { libc::unshare(flags) } < 0;
    if need_userns {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
            die_errno!("unshare(CLONE_NEWUSER)");
        }
        // setgroups must be denied before gid_map is written by an
        // unprivileged process.
        write_file("/proc/self/setgroups", "deny");
        write_file("/proc/self/uid_map", &format!("{uid} {uid} 1\n"));
        write_file("/proc/self/gid_map", &format!("{gid} {gid} 1\n"));
        if flags != 0 && unsafe { libc::unshare(flags) } < 0 {
            die_errno!("unshare(CLONE_NEWNET) after userns");
        }
    }
}

fn enter_mount_pid_namespaces() {
    if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) } >= 0 {
        return;
    }
    // Phase 1 didn't take a userns (no NET, not forced). Take it now.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
        die_errno!("unshare(CLONE_NEWUSER)");
    }
    write_file("/proc/self/setgroups", "deny");
    write_file("/proc/self/uid_map", &format!("{uid} {uid} 1\n"));
    write_file("/proc/self/gid_map", &format!("{gid} {gid} 1\n"));
    if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) } < 0 {
        die_errno!("unshare(CLONE_NEWNS|CLONE_NEWPID) after userns");
    }
}

// ---------------------------------------------------------------------------
// Capability drop
// ---------------------------------------------------------------------------

#[repr(C)]
struct CapHeader { version: u32, pid: i32 }
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData { effective: u32, permitted: u32, inheritable: u32 }

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

/// Drop all capabilities (effective + permitted + inheritable) and clear the
/// bounding + ambient sets so execve can't recover any. NO_NEW_PRIVS is
/// already set at the top of `main`, so file caps / setuid can't restore
/// them either.
pub(crate) fn drop_all_caps() {
    unsafe {
        // Clear ambient set wholesale.
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        // Drop every cap from the bounding set. EINVAL = "no such cap", which
        // is the loop terminator on kernels with fewer caps than CAP_LAST_CAP.
        let mut cap = 0;
        loop {
            let r = libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
            if r < 0 {
                match errno() {
                    libc::EINVAL | libc::EPERM => break,
                    _ => die_errno!("prctl(PR_CAPBSET_DROP, {cap})"),
                }
            }
            cap += 1;
        }
        // Zero effective/permitted/inheritable.
        let hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let data = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) < 0 && errno() != libc::EPERM {
            // Some seccomp policies (systemd-nspawn) deny capset; bwrap
            // tolerates EPERM here for the same reason.
            die_errno!("capset");
        }
    }
}

// ---------------------------------------------------------------------------
// Seccomp: baked-in BPF filter that blocks socket(AF_UNIX,...) + io_uring.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const UNIX_BLOCK_BPF: &[u8] = include_bytes!("../bpf/x86_64.bpf");
#[cfg(target_arch = "aarch64")]
const UNIX_BLOCK_BPF: &[u8] = include_bytes!("../bpf/aarch64.bpf");

#[repr(C)]
struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
#[repr(C)]
struct SockFprog { len: u16, filter: *const SockFilter }

fn apply_seccomp_unix_block() {
    // The BPF blob is generated by vendor/seccomp-src/seccomp-unix-block.c at
    // build time. It's an array of 8-byte sock_filter records; assert that.
    assert!(UNIX_BLOCK_BPF.len().is_multiple_of(core::mem::size_of::<SockFilter>()));
    let prog = SockFprog {
        len: (UNIX_BLOCK_BPF.len() / core::mem::size_of::<SockFilter>()) as u16,
        filter: UNIX_BLOCK_BPF.as_ptr().cast(),
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) } < 0 {
        die_errno!("prctl(PR_SET_SECCOMP)");
    }
}

// ---------------------------------------------------------------------------
// Worker: drop caps, apply seccomp, exec.
// ---------------------------------------------------------------------------

fn worker_exec(c: &Config) -> ! {
    drop_all_caps();

    // Export env additions. set_var is `unsafe` (process-global), but we're
    // single-threaded and pre-exec — same constraint bwrap satisfies.
    for (k, v) in &c.env {
        unsafe { std::env::set_var(k, v) };
    }

    // NO_NEW_PRIVS was set at the top of run::main and is inherited; the
    // kernel still requires it on the seccomp-applying thread, which is us.
    if c.seccomp_unix {
        apply_seccomp_unix_block();
    }

    // execvp. Build the *const *const c_char array on the stack.
    let argv: Vec<*const libc::c_char> = c.cmd.iter().map(|s| s.as_ptr()).chain(std::iter::once(ptr::null())).collect();
    unsafe { libc::execvp(argv[0], argv.as_ptr()) };
    die_errno!("execvp {:?}", c.cmd[0]);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main(args: Vec<String>) -> ExitCode {
    let c = parse(args);

    // Set NO_NEW_PRIVS first (bwrap parity), so it's inherited by every
    // subsequent fork — the relays, PID 1, and the worker. unshare(NEWUSER)
    // still grants caps in the new userns regardless; this only blocks
    // setuid/setgid/file-cap escalation on exec, which we never want.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        die_errno!("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    // Die with the parent so we don't orphan a sandbox tree if the host
    // process crashes. Set on the stub here and again on PID 1 below.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
        die_errno!("prctl(PR_SET_PDEATHSIG)");
    }

    // ---- Phase 1: USER? + NET. Relays fork here, before NS|PID. ----
    // DUMPABLE stays 1 across both namespace phases: writing
    // /proc/self/{setgroups,uid_map,gid_map} requires the files be owned by
    // us, and with DUMPABLE=0 they're root-owned. The relays and PID 1 set
    // DUMPABLE=0 themselves immediately after fork.
    enter_net_namespace(c.unshare_net, c.unshare_user);

    let mut relay_pids: Vec<libc::pid_t> = Vec::with_capacity(c.relays.len());
    if c.unshare_net {
        // lo must be up for the relay to bind 127.0.0.1; the stub holds the
        // netns so this carries through to PID 1 and the worker.
        net::loopback_up();
        // Relays fork now: {host pidns, host mountns, sandbox netns}. The
        // workload has no PID for them (they're outside its pidns), and they
        // resolve the bridge unix-socket path in the *host* mountns — the
        // workload cannot swap that path. They inherit DUMPABLE=0. They run
        // without seccomp (they need socket(AF_UNIX)); their caps are dropped
        // inside relay_fork.
        for r in &c.relays {
            relay_pids.push(net::relay_fork(r));
        }
    }

    // ---- Phase 2: NS + PID. ----
    enter_mount_pid_namespaces();

    // DUMPABLE=0 from here protects the stub and is inherited by PID 1.
    // (Set after the userns map writes, which need /proc/self/* to be owned
    // by us.) The relays set it themselves in relay_fork. The relays and stub
    // live in the *host* pidns, so the workload has no PID for them —
    // DUMPABLE=0 is defense-in-depth for the --host-proc case where they're
    // visible at host PIDs.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } < 0 {
        die_errno!("prctl(PR_SET_DUMPABLE)");
    }

    // Fork: parent stays in the host PID ns as the stub; child is PID 1 in
    // the new PID ns (unshare(CLONE_NEWPID) puts *children*, not us, there).
    let pid1 = unsafe { libc::fork() };
    if pid1 < 0 {
        die_errno!("fork (PID 1)");
    }
    if pid1 > 0 {
        // ---- stub: forward signals to PID 1, reap relays + PID 1. ----
        install_forwarders(pid1);
        drop_all_caps();
        // The stub now has both relays and pid1 as children; reap_until
        // collects whichever exits first and returns when pid1 does.
        let code = reap_until(pid1);
        // Relays don't get the kernel's pidns-teardown SIGKILL (they're in
        // the host pidns). Tear them down explicitly. Each relay setpgid'd
        // itself, so kill(-pid) reaches its per-connection children too.
        for pid in relay_pids {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
        return ExitCode::from(code as u8);
    }

    // =======================================================================
    // PID 1 in the sandbox.
    // =======================================================================

    // Inherited DUMPABLE=0 from the stub blocks ptrace and /proc/1/mem
    // writes against this process. PDEATHSIG was cleared by fork; re-set it.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };

    // setsid drops the controlling terminal — the TIOCSTI defense. Runs
    // before forking so the worker shares the new session.
    if unsafe { libc::setsid() } < 0 {
        die_errno!("setsid");
    }

    // Capture the spawn-time cwd before the pivot invalidates it, so we can
    // restore it (best-effort) for the worker. This is bwrap's behavior:
    // inherit the caller's cwd if it survives the mount setup, else land in /.
    let spawn_cwd = std::env::current_dir().ok();

    // Filesystem setup happens here so PID 1 (which mounts /proc) is in the
    // pidns whose process list /proc should reflect.
    mount::setup_filesystem(&c.ops);

    // Restore cwd best-effort; if the path doesn't exist inside the sandbox,
    // we stay in / (where setup_filesystem left us).
    if let Some(cwd) = spawn_cwd {
        let _ = std::env::set_current_dir(&cwd);
    }

    // Fork the worker so PID 1 stays as a non-dumpable reaper.
    let worker = unsafe { libc::fork() };
    if worker < 0 {
        die_errno!("fork (worker)");
    }
    if worker == 0 {
        worker_exec(&c);
    }

    // PID 1: reap everything, exit with the worker's status. PID 1 drops
    // signals without handlers, so install forwarders before reaping.
    install_forwarders(worker);
    drop_all_caps();
    let code = reap_until(worker);
    unsafe { libc::_exit(code) }
}
