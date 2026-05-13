//! `srt-launcher run` — the per-command sandbox.
//!
//! Process tree (one wrapped command, network restrictions on):
//!
//!   srt-launcher run [stub]            host pid ns; waits, forwards signals
//!   ═══════════════════════════════════ user/mount/pid[/net] ns boundary
//!   └─ srt-launcher run [PID 1]        DUMPABLE=0; pivot_root; reaper
//!      ├─ relay (3128)                 DUMPABLE=0 inherited; no seccomp
//!      ├─ relay (1080)                 DUMPABLE=0 inherited; no seccomp
//!      └─ worker                       seccomp applied, then execvp
//!
//! There is no nested PID namespace. apply-seccomp needed one to hide bwrap's
//! init (which we didn't control) from the seccomp'd worker; here PID 1 and
//! the relays are all our own forks with PR_SET_DUMPABLE=0 set before any of
//! them is created, so the worker can't ptrace or write /proc/N/mem against
//! them regardless of kernel.yama.ptrace_scope. One namespace layer.

use crate::mount::{self, MountOp};
use crate::net::{self, RelaySpec};
use crate::{die, die_errno, errno_str};
use std::ffi::CString;
use std::io::Write as _;
use std::mem::zeroed;
use std::process::ExitCode;
use std::ptr;

// ---------------------------------------------------------------------------
// Config + argv parsing
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Config {
    new_session: bool,
    die_with_parent: bool,
    unshare_net: bool,
    unshare_pid: bool,
    /// Force --unshare-user even when EUID == 0. Needed in unprivileged
    /// containers (Docker default: EUID=0 without CAP_SYS_ADMIN) where direct
    /// clone EPERMs and the userns path is the only way in.
    unshare_user: bool,
    seccomp_unix: bool,
    ops: Vec<MountOp>,
    relays: Vec<RelaySpec>,
    env: Vec<(String, String)>,
    /// argv for the worker. CStrings are built before fork so the post-fork
    /// path doesn't allocate.
    cmd: Vec<CString>,
    /// chdir target inside the sandbox; defaults to inherited cwd if it
    /// survives the pivot, else "/".
    chdir: Option<String>,
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
            "--new-session" => c.new_session = true,
            "--die-with-parent" => c.die_with_parent = true,
            "--unshare-net" => c.unshare_net = true,
            "--unshare-pid" => c.unshare_pid = true,
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
            "--chdir" => c.chdir = Some(next!("--chdir")),
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

static mut FORWARD_TARGET: libc::pid_t = -1;

extern "C" fn forward_signal(sig: libc::c_int) {
    unsafe {
        if FORWARD_TARGET > 0 {
            libc::kill(FORWARD_TARGET, sig);
        }
    }
}

fn install_forwarders(target: libc::pid_t) {
    unsafe {
        FORWARD_TARGET = target;
        let mut sa: libc::sigaction = zeroed();
        sa.sa_sigaction = forward_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT, libc::SIGUSR1, libc::SIGUSR2] {
            libc::sigaction(s, &sa, ptr::null_mut());
        }
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
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return 1; // ECHILD without seeing main_child — shouldn't happen.
        }
        if r == main_child {
            return if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            };
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
            if f.write_all(content.as_bytes()).is_err() {
                die_errno!("write {path}");
            }
        }
        Err(e) => die!("open {path}: {e}"),
    }
}

fn enter_namespaces(c: &Config) {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    // Try direct unshare first (succeeds when we already have CAP_SYS_ADMIN).
    // Otherwise create a user namespace to get it. unshare_user forces the
    // userns path even at EUID 0, for unprivileged-container hosts.
    let mut flags = libc::CLONE_NEWNS;
    if c.unshare_pid { flags |= libc::CLONE_NEWPID }
    if c.unshare_net { flags |= libc::CLONE_NEWNET }

    let need_userns = c.unshare_user || unsafe { libc::unshare(flags) } < 0;
    if need_userns {
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
            die_errno!("unshare(CLONE_NEWUSER)");
        }
        // setgroups must be denied before gid_map is written by an
        // unprivileged process.
        write_file("/proc/self/setgroups", "deny");
        write_file("/proc/self/uid_map", &format!("{uid} {uid} 1\n"));
        write_file("/proc/self/gid_map", &format!("{gid} {gid} 1\n"));
        if unsafe { libc::unshare(flags) } < 0 {
            die_errno!("unshare(NS|PID|NET) after userns");
        }
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
fn drop_all_caps() {
    unsafe {
        // Clear ambient set wholesale.
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        // Drop every cap from the bounding set. EINVAL = "no such cap", which
        // is the loop terminator on kernels with fewer caps than CAP_LAST_CAP.
        let mut cap = 0;
        loop {
            let r = libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
            if r < 0 {
                let e = *libc::__errno_location();
                if e == libc::EINVAL { break }
                if e == libc::EPERM { break } // already dropped or not permitted; fine
                die_errno!("prctl(PR_CAPBSET_DROP, {cap})");
            }
            cap += 1;
        }
        // Zero effective/permitted/inheritable.
        let hdr = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let data = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) < 0 {
            // Some seccomp policies (systemd-nspawn) deny capset; bwrap
            // tolerates EPERM here for the same reason.
            if *libc::__errno_location() != libc::EPERM {
                die_errno!("capset");
            }
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

    // Export env additions. setenv is async-signal-unsafe in the strict POSIX
    // sense, but we're single-threaded and pre-exec, which is what bwrap does.
    for (k, v) in &c.env {
        let kc = CString::new(k.as_str()).unwrap();
        let vc = CString::new(v.as_str()).unwrap();
        unsafe { libc::setenv(kc.as_ptr(), vc.as_ptr(), 1) };
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
    // subsequent fork — PID 1, the relays, and the worker. unshare(NEWUSER)
    // still grants caps in the new userns regardless; this only blocks
    // setuid/setgid/file-cap escalation on exec, which we never want.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        die_errno!("prctl(PR_SET_NO_NEW_PRIVS)");
    }
    // The outer stub also needs --die-with-parent so we don't orphan a whole
    // sandbox tree if the host process crashes.
    if c.die_with_parent && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } < 0 {
        die_errno!("prctl(PR_SET_PDEATHSIG)");
    }

    enter_namespaces(&c);

    // Fork: parent stays in the host PID ns as the stub; child is PID 1 in
    // the new PID ns (unshare(CLONE_NEWPID) puts *children*, not us, there).
    let pid1 = unsafe { libc::fork() };
    if pid1 < 0 {
        die_errno!("fork (PID 1)");
    }
    if pid1 > 0 {
        // ---- outer stub: forward signals, wait for PID 1. ----
        install_forwarders(pid1);
        let mut status = 0;
        loop {
            let r = unsafe { libc::waitpid(pid1, &mut status, 0) };
            if r < 0 && unsafe { *libc::__errno_location() } == libc::EINTR { continue }
            break;
        }
        let code = if libc::WIFSIGNALED(status) { 128 + libc::WTERMSIG(status) }
                   else if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) }
                   else { 1 };
        return ExitCode::from(code as u8);
    }

    // =======================================================================
    // PID 1 in the sandbox.
    // =======================================================================

    // Block ptrace and /proc/1/mem writes against this process and every
    // child forked from here (relays). This is what makes the single-layer
    // architecture safe without apply-seccomp's nested PID namespace.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } < 0 {
        die_errno!("prctl(PR_SET_DUMPABLE)");
    }
    if c.die_with_parent {
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    }

    // setsid before forking so the relays and worker share the new session.
    // This drops the controlling terminal — the TIOCSTI defense.
    if c.new_session && unsafe { libc::setsid() } < 0 {
        die_errno!("setsid");
    }

    // Capture the spawn-time cwd before the pivot invalidates it, so we can
    // restore it (best-effort) for the worker. This is bwrap's behavior:
    // inherit the caller's cwd if it survives the mount setup, else land in /.
    let spawn_cwd = std::env::current_dir().ok();

    // Filesystem setup happens before relays/worker so they all see the
    // pivoted root.
    mount::setup_filesystem(&c.ops);

    // Restore cwd. --chdir wins; otherwise the captured spawn-time cwd; if
    // that path doesn't exist inside the sandbox, fall through to / (which is
    // where setup_filesystem left us).
    if let Some(d) = c.chdir.as_deref() {
        let dc = CString::new(d).unwrap();
        if unsafe { libc::chdir(dc.as_ptr()) } < 0 {
            die_errno!("chdir {d}");
        }
    } else if let Some(cwd) = spawn_cwd {
        let _ = std::env::set_current_dir(&cwd);
    }

    if c.unshare_net {
        net::loopback_up();
    }

    // Fork relays. They inherit DUMPABLE=0. They run *without* seccomp — they
    // need socket(AF_UNIX) to reach the host bridge socket.
    for r in &c.relays {
        net::relay_fork(r);
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
