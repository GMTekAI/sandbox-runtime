//! srt-launcher — sandbox-runtime's Linux sandbox helper.
//!
//! Subcommands:
//!   run [opts] -- COMMAND [ARGS...]
//!       Per-command sandbox. Replaces bwrap + apply-seccomp + the in-sandbox
//!       socat relays. unshare(USER|PID|NS[|NET]) → fork PID 1 → mounts +
//!       pivot_root → fork relays → fork worker → seccomp → exec.
//!   relay [--ready-fd N] UNIX_SOCKET TCP_HOST:PORT
//!       Host-side Unix→TCP bridge to an external proxy. Used only when
//!       network.{http,socks}ProxyPort is configured; the internal proxy
//!       listens on the unix socket directly.
//!   connect HOST PORT [--proxy ADDR]
//!       HTTP CONNECT helper for ssh ProxyCommand inside the sandbox.
//!
//! Design notes that apply throughout:
//! - Single-threaded. fork() safety in Rust is about not forking from a
//!   multi-threaded process; we never spawn threads, so std (allocation,
//!   CString, etc.) is safe between fork and exec.
//! - panic = "abort" (Cargo.toml). die!() is the error path everywhere; there
//!   is no recovery story for a failed mount or unshare.
//! - Raw `libc::` for the security-relevant syscalls so the mount/namespace
//!   code reads like bubblewrap.c when reviewed side-by-side.

mod mount;
mod net;
mod run;

use std::env;
use std::ffi::CStr;
use std::process::ExitCode;

/// Abort with a message on stderr. Uses libc `_exit` so no atexit/drop runs —
/// matters in the post-fork paths where we may be PID 1 or a relay child.
macro_rules! die {
    ($($arg:tt)*) => {{
        eprintln!("srt-launcher: {}", format_args!($($arg)*));
        #[allow(unused_unsafe)]
        unsafe { libc::_exit(1) }
    }};
}

/// Like die!, with `: <strerror(errno)>` appended.
macro_rules! die_errno {
    ($($arg:tt)*) => {{
        let e = errno_str();
        eprintln!("srt-launcher: {}: {}", format_args!($($arg)*), e);
        #[allow(unused_unsafe)]
        unsafe { libc::_exit(1) }
    }};
}

pub(crate) use {die, die_errno};

pub(crate) fn errno_str() -> String {
    let e = unsafe { *libc::__errno_location() };
    let s = unsafe { CStr::from_ptr(libc::strerror(e)) };
    s.to_string_lossy().into_owned()
}

fn usage() -> ! {
    eprintln!(
        "usage: srt-launcher run [opts] -- COMMAND [ARGS...]\n       \
         srt-launcher relay [--ready-fd N] UNIX_SOCKET TCP_HOST:PORT\n       \
         srt-launcher connect HOST PORT [--proxy ADDR]"
    );
    std::process::exit(2)
}

fn main() -> ExitCode {
    // Multicall support: when srt-launcher is compiled into a larger binary,
    // the host sets ARGV0=srt-launcher and re-dispatch happens here without
    // consuming an argv slot.
    if env::var("ARGV0").as_deref() == Ok("srt-launcher") {
        unsafe { env::remove_var("ARGV0") };
    }

    let mut args = env::args();
    let _argv0 = args.next();
    let sub = args.next().unwrap_or_else(|| usage());
    let rest: Vec<String> = args.collect();

    match sub.as_str() {
        "run" => run::main(rest),
        "relay" => net::relay_main(rest),
        "connect" => net::connect_main(rest),
        _ => usage(),
    }
}
