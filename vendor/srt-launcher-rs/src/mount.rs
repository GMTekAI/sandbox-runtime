//! Filesystem setup: bind / ro-bind / tmpfs / dev / proc, the pivot_root
//! sequence, and the mountinfo-driven recursive remount.
//!
//! This is the security-critical module. It is intentionally written against
//! raw `libc::mount` / syscalls so it reads like `bubblewrap.c` /
//! `bind-mount.c`, which is what it's reviewed against. The structure follows
//! bwrap closely:
//!
//!   1. mark / as MS_SLAVE|MS_REC so our mounts don't propagate to the host
//!   2. mount a tmpfs at BASE, mkdir newroot+oldroot, pivot_root into BASE
//!   3. apply each mount op with src under /oldroot and dst under /newroot
//!   4. detach /oldroot, second pivot_root(., .) to make /newroot the real /
//!
//! The single recurring footgun: `MS_BIND` ignores `MS_RDONLY`/`MS_NOSUID`/
//! `MS_NODEV`. They only take effect on `MS_REMOUNT`, and a recursive bind
//! brings every submount along — each needing its own remount. We walk
//! /proc/self/mountinfo for that, same as bwrap.

use crate::{die, die_errno, errno_str};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::ptr;

const BASE: &str = "/tmp";
const OLDROOT: &str = "/oldroot";
const NEWROOT: &str = "/newroot";

#[derive(Clone)]
pub enum MountOp {
    Bind { src: String, dst: String },
    RoBind { src: String, dst: String },
    Tmpfs { dst: String },
    Dev { dst: String },
    /// `host = true`: bind the host /proc instead of mounting a fresh procfs.
    /// Used in unprivileged-container environments where the host /proc has
    /// masked subpaths and a fresh procfs mount fails the kernel's "fully
    /// visible" check.
    Proc { dst: String, host: bool },
}

bitflags_lite! {
    pub struct BindFlags: u32 {
        const READONLY = 1 << 0;
        // DEVICES: don't add nodev — the /dev/* nodes are device nodes.
        const DEVICES  = 1 << 1;
    }
}

// ---------------------------------------------------------------------------
// libc helpers
// ---------------------------------------------------------------------------

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| die!("path contains interior NUL: {s:?}"))
}

fn mount(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), ()> {
    let src_c = src.map(cstr);
    let tgt_c = cstr(target);
    let fst_c = fstype.map(cstr);
    let dat_c = data.map(cstr);
    let r = unsafe {
        libc::mount(
            src_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            tgt_c.as_ptr(),
            fst_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            flags,
            dat_c.as_ref().map_or(ptr::null(), |c| c.as_ptr().cast()),
        )
    };
    if r < 0 { Err(()) } else { Ok(()) }
}

fn mount_or_die(src: Option<&str>, target: &str, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>, what: &str) {
    if mount(src, target, fstype, flags, data).is_err() {
        die_errno!("{what}");
    }
}

fn pivot_root(new: &str, old: &str) -> Result<(), ()> {
    let n = cstr(new);
    let o = cstr(old);
    let r = unsafe { libc::syscall(libc::SYS_pivot_root, n.as_ptr(), o.as_ptr()) };
    if r < 0 { Err(()) } else { Ok(()) }
}

// ---------------------------------------------------------------------------
// Path joining
// ---------------------------------------------------------------------------

/// Join a fixed prefix and an absolute path, dropping any trailing '/' from
/// the result. The trailing-slash strip is load-bearing: it arises for
/// `--ro-bind / /`, and a trailing '/' breaks the prefix match in
/// `for_each_mount_under` ("/newroot/tmp" doesn't start_with "/newroot/"+'/'
/// when the root is "/newroot/"), so no submounts of / would be remounted
/// read-only. Do not simplify away.
fn prefix_path(prefix: &str, path: &str) -> String {
    if !path.starts_with('/') {
        die!("mount path is not absolute: {path}");
    }
    let mut s = format!("{prefix}{path}");
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

// ---------------------------------------------------------------------------
// /proc/self/mountinfo walk
// ---------------------------------------------------------------------------

/// Parse the per-mount option string from mountinfo field 6 into MS_* flags.
/// Only the flags we care about for the remount: ro/nosuid/nodev/noexec/
/// noatime/nodiratime/relatime. Unknown tokens are ignored.
fn parse_mount_flags(opts: &str) -> libc::c_ulong {
    let mut f = 0;
    for tok in opts.split(',') {
        f |= match tok {
            "ro" => libc::MS_RDONLY,
            "nosuid" => libc::MS_NOSUID,
            "nodev" => libc::MS_NODEV,
            "noexec" => libc::MS_NOEXEC,
            "noatime" => libc::MS_NOATIME,
            "nodiratime" => libc::MS_NODIRATIME,
            "relatime" => libc::MS_RELATIME,
            _ => 0,
        };
    }
    f
}

/// mountinfo escapes ' ', '\t', '\n', '\\' as octal `\040` etc. Undo that.
fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let (Some(a), Some(b), Some(c)) = (
                (bytes[i + 1] as char).to_digit(8),
                (bytes[i + 2] as char).to_digit(8),
                (bytes[i + 3] as char).to_digit(8),
            ) {
                out.push((a * 64 + b * 8 + c) as u8 as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Call `f(mountpoint, current_flags)` for the mount at `root` and every
/// mount whose mountpoint is under `root`. mountinfo is read via the proc fd
/// captured before the first pivot, so it works while /proc is mid-shuffle —
/// /proc itself doesn't exist in the new root at this point, so we openat()
/// against the held fd rather than going through any /proc path.
fn for_each_mount_under(proc_fd: RawFd, root: &str, mut f: impl FnMut(&str, libc::c_ulong)) {
    let fd = unsafe {
        libc::openat(
            proc_fd,
            cstr("self/mountinfo").as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        die_errno!("openat(proc, self/mountinfo)");
    }
    let mut info = String::new();
    {
        use std::io::Read as _;
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        if let Err(e) = file.read_to_string(&mut info) {
            die!("read mountinfo: {e}");
        }
    }
    let root_slash = if root == "/" { "/".to_string() } else { format!("{root}/") };
    for line in info.lines() {
        // Field 5 = mountpoint, field 6 = per-mount options. Fields are
        // space-separated; mountinfo escapes spaces inside paths.
        let mut it = line.split(' ');
        let mp_raw = match it.nth(4) {
            Some(s) => s,
            None => continue,
        };
        let opts = match it.next() {
            Some(s) => s,
            None => continue,
        };
        let mp = unescape_mountinfo(mp_raw);
        if mp == root || mp.starts_with(&root_slash) {
            f(&mp, parse_mount_flags(opts));
        }
    }
}

// ---------------------------------------------------------------------------
// ensure_dst: create the bind-mount target as a file or dir matching src.
// ---------------------------------------------------------------------------

fn ensure_dst(dst: &str, is_dir: bool) {
    let p = Path::new(dst);
    // If the dest already exists, don't touch it. open(O_CREAT|O_WRONLY) on an
    // existing file requires write permission on the file, and mkdir on an
    // existing dir requires write permission on the parent — neither of which
    // we have when the dest is inside an already-ro bind. bwrap's
    // ensure_file/ensure_dir do the same lstat-then-skip.
    if let Ok(md) = fs::symlink_metadata(p) {
        // A pre-existing symlink at the dest is fine if it points at the right
        // kind of thing (the kernel will mount over the symlink itself, not
        // its target, but creating a mount-point file behind a symlink would
        // EEXIST). Don't try to "fix" the kind; the mount() call will fail
        // loud if the kind is wrong.
        let _ = md;
        return;
    }
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }
    if is_dir {
        if let Err(e) = fs::create_dir(p) {
            die!("mkdir {dst}: {e}")
        }
    } else {
        // mknod(S_IFREG) instead of open(O_CREAT|O_WRONLY): we only need a
        // dentry to bind over, not a writable fd, and open() would fail on a
        // 0444 dest we just created under umask 0.
        let dc = cstr(dst);
        if unsafe { libc::mknod(dc.as_ptr(), libc::S_IFREG | 0o444, 0) } < 0 {
            die_errno!("create {dst}");
        }
    }
}

// ---------------------------------------------------------------------------
// Mount ops
// ---------------------------------------------------------------------------

fn do_bind(proc_fd: RawFd, src: &str, dst: &str, bf: BindFlags) {
    let real_src = prefix_path(OLDROOT, src);
    let real_dst = prefix_path(NEWROOT, dst);

    // Follow symlinks: a bind mount of a symlink mounts what it points at, so
    // the mount-point dentry kind must match the *target*, not the link. (`/bin
    // -> usr/bin` needs a directory dst, not a file.) bwrap's
    // resolve_symlinks_in_ops does the same.
    let md = match fs::metadata(&real_src) {
        Ok(m) => m,
        Err(e) => die!("bind source {real_src}: {e}"),
    };
    ensure_dst(&real_dst, md.is_dir());

    mount_or_die(
        Some(&real_src),
        &real_dst,
        None,
        libc::MS_SILENT | libc::MS_BIND | libc::MS_REC,
        None,
        &format!("bind {real_src} -> {real_dst}"),
    );

    // MS_BIND ignores MS_RDONLY/MS_NOSUID/MS_NODEV — they only take effect on
    // MS_REMOUNT. A recursive bind brings submounts along, each needing its
    // own remount. Mirrors bwrap's bind_mount(): always nosuid; nodev unless
    // BIND_DEVICES; rdonly when requested. Compute new = current | add and
    // skip when nothing would change.
    let add = libc::MS_NOSUID
        | if bf.contains(BindFlags::DEVICES) { 0 } else { libc::MS_NODEV }
        | if bf.contains(BindFlags::READONLY) { libc::MS_RDONLY } else { 0 };

    for_each_mount_under(proc_fd, &real_dst, |mp, cur| {
        let new = cur | add;
        if new == cur {
            return;
        }
        if mount(None, mp, None, libc::MS_SILENT | libc::MS_BIND | libc::MS_REMOUNT | new, None).is_err() {
            // EACCES: a mount we can't read can't be reached by the sandbox
            // either, so there's nothing to harden (bwrap behavior). EINVAL/
            // ENOENT: a submount raced away between mountinfo and remount.
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EINVAL && errno != libc::ENOENT && errno != libc::EACCES {
                die_errno!("remount {mp}");
            }
        }
    });
}

fn do_tmpfs(dst: &str) {
    let real_dst = prefix_path(NEWROOT, dst);
    ensure_dst(&real_dst, true);
    mount_or_die(
        Some("tmpfs"),
        &real_dst,
        Some("tmpfs"),
        libc::MS_SILENT | libc::MS_NOSUID | libc::MS_NODEV,
        Some("mode=755"),
        &format!("mount tmpfs {real_dst}"),
    );
}

fn do_proc(proc_fd: RawFd, dst: &str, host_proc: bool) {
    let real_dst = prefix_path(NEWROOT, dst);
    ensure_dst(&real_dst, true);

    if host_proc {
        // Unprivileged container: a fresh procfs mount fails the kernel's
        // "fully visible" check because the host /proc has masked subpaths.
        // Bind the host /proc instead — leakier, but the only thing that
        // works there.
        mount_or_die(
            Some(&format!("{OLDROOT}/proc")),
            &real_dst,
            None,
            libc::MS_SILENT | libc::MS_BIND | libc::MS_REC,
            None,
            &format!("bind host /proc -> {real_dst}"),
        );
        return;
    }

    mount_or_die(
        Some("proc"),
        &real_dst,
        Some("proc"),
        libc::MS_SILENT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
        &format!("mount proc {real_dst}"),
    );

    // Cover writable /proc subdirs that can affect the host even from an
    // unprivileged process in some configurations (sysrq-trigger). bwrap parity.
    for sub in &["sys", "sysrq-trigger", "irq", "bus"] {
        let p = format!("{real_dst}/{sub}");
        let cp = cstr(&p);
        if unsafe { libc::access(cp.as_ptr(), libc::W_OK) } < 0 {
            continue; // already ro or missing — nothing to harden
        }
        if mount(Some(&p), &p, None, libc::MS_SILENT | libc::MS_BIND, None).is_err() {
            die_errno!("cover {p}");
        }
        for_each_mount_under(proc_fd, &p, |mp, cur| {
            let new = cur | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_RDONLY;
            if new != cur {
                let _ = mount(None, mp, None, libc::MS_SILENT | libc::MS_BIND | libc::MS_REMOUNT | new, None);
            }
        });
    }
}

fn do_dev(proc_fd: RawFd, dst: &str) {
    let real_dst = prefix_path(NEWROOT, dst);
    ensure_dst(&real_dst, true);
    mount_or_die(
        Some("tmpfs"),
        &real_dst,
        Some("tmpfs"),
        libc::MS_SILENT | libc::MS_NOSUID,
        Some("mode=755,size=65536k"),
        &format!("mount tmpfs {real_dst}"),
    );

    // Bind the basic device nodes from the host. BIND_DEVICES: nosuid yes,
    // nodev no — these ARE device nodes.
    for n in &["null", "zero", "full", "random", "urandom", "tty"] {
        let host_src = format!("{OLDROOT}/dev/{n}");
        if !Path::new(&host_src).exists() {
            continue; // containers often lack /dev/full; skip absent nodes
        }
        do_bind(proc_fd, &format!("/dev/{n}"), &format!("{dst}/{n}"), BindFlags::DEVICES);
    }

    // /dev/stdin etc. → /proc/self/fd/N
    for (i, name) in ["stdin", "stdout", "stderr"].iter().enumerate() {
        let link = format!("{real_dst}/{name}");
        if let Err(e) = std::os::unix::fs::symlink(format!("/proc/self/fd/{i}"), &link) {
            die!("symlink {link}: {e}");
        }
    }
    let _ = std::os::unix::fs::symlink("/proc/self/fd", format!("{real_dst}/fd"));
    let _ = std::os::unix::fs::symlink("/proc/kcore", format!("{real_dst}/core"));

    // devpts + /dev/ptmx + /dev/shm
    let pts = format!("{real_dst}/pts");
    let shm = format!("{real_dst}/shm");
    if let Err(e) = fs::create_dir(&pts) { die!("mkdir {pts}: {e}") }
    if let Err(e) = fs::create_dir(&shm) { die!("mkdir {shm}: {e}") }
    mount_or_die(
        Some("devpts"),
        &pts,
        Some("devpts"),
        libc::MS_SILENT | libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
        &format!("mount devpts {pts}"),
    );
    if let Err(e) = std::os::unix::fs::symlink("pts/ptmx", format!("{real_dst}/ptmx")) {
        die!("symlink {real_dst}/ptmx: {e}");
    }

    // If stdin is a tty, expose it as /dev/console so programs that talk to
    // the controlling terminal by name still work.
    if unsafe { libc::isatty(0) } == 1 {
        let mut buf = [0i8; 256];
        if unsafe { libc::ttyname_r(0, buf.as_mut_ptr(), buf.len()) } == 0 {
            let tty = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            let host_tty = format!("{OLDROOT}{tty}");
            if tty.starts_with("/dev/") && Path::new(&host_tty).exists() {
                do_bind(proc_fd, &tty, &format!("{dst}/console"), BindFlags::DEVICES);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level filesystem setup — the pivot_root dance.
// ---------------------------------------------------------------------------

pub fn setup_filesystem(ops: &[MountOp]) {
    // Hold a handle to the host /proc so mountinfo stays readable after the
    // pivot, before the new /proc is mounted.
    let proc_dir = match fs::File::open("/proc") {
        Ok(f) => f,
        Err(e) => die!("open /proc: {e}"),
    };
    let proc_fd = proc_dir.as_raw_fd();

    // Mount-point dentries (mkdir/creat) should get the requested mode
    // exactly, not whatever the inherited umask masks out.
    let old_umask = unsafe { libc::umask(0) };

    // Stop our mount activity from leaking into the host. MS_SLAVE keeps
    // host→sandbox propagation (matching bwrap) while blocking the reverse.
    mount_or_die(None, "/", None, libc::MS_SILENT | libc::MS_SLAVE | libc::MS_REC, None, "mount(/, MS_SLAVE)");

    // Stage the new root in a private tmpfs over /tmp.
    mount_or_die(Some("tmpfs"), BASE, Some("tmpfs"), libc::MS_SILENT | libc::MS_NODEV | libc::MS_NOSUID, None, &format!("mount tmpfs {BASE}"));
    if unsafe { libc::chdir(cstr(BASE).as_ptr()) } < 0 {
        die_errno!("chdir {BASE}");
    }
    if let Err(e) = fs::create_dir("newroot") { die!("mkdir newroot: {e}") }
    // pivot_root requires new_root to itself be a mount point.
    mount_or_die(Some("newroot"), "newroot", None, libc::MS_SILENT | libc::MS_BIND | libc::MS_REC, None, "bind newroot");
    if let Err(e) = fs::create_dir("oldroot") { die!("mkdir oldroot: {e}") }

    if pivot_root(BASE, &format!("{BASE}/oldroot")).is_err() {
        die_errno!("pivot_root");
    }
    if unsafe { libc::chdir(cstr("/").as_ptr()) } < 0 {
        die_errno!("chdir /");
    }

    // Apply each mount op, rewriting SRC under /oldroot and DST under
    // /newroot. Order matters: the TS layer emits the broad ro-bind / /
    // first, then layers narrower binds on top.
    for op in ops {
        match op {
            MountOp::Bind { src, dst } => do_bind(proc_fd, src, dst, BindFlags::empty()),
            MountOp::RoBind { src, dst } => do_bind(proc_fd, src, dst, BindFlags::READONLY),
            MountOp::Tmpfs { dst } => do_tmpfs(dst),
            MountOp::Dev { dst } => do_dev(proc_fd, dst),
            MountOp::Proc { dst, host } => do_proc(proc_fd, dst, *host),
        }
    }

    // Detach the old root. Marking it MS_PRIVATE first prevents the umount
    // from sending an unmount event back to the host.
    mount_or_die(Some("oldroot"), "oldroot", None, libc::MS_SILENT | libc::MS_REC | libc::MS_PRIVATE, None, "mount(oldroot, MS_PRIVATE)");
    if unsafe { libc::umount2(cstr("oldroot").as_ptr(), libc::MNT_DETACH) } < 0 {
        die_errno!("umount oldroot");
    }

    // Swap newroot into place with a second pivot_root(".", ".") instead of
    // chroot(): the kernel only checks old_root is reachable from new_root,
    // not strict containment, so put_old == new_root works. This is what
    // current bubblewrap, runc, and LXC all do; it keeps the namespace's root
    // mount and the process root pointing at the same thing without going
    // through chroot()'s more checkered history.
    if unsafe { libc::chdir(cstr("/newroot").as_ptr()) } < 0 {
        die_errno!("chdir /newroot");
    }
    let rootfd = unsafe { libc::open(cstr("/").as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if rootfd < 0 {
        die_errno!("open / before second pivot");
    }
    if pivot_root(".", ".").is_err() {
        die_errno!("pivot_root(., .)");
    }
    if unsafe { libc::fchdir(rootfd) } < 0 {
        die_errno!("fchdir to old base");
    }
    unsafe { libc::close(rootfd) };
    if unsafe { libc::umount2(cstr(".").as_ptr(), libc::MNT_DETACH) } < 0 {
        die_errno!("umount old base");
    }
    if unsafe { libc::chdir(cstr("/").as_ptr()) } < 0 {
        die_errno!("chdir / (final)");
    }

    unsafe { libc::umask(old_umask) };
    drop(proc_dir);
}

// ---------------------------------------------------------------------------
// A tiny bitflags so we don't pull in the bitflags crate.
// ---------------------------------------------------------------------------

macro_rules! bitflags_lite {
    (pub struct $name:ident : $t:ty { $(const $f:ident = $v:expr;)* }) => {
        #[derive(Clone, Copy)]
        pub struct $name($t);
        #[allow(dead_code)]
        impl $name {
            $(pub const $f: Self = Self($v);)*
            pub const fn empty() -> Self { Self(0) }
            pub const fn contains(self, other: Self) -> bool { self.0 & other.0 == other.0 }
        }
        impl std::ops::BitOr for $name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
        }
    };
}
use bitflags_lite;
