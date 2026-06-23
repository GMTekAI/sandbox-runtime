/*
 * apply-seccomp.c - Apply seccomp BPF filter in an isolated PID namespace
 *
 * Usage: apply-seccomp <command> [args...]
 *
 * This program applies a baked-in seccomp BPF filter, isolates the
 * target command in a nested user+PID+mount namespace so it cannot see or
 * ptrace any process that lacks the filter, applies the filter with
 * prctl(PR_SET_SECCOMP), and execs the command.
 *
 * Process layout inside the outer bwrap sandbox:
 *
 *   bwrap init (PID 1)          <- outer PID ns, no seccomp
 *   \_ bash / socat ...         <- outer PID ns, no seccomp
 *      \_ apply-seccomp [outer] <- outer PID ns, waits for inner init
 *         ================================================= PID ns boundary
 *         \_ apply-seccomp [inner init] <- inner PID 1, PR_SET_DUMPABLE=0
 *            \_ user command            <- inner PID 2, seccomp applied
 *
 * From the user command's point of view /proc contains only its own process
 * tree. The bwrap init, bash wrapper, and socat helpers are not addressable,
 * so they cannot be ptraced or patched via /proc/N/mem even on systems with
 * kernel.yama.ptrace_scope=0. The inner init (PID 1) sets PR_SET_DUMPABLE=0
 * so it cannot be ptraced either.
 *
 * Any failure to set up the nested namespaces aborts with a non-zero exit
 * status; we never fall back to running the command without isolation.
 *
 * Compile: gcc -static -O2 -o apply-seccomp apply-seccomp.c
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>

#include "unix-block-bpf.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif

#if defined(__x86_64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define SRT_HAS_X32 1
#elif defined(__aarch64__)
#  define SRT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#  define SRT_HAS_X32 0
#else
#  define SRT_AUDIT_ARCH 0
#  define SRT_HAS_X32 0
#endif

/* ---- Optional passive observation filter -------------------------------
 * When SRT_OBSERVE_SOCK is set, install a second seccomp filter that traps
 * write-intent filesystem syscalls (and connect) to SECCOMP_RET_USER_NOTIF
 * and hand the listener fd to the supervisor over that unix socket. The
 * supervisor replies CONTINUE to every notification, so this never changes
 * the workload's behaviour — it only lets the parent record which paths a
 * sandboxed command tried to touch. Every failure path is non-fatal: log a
 * one-line JSON error on the socket if we managed to connect, then proceed
 * exactly as if SRT_OBSERVE_SOCK were unset. */

#define OBS_WRITE_MASK ((unsigned)(O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND))

static void observe_fail(int sock, const char *why) {
    if (sock >= 0) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
                         "{\"observe_init_error\":\"%s: %s\"}\n",
                         why, strerror(errno));
        if (n > 0) (void)!write(sock, buf, (size_t)n);
        close(sock);
    }
}

static int build_observe_bpf(struct sock_filter *f, int cap) {
    /* Syscalls that always trap. openat/open are handled separately so their
     * flags argument can gate the trap; openat2 traps unconditionally because
     * its flags live behind a userspace pointer the BPF program cannot read.
     * x86_64 still has the legacy non-*at entry points and glibc/coreutils
     * call them directly; aarch64 only ever had the *at forms. */
    static const int trap_nrs[] = {
#ifdef __NR_openat2
        __NR_openat2,
#endif
        __NR_unlinkat, __NR_mkdirat, __NR_symlinkat, __NR_linkat,
#ifdef __NR_renameat
        __NR_renameat,
#endif
        __NR_renameat2, __NR_connect,
#ifdef __x86_64__
        __NR_creat, __NR_unlink, __NR_mkdir, __NR_rmdir, __NR_rename,
        __NR_link, __NR_symlink, __NR_truncate, __NR_chmod,
        __NR_chown, __NR_lchown,
#endif
    };
    const int ntrap = (int)(sizeof(trap_nrs) / sizeof(trap_nrs[0]));

    int n = 0;
    int allow_at, notify_at;
#define EMIT(ins) do { if (n >= cap) return -1; f[n++] = (struct sock_filter)ins; } while (0)

    /* arch check */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, arch)));
    int j_arch = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SRT_AUDIT_ARCH, 0, 0)); /* jf→ALLOW */

    /* nr */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, nr)));
#if SRT_HAS_X32
    int j_x32 = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 0));    /* jt→ALLOW */
#endif

    int j_trap[24];
    for (int i = 0; i < ntrap; i++) {
        j_trap[i] = n;
        EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)trap_nrs[i], 0, 0)); /* jt→NOTIFY */
    }

    /* openat: trap only when flags (args[2]) carry write intent */
    int j_openat = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)__NR_openat, 0, 0)); /* jf→next */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[2])));
    EMIT(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, OBS_WRITE_MASK));
    int j_oat_flags = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0));              /* jt→ALLOW jf→NOTIFY */

#ifdef __x86_64__
    /* open: trap only when flags (args[1]) carry write intent */
    int j_open = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)__NR_open, 0, 0)); /* jf→ALLOW */
    EMIT(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                  offsetof(struct seccomp_data, args[1])));
    EMIT(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, OBS_WRITE_MASK));
    int j_o_flags = n;
    EMIT(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0));              /* jt→ALLOW jf→NOTIFY */
#endif

    allow_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    notify_at = n;
    EMIT(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));

#define TO(idx, tgt) ((unsigned char)((tgt) - (idx) - 1))
    f[j_arch].jf  = TO(j_arch, allow_at);
#if SRT_HAS_X32
    f[j_x32].jt   = TO(j_x32, allow_at);
#endif
    for (int i = 0; i < ntrap; i++) f[j_trap[i]].jt = TO(j_trap[i], notify_at);
#ifdef __x86_64__
    f[j_openat].jf    = TO(j_openat, j_open);
    f[j_oat_flags].jt = TO(j_oat_flags, allow_at);
    f[j_oat_flags].jf = TO(j_oat_flags, notify_at);
    f[j_open].jf      = TO(j_open, allow_at);
    f[j_o_flags].jt   = TO(j_o_flags, allow_at);
    f[j_o_flags].jf   = TO(j_o_flags, notify_at);
#else
    f[j_openat].jf    = TO(j_openat, allow_at);
    f[j_oat_flags].jt = TO(j_oat_flags, allow_at);
    f[j_oat_flags].jf = TO(j_oat_flags, notify_at);
#endif
#undef TO
#undef EMIT
    return n;
}

static void install_observe_filter(void) {
    const char *path = getenv("SRT_OBSERVE_SOCK");
    if (!path || !*path || SRT_AUDIT_ARCH == 0) return;
    unsetenv("SRT_OBSERVE_SOCK");   /* don't leak into the workload */

    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) { observe_fail(-1, "socket"); return; }

    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(sa.sun_path)) { observe_fail(sock, "path"); return; }
    strcpy(sa.sun_path, path);
    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        observe_fail(sock, "connect"); return;
    }

    const char *enc = getenv("SRT_ENCODED_CMD");
    if (enc && *enc) {
        char hdr[768];
        int n = snprintf(hdr, sizeof(hdr), "{\"encodedCommand\":\"%.700s\"}\n", enc);
        if (n > 0) (void)!write(sock, hdr, (size_t)n);
    }

    struct sock_filter filt[48];
    int len = build_observe_bpf(filt, 48);
    if (len < 0) { observe_fail(sock, "bpf"); return; }
    struct sock_fprog prog = { .len = (unsigned short)len, .filter = filt };

    int nfd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (nfd < 0) { observe_fail(sock, "seccomp"); return; }

    char dummy = 'F';
    union { struct cmsghdr align; char ctl[CMSG_SPACE(sizeof(int))]; } u;
    memset(&u, 0, sizeof(u));
    struct iovec iov = { .iov_base = &dummy, .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.ctl, .msg_controllen = sizeof(u.ctl) };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &nfd, sizeof(int));
    if (sendmsg(sock, &msg, 0) < 0) observe_fail(sock, "sendmsg");
    else close(sock);
    close(nfd);   /* supervisor now holds the only reference */
}

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static int write_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (len < 0 || (size_t)len >= sizeof(buf)) {
        errno = EOVERFLOW;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t r = write(fd, buf, (size_t)len);
    int saved = errno;
    close(fd);
    if (r != len) {
        errno = (r < 0) ? saved : EIO;
        return -1;
    }
    return 0;
}

/* PID the current process forwards signals to. Used by both the outer stub
 * (forwards to inner init) and the inner init (forwards to the worker).
 * PID 1 ignores signals it has no handler for, so the inner init MUST install
 * these or SIGTERM from the outside is silently dropped. */
static volatile pid_t forward_target = -1;

static void forward_signal(int sig) {
    if (forward_target > 0) {
        kill(forward_target, sig);
    }
}

static void install_forwarders(pid_t target) {
    forward_target = target;
    struct sigaction sa = { .sa_handler = forward_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

/*
 * Wait for `main_child`, reaping any other children that exit first.
 * Returns as soon as `main_child` terminates — the caller then _exit()s,
 * which as PID 1 tears down the namespace and SIGKILLs any stragglers.
 * Returns an exit(3)-style status: exit code, or 128+signal.
 */
static int reap_until(pid_t main_child) {
    int status = 0;
    for (;;) {
        pid_t r = waitpid(-1, &status, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1;  /* ECHILD without seeing main_child — shouldn't happen. */
        }
        if (r == main_child) {
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            }
            if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 1;
        }
        /* Reaped an orphan that died before main_child; keep waiting. */
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    char **command_argv = &argv[1];

    _Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
                   "BPF filter size must be a multiple of sock_filter");
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(unix_block_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)unix_block_bpf,
    };

    /* ---- New PID + mount namespaces. Children (not us) enter the PID ns. ----
     *
     * Two paths to get CAP_SYS_ADMIN for the unshare:
     *   (a) The caller (bwrap) kept CAP_SYS_ADMIN in this user namespace via
     *       --cap-add. Just unshare directly.
     *   (b) We don't have the cap. Create a nested user namespace to get it,
     *       map uid/gid, then unshare. This also works when apply-seccomp is
     *       run standalone outside bwrap.
     *
     * Path (a) is tried first. If the caller didn't give us the cap, the
     * kernel returns EPERM and we fall through to (b). Path (b) can itself
     * fail on hosts where unprivileged user namespaces are gated by an LSM
     * (Ubuntu 24.04's AppArmor restriction, for example) — the unshare
     * succeeds but the new namespace grants no capabilities, so the setgroups
     * write fails. In that case we abort: the caller must supply CAP_SYS_ADMIN.
     */
    if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
        if (errno != EPERM) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS)");
        }

        uid_t uid = geteuid();
        gid_t gid = getegid();

        if (unshare(CLONE_NEWUSER) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWUSER)");
        }
        if (write_file("/proc/self/setgroups", "deny") < 0) {
            die("apply-seccomp: write /proc/self/setgroups "
                "(nested userns is capability-restricted; "
                "caller must provide CAP_SYS_ADMIN)");
        }
        if (write_file("/proc/self/uid_map", "%u %u 1\n", uid, uid) < 0) {
            die("apply-seccomp: write /proc/self/uid_map");
        }
        if (write_file("/proc/self/gid_map", "%u %u 1\n", gid, gid) < 0) {
            die("apply-seccomp: write /proc/self/gid_map");
        }
        if (unshare(CLONE_NEWPID | CLONE_NEWNS) < 0) {
            die("apply-seccomp: unshare(CLONE_NEWPID|CLONE_NEWNS) after userns");
        }
    }

    pid_t child = fork();
    if (child < 0) {
        die("apply-seccomp: fork");
    }

    if (child > 0) {
        /* Outer stub: still in bwrap's PID namespace. Forward signals and
         * wait so the caller sees the real exit status. */
        install_forwarders(child);

        int status;
        for (;;) {
            pid_t r = waitpid(child, &status, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) die("apply-seccomp: waitpid");
            break;
        }
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }

    /* ================================================================
     * Inner init — PID 1 in the nested PID namespace.
     * ================================================================ */

    /* Block ptrace and /proc/1/mem writes against this process. */
    if (prctl(PR_SET_DUMPABLE, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_DUMPABLE)");
    }

    /* Don't let our /proc mount propagate anywhere. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        die("apply-seccomp: mount(MS_PRIVATE)");
    }
    /* EPERM here means a masked /proc is underneath (unprivileged Docker)
     * and the kernel domination check refused the overmount. The nested
     * userns above is the isolation boundary; this remount only hides
     * outer PIDs from `ls /proc`. enableWeakerNestedSandbox targets
     * exactly this environment. */
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0
        && errno != EPERM) {
        die("apply-seccomp: mount(/proc)");
    }

    /* bwrap --cap-add places CAP_SYS_ADMIN in the ambient set so it survives
     * exec. Clear it now that the mount is done; combined with
     * PR_SET_NO_NEW_PRIVS, the worker's execve drops to zero capabilities. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_CAP_AMBIENT_CLEAR_ALL)");
    }

    /* Fork the real workload so PID 1 can stay as a non-dumpable reaper. */
    pid_t worker = fork();
    if (worker < 0) {
        die("apply-seccomp: fork(worker)");
    }

    if (worker > 0) {
        /* Inner init: reap everything, exit with the worker's status.
         * When PID 1 exits the kernel tears down the whole namespace.
         * PID 1 drops signals without handlers, so install forwarders. */
        install_forwarders(worker);
        _exit(reap_until(worker));
    }

    /* ---- Worker (inner PID 2): apply seccomp and exec. ---- */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        die("apply-seccomp: prctl(PR_SET_NO_NEW_PRIVS)");
    }
    /* Best-effort: hand a USER_NOTIF listener to the supervisor so it can
     * record write-intent paths. Runs before the unix-block filter so the
     * AF_UNIX connect() is still permitted, and before exec so only the
     * workload is observed. Never fatal. */
    install_observe_filter();
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        die("apply-seccomp: prctl(PR_SET_SECCOMP)");
    }

    execvp(command_argv[0], command_argv);
    die("apply-seccomp: execvp");
    return 1;
}
