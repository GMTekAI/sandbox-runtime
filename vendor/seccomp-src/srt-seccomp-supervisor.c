/*
 * srt-seccomp-supervisor.c - Passive seccomp user-notification observer.
 *
 * Usage: srt-seccomp-supervisor <unix-socket-path>
 *
 * Binds a SOCK_STREAM listener at <unix-socket-path>, prints "READY\n" on
 * stdout, then in a single poll() loop:
 *
 *   - accept() new connections from apply-seccomp instances. Each connection
 *     carries one SCM_RIGHTS message with a SECCOMP_RET_USER_NOTIF listener
 *     fd, optionally preceded by a JSON header line {"encodedCommand":"..."}.
 *   - For every received notify fd: SECCOMP_IOCTL_NOTIF_RECV, validate the
 *     id, copy the path argument(s) out of the tracee with process_vm_readv,
 *     immediately reply with SECCOMP_USER_NOTIF_FLAG_CONTINUE so the tracee
 *     proceeds unmodified, then emit one JSON line per path on stdout.
 *
 * The supervisor is a pure observer: every notification is answered with
 * CONTINUE. If the notify fd dies (all filtered tasks gone) it is dropped
 * from the poll set. If stdout closes (parent gone) the process exits.
 *
 * Compile: gcc -static -O2 -Wall -Wextra -o srt-seccomp-supervisor \
 *              srt-seccomp-supervisor.c
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/openat2.h>

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#  include <linux/ioctl.h>
#  define SECCOMP_IOC_MAGIC '!'
#  define SECCOMP_IOCTL_NOTIF_RECV     _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#  define SECCOMP_IOCTL_NOTIF_SEND     _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#  define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW (SECCOMP_IOC_MAGIC, 2, __u64)
#endif

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#  define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#define MAX_SLOTS      256        /* listener + accepted conns + notify fds */
#define PATH_CAP       3072       /* keep each JSON line under PIPE_BUF */
#define LINE_CAP       4096

enum slot_kind { SLOT_FREE = 0, SLOT_LISTEN, SLOT_CONN, SLOT_NOTIFY };

struct slot {
    enum slot_kind kind;
    char *encoded_cmd;            /* malloc'd; NULL when unknown */
};

static struct pollfd      pfds[MAX_SLOTS];
static struct slot        slots[MAX_SLOTS];
static int                nslots;

static struct seccomp_notif       *g_req;
static struct seccomp_notif_resp  *g_resp;

static int add_slot(int fd, enum slot_kind kind, char *encoded_cmd) {
    if (nslots >= MAX_SLOTS) { close(fd); free(encoded_cmd); return -1; }
    pfds[nslots].fd = fd;
    pfds[nslots].events = POLLIN;
    pfds[nslots].revents = 0;
    slots[nslots].kind = kind;
    slots[nslots].encoded_cmd = encoded_cmd;
    return nslots++;
}

static void drop_slot(int i) {
    close(pfds[i].fd);
    free(slots[i].encoded_cmd);
    nslots--;
    if (i != nslots) { pfds[i] = pfds[nslots]; slots[i] = slots[nslots]; }
}

/* Single write() per line so concurrent emitters never interleave inside a
 * line (writes <= PIPE_BUF to a pipe are atomic; we are the only writer
 * anyway, but a short write on a full pipe would otherwise split a line). */
static void emit_line(const char *buf, size_t len) {
    while (len > 0) {
        ssize_t r = write(STDOUT_FILENO, buf, len);
        if (r < 0) {
            if (errno == EINTR) continue;
            _exit(0);   /* parent closed the pipe — nothing left to do */
        }
        buf += r; len -= (size_t)r;
    }
}

static void json_escape_into(char *dst, size_t dstcap, const char *src, size_t srclen) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < srclen && o + 7 < dstcap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { dst[o++]='\\'; dst[o++]=(char)c; }
        else if (c < 0x20)         { dst[o++]='\\'; dst[o++]='u'; dst[o++]='0'; dst[o++]='0';
                                     dst[o++]=hex[c>>4]; dst[o++]=hex[c&0xf]; }
        else                       { dst[o++]=(char)c; }
    }
    dst[o] = '\0';
}

static ssize_t read_remote_bytes(pid_t pid, unsigned long addr, char *dst, size_t cap) {
    if (addr == 0) return -1;
    struct iovec local  = { .iov_base = dst, .iov_len = cap };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = cap };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static ssize_t read_remote_cstr(pid_t pid, unsigned long addr, char *dst, size_t cap) {
    ssize_t r = read_remote_bytes(pid, addr, dst, cap);
    /* The string may sit at the tail of a mapping; if the full read faults,
     * fall back to a page-bounded first chunk. */
    if (r < 0 && errno == EFAULT) {
        size_t first = 4096 - (addr & 4095);
        if (first > cap) first = cap;
        r = read_remote_bytes(pid, addr, dst, first);
    }
    if (r <= 0) return -1;
    char *nul = memchr(dst, '\0', (size_t)r);
    return nul ? (nul - dst) : r;   /* truncated: caller treats len==cap as cut */
}

static const char *syscall_label(int nr) {
    switch (nr) {
#ifdef SYS_openat
        case SYS_openat:    return "openat";
#endif
#ifdef SYS_openat2
        case SYS_openat2:   return "openat2";
#endif
#ifdef SYS_unlinkat
        case SYS_unlinkat:  return "unlinkat";
#endif
#ifdef SYS_mkdirat
        case SYS_mkdirat:   return "mkdirat";
#endif
#ifdef SYS_symlinkat
        case SYS_symlinkat: return "symlinkat";
#endif
#ifdef SYS_linkat
        case SYS_linkat:    return "linkat";
#endif
#ifdef SYS_renameat
        case SYS_renameat:  return "renameat";
#endif
#ifdef SYS_renameat2
        case SYS_renameat2: return "renameat2";
#endif
#ifdef SYS_connect
        case SYS_connect:   return "connect";
#endif
#ifdef SYS_open
        case SYS_open:      return "open";
#endif
#ifdef SYS_creat
        case SYS_creat:     return "creat";
#endif
#ifdef SYS_unlink
        case SYS_unlink:    return "unlink";
#endif
#ifdef SYS_mkdir
        case SYS_mkdir:     return "mkdir";
#endif
#ifdef SYS_rmdir
        case SYS_rmdir:     return "rmdir";
#endif
#ifdef SYS_rename
        case SYS_rename:    return "rename";
#endif
#ifdef SYS_link
        case SYS_link:      return "link";
#endif
#ifdef SYS_symlink
        case SYS_symlink:   return "symlink";
#endif
#ifdef SYS_truncate
        case SYS_truncate:  return "truncate";
#endif
#ifdef SYS_chmod
        case SYS_chmod:     return "chmod";
#endif
#ifdef SYS_chown
        case SYS_chown:     return "chown";
#endif
#ifdef SYS_lchown
        case SYS_lchown:    return "lchown";
#endif
        default:            return "syscall";
    }
}

static void emit_event(int nr, pid_t pid, const char *path, size_t pathlen,
                       const char *encoded_cmd) {
    char esc[LINE_CAP];
    json_escape_into(esc, sizeof(esc), path, pathlen);
    char line[LINE_CAP + 512];
    int n;
    if (encoded_cmd && encoded_cmd[0]) {
        n = snprintf(line, sizeof(line),
                     "{\"nr\":%d,\"syscall\":\"%s\",\"pid\":%d,\"path\":\"%s\","
                     "\"encodedCommand\":\"%s\"}\n",
                     nr, syscall_label(nr), (int)pid, esc, encoded_cmd);
    } else {
        n = snprintf(line, sizeof(line),
                     "{\"nr\":%d,\"syscall\":\"%s\",\"pid\":%d,\"path\":\"%s\"}\n",
                     nr, syscall_label(nr), (int)pid, esc);
    }
    if (n > 0) emit_line(line, (size_t)(n < (int)sizeof(line) ? n : (int)sizeof(line)-1));
}

/* arg indices that hold a pathname pointer for each trapped syscall.
 * -1 terminates; renameat* report both old and new path. */
static void path_arg_indices(int nr, int out[3]) {
    out[0] = out[1] = out[2] = -1;
    switch (nr) {
#ifdef SYS_openat
        case SYS_openat:    out[0]=1; break;
#endif
#ifdef SYS_openat2
        case SYS_openat2:   out[0]=1; break;
#endif
#ifdef SYS_unlinkat
        case SYS_unlinkat:  out[0]=1; break;
#endif
#ifdef SYS_mkdirat
        case SYS_mkdirat:   out[0]=1; break;
#endif
#ifdef SYS_symlinkat
        case SYS_symlinkat: out[0]=2; break;
#endif
#ifdef SYS_linkat
        case SYS_linkat:    out[0]=3; break;
#endif
#ifdef SYS_renameat
        case SYS_renameat:  out[0]=1; out[1]=3; break;
#endif
#ifdef SYS_renameat2
        case SYS_renameat2: out[0]=1; out[1]=3; break;
#endif
#ifdef SYS_open
        case SYS_open:      out[0]=0; break;
#endif
#ifdef SYS_creat
        case SYS_creat:     out[0]=0; break;
#endif
#ifdef SYS_unlink
        case SYS_unlink:    out[0]=0; break;
#endif
#ifdef SYS_mkdir
        case SYS_mkdir:     out[0]=0; break;
#endif
#ifdef SYS_rmdir
        case SYS_rmdir:     out[0]=0; break;
#endif
#ifdef SYS_rename
        case SYS_rename:    out[0]=0; out[1]=1; break;
#endif
#ifdef SYS_link
        case SYS_link:      out[0]=1; break;
#endif
#ifdef SYS_symlink
        case SYS_symlink:   out[0]=1; break;
#endif
#ifdef SYS_truncate
        case SYS_truncate:  out[0]=0; break;
#endif
#ifdef SYS_chmod
        case SYS_chmod:     out[0]=0; break;
#endif
#ifdef SYS_chown
        case SYS_chown:     out[0]=0; break;
#endif
#ifdef SYS_lchown
        case SYS_lchown:    out[0]=0; break;
#endif
        default: break;
    }
}

/* Returns 1 if slot idx was dropped (caller must not advance its index). */
static int handle_notify(int idx) {
    int fd = pfds[idx].fd;
    /* Kernel requires the request buffer to be zeroed on entry. */
    memset(g_req, 0, sizeof(*g_req));
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, g_req) < 0) {
        if (errno == EINTR) return 0;
        /* ENOTCONN / 0 tasks left, or any other terminal error → drop. */
        drop_slot(idx);
        return 1;
    }

    int nr = g_req->data.nr;
    pid_t pid = (pid_t)g_req->pid;
    __u64 id = g_req->id;

    char paths[2][PATH_CAP];
    ssize_t plen[2] = { -1, -1 };
    int npaths = 0;

    /* Verify the tracee hasn't been recycled before touching its memory. */
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0) {
#ifdef SYS_connect
        if (nr == SYS_connect) {
            struct sockaddr_un sun;
            ssize_t r = read_remote_bytes(pid, (unsigned long)g_req->data.args[1],
                                          (char *)&sun, sizeof(sun));
            if (r >= (ssize_t)sizeof(sa_family_t) && sun.sun_family == AF_UNIX) {
                size_t maxp = (size_t)r - offsetof(struct sockaddr_un, sun_path);
                if (maxp > sizeof(sun.sun_path)) maxp = sizeof(sun.sun_path);
                size_t l = strnlen(sun.sun_path, maxp);
                if (l > 0 || (maxp > 0 && sun.sun_path[0] == '\0')) {
                    if (l > PATH_CAP) l = PATH_CAP;
                    memcpy(paths[0], sun.sun_path, l);
                    plen[0] = (ssize_t)l; npaths = 1;
                }
            }
        } else
#endif
#ifdef SYS_openat2
        if (nr == SYS_openat2) {
            struct open_how how;
            int write_intent = 1;   /* assume write if we can't read the struct */
            if (read_remote_bytes(pid, (unsigned long)g_req->data.args[2],
                                  (char *)&how, sizeof(how)) >= (ssize_t)sizeof(how.flags)) {
                write_intent = (how.flags &
                    ((__u64)O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
            }
            if (write_intent) {
                plen[0] = read_remote_cstr(pid, (unsigned long)g_req->data.args[1],
                                           paths[0], PATH_CAP);
                if (plen[0] >= 0) npaths = 1;
            }
        } else
#endif
        {
            int ai[3]; path_arg_indices(nr, ai);
            for (int k = 0; k < 2 && ai[k] >= 0; k++) {
                plen[k] = read_remote_cstr(pid, (unsigned long)g_req->data.args[ai[k]],
                                           paths[k], PATH_CAP);
                if (plen[k] >= 0) npaths = k + 1;
            }
        }
    }

    /* Let the tracee proceed unchanged. ENOENT here means it was interrupted
     * or died between RECV and SEND — nothing to do. */
    memset(g_resp, 0, sizeof(*g_resp));
    g_resp->id = id;
    g_resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, g_resp) < 0 && errno != ENOENT) {
        /* Any non-ENOENT failure (including EINVAL on pre-5.5 kernels lacking
         * CONTINUE) is unrecoverable for this tracee — drop the fd so it gets
         * ENOSYS rather than hanging on the next trapped call. */
        drop_slot(idx);
        return 1;
    }

    for (int k = 0; k < npaths; k++) {
        if (plen[k] >= 0)
            emit_event(nr, pid, paths[k], (size_t)plen[k], slots[idx].encoded_cmd);
    }
    return 0;
}

/* An accepted connection from apply-seccomp: optional JSON header line
 * followed by one SCM_RIGHTS carrying the notify fd. */
static void handle_conn(int idx) {
    int fd = pfds[idx].fd;
    char buf[512];
    union { struct cmsghdr align; char ctl[CMSG_SPACE(sizeof(int))]; } u;
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) - 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = u.ctl, .msg_controllen = sizeof(u.ctl) };

    ssize_t r = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
    if (r < 0 && errno == EINTR) return;
    if (r <= 0) { drop_slot(idx); return; }
    buf[r] = '\0';

    int nfd = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
            c->cmsg_len >= CMSG_LEN(sizeof(int))) {
            memcpy(&nfd, CMSG_DATA(c), sizeof(int));
        }
    }

    /* Header may carry the encoded command tag for per-command attribution.
     * Anything that looks like an init error from apply-seccomp is forwarded. */
    char *enc = NULL;
    char *p = strstr(buf, "\"encodedCommand\":\"");
    if (p) {
        p += strlen("\"encodedCommand\":\"");
        char *q = strchr(p, '"');
        if (q) { *q = '\0'; enc = strdup(p); }
    } else if (strstr(buf, "observe_init_error")) {
        emit_line(buf, strlen(buf));
        if (buf[strlen(buf)-1] != '\n') emit_line("\n", 1);
    }

    if (nfd < 0) {
        /* No fd yet — stash the tag (if any) on the conn slot and wait for
         * the SCM_RIGHTS message. */
        if (enc) { free(slots[idx].encoded_cmd); slots[idx].encoded_cmd = enc; }
        return;
    }

    /* Replace the connection slot in-place with the notify slot so the
     * caller's index stays valid. */
    if (!enc) { enc = slots[idx].encoded_cmd; slots[idx].encoded_cmd = NULL; }
    close(fd);
    free(slots[idx].encoded_cmd);
    pfds[idx].fd = nfd;
    pfds[idx].events = POLLIN;
    slots[idx].kind = SLOT_NOTIFY;
    slots[idx].encoded_cmd = enc;
}

static int alloc_notif_buffers(void) {
    struct seccomp_notif_sizes sz;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz) < 0) {
        /* Fallback for headers newer than the running kernel. */
        sz.seccomp_notif = sizeof(struct seccomp_notif);
        sz.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);
    }
    size_t reqsz  = sz.seccomp_notif      > sizeof(*g_req)  ? sz.seccomp_notif      : sizeof(*g_req);
    size_t respsz = sz.seccomp_notif_resp > sizeof(*g_resp) ? sz.seccomp_notif_resp : sizeof(*g_resp);
    g_req  = calloc(1, reqsz);
    g_resp = calloc(1, respsz);
    return (g_req && g_resp) ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <unix-socket-path>\n", argv[0]);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    if (alloc_notif_buffers() < 0) { perror("calloc"); return 1; }

    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ls < 0) { perror("socket"); return 1; }

    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    if (strlen(argv[1]) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "socket path too long\n"); return 1;
    }
    strcpy(sa.sun_path, argv[1]);
    unlink(sa.sun_path);
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    if (listen(ls, 64) < 0) { perror("listen"); return 1; }

    add_slot(ls, SLOT_LISTEN, NULL);
    emit_line("READY\n", 6);

    for (;;) {
        int n = poll(pfds, (nfds_t)nslots, -1);
        if (n < 0) { if (errno == EINTR) continue; break; }

        /* Walk backwards so drop_slot's swap-with-last never moves an
         * unvisited entry into a visited index. New slots appended by
         * accept()/handle_conn land past the snapshot and are picked up on
         * the next poll(). */
        for (int i = nslots - 1; i >= 0; i--) {
            short ev = pfds[i].revents;
            if (!(ev & (POLLIN | POLLHUP | POLLERR))) continue;
            switch (slots[i].kind) {
                case SLOT_LISTEN: {
                    int c = accept4(pfds[i].fd, NULL, NULL, SOCK_CLOEXEC);
                    if (c >= 0) add_slot(c, SLOT_CONN, NULL);
                    break;
                }
                case SLOT_CONN:
                    if (ev & POLLIN) handle_conn(i);
                    else             drop_slot(i);
                    break;
                case SLOT_NOTIFY:
                    if (ev & POLLIN) handle_notify(i);
                    else             drop_slot(i);
                    break;
                default: break;
            }
        }
    }
    unlink(sa.sun_path);
    return 0;
}
