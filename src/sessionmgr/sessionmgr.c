/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */
/*
 * sessionmgr.c -- rdp-sessionmgr daemon.
 *
 * One AF_UNIX SOCK_SEQPACKET socket, one process per request flow
 * is the model: the daemon accepts a connection, services any
 * sequence of operations on that connection (AUTH then SPAWN), and
 * closes when the worker hangs up.  The connection itself carries
 * the per-flow state -- specifically, which user was authenticated
 * -- so SPAWN can fork as that user without re-presenting creds.
 *
 * AUTH calls into the configured backend (PAM or bsd_auth).  SPAWN
 * fork()s, drops privileges in the child via setresuid/setresgid +
 * initgroups, and exec()s rdp-session with one end of a SOCK_STREAM
 * socketpair on fd 3.  The other end goes back to the worker via
 * SCM_RIGHTS in the SPAWN reply.
 */

#define _GNU_SOURCE   /* setresuid/setresgid + getgrouplist on glibc */

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include "auth.h"
#include "protocol.h"
#include "../common/rand.h"
#include "../common/utf16.h"

#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#if HAVE_FUSE
#include <sys/mount.h>   /* mount(2), umount2(2), MS_* */
#endif
#if HAVE_OBSD_FUSE
#include <sys/queue.h>   /* SIMPLEQ_ENTRY, needed by <sys/fusebuf.h> */
#include <sys/statvfs.h> /* struct statvfs, used in the fusebuf FD union */
#include <sys/mount.h>   /* mount(2), unmount(2), MOUNT_FUSEFS, MNT_*, fusefs_args */
#include <sys/fusebuf.h> /* FUSEBUFMAXSIZE */
#endif

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RDP_SESSMGR_BACKLOG 16

#ifndef RDP_SESSION_PATH
# define RDP_SESSION_PATH "/usr/local/sbin/rdp-session"
#endif

static const char *session_path = RDP_SESSION_PATH;

/* Max desktop size handed to each rdp-session for dynamic resize; the session
 * sizes its Xvfb framebuffer to this so the desktop can grow up to here. */
static int max_w = 3840, max_h = 2160;

static volatile sig_atomic_t want_shutdown;

static void
on_signal(int sig)
{
	(void)sig;
	want_shutdown = 1;
}

#if HAVE_FUSE || HAVE_OBSD_FUSE
static void fuse_mount_reap(pid_t pid);
#endif

static void
on_sigchld(int sig)
{
	int saved = errno;
	pid_t p;
	(void)sig;
	while ((p = waitpid(-1, NULL, WNOHANG)) > 0) {
#if HAVE_FUSE || HAVE_OBSD_FUSE
		/* Tear down (Linux) or queue the teardown of (OpenBSD) the
		 * dead session's RemoteDrive, if any. */
		fuse_mount_reap(p);
#else
		(void)p;
#endif
	}
	errno = saved;
}

static void
install_signal_handlers(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGTERM, &sa, NULL);
	(void)sigaction(SIGINT,  &sa, NULL);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_sigchld;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGCHLD, &sa, NULL);
}

static int
bind_listener(const char *path)
{
	struct sockaddr_un sun;
	int fd;
	mode_t old;

	if (strlen(path) >= sizeof sun.sun_path) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return -1;
	(void)unlink(path);
	memset(&sun, 0, sizeof sun);
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof sun.sun_path - 1);

	old = umask(0117);
	if (bind(fd, (struct sockaddr *)&sun, sizeof sun) < 0) {
		int e = errno;
		(void)umask(old);
		(void)close(fd);
		errno = e;
		return -1;
	}
	(void)umask(old);
	if (listen(fd, RDP_SESSMGR_BACKLOG) < 0) {
		int e = errno;
		(void)close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

/* Send a 4-byte status reply, optionally with an attached fd via
 * SCM_RIGHTS.  Returns 0 on success. */
static int
reply(int cfd, uint8_t status, int attach_fd)
{
	uint8_t buf[8];
	struct msghdr msg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];

	memset(buf, 0, sizeof buf);
	buf[0] = status;
	memset(cbuf, 0, sizeof cbuf);

	memset(&msg, 0, sizeof msg);
	iov.iov_base = buf;
	iov.iov_len  = sizeof buf;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (attach_fd >= 0) {
		struct cmsghdr *cmsg;
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof cbuf;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type  = SCM_RIGHTS;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &attach_fd, sizeof(int));
	}
	{
		ssize_t r;
		do { r = sendmsg(cfd, &msg, 0); }
		while (r < 0 && errno == EINTR);
		if (r != (ssize_t)sizeof buf)
			return -1;
	}
	return 0;
}

#if HAVE_FUSE
/*
 * FUSE mount bookkeeping.  rdp-sessionmgr opens /dev/fuse and mounts it
 * on $HOME/RemoteDrive before forking the session; the kernel speaks the
 * FUSE protocol to the session over the inherited fd.  When the session
 * process dies (clean exit or crash) the mount must be torn down so no
 * stale mount lingers, so we keep a small pid -> mountpoint table and
 * unmount it from on_sigchld / sweep_expired.  The mount deliberately
 * survives suspend/resume: only the actual death of the session pid
 * removes it.
 */
#define FUSE_MOUNT_MAX  64
#define FUSE_MOUNT_PATH 512   /* matches the spawn_session mountpoint buffer */

struct fuse_mount {
	int   in_use;
	pid_t pid;
	char  mountpoint[FUSE_MOUNT_PATH];
};

static struct fuse_mount fuse_mounts[FUSE_MOUNT_MAX];

/* The caller must hold SIGCHLD blocked so the reaper cannot interrupt the
 * table walk. */
static void
fuse_mount_record(pid_t pid, const char *mountpoint)
{
	int i;
	if (strlen(mountpoint) >= sizeof fuse_mounts[0].mountpoint) {
		rdp_warn("fuse: mountpoint too long, %s will not be "
			"auto-unmounted", mountpoint);
		return;
	}
	for (i = 0; i < FUSE_MOUNT_MAX; i++) {
		if (!fuse_mounts[i].in_use) {
			fuse_mounts[i].pid = pid;
			(void)strlcpy(fuse_mounts[i].mountpoint, mountpoint,
				sizeof fuse_mounts[i].mountpoint);
			fuse_mounts[i].in_use = 1;
			return;
		}
	}
	rdp_warn("fuse: mount table full, %s will not be auto-unmounted",
		mountpoint);
}

/* Tear down the mount belonging to a dead session pid.  Called from the
 * SIGCHLD handler and from the main flow (with SIGCHLD blocked), so it must
 * stay async-signal-safe: umount2 is a bare syscall and the table writes
 * touch only a fixed-size buffer, with no malloc/free. */
static void
fuse_mount_reap(pid_t pid)
{
	int i;
	for (i = 0; i < FUSE_MOUNT_MAX; i++) {
		if (fuse_mounts[i].in_use && fuse_mounts[i].pid == pid) {
			(void)umount2(fuse_mounts[i].mountpoint, MNT_DETACH);
			fuse_mounts[i].in_use = 0;
		}
	}
}

/*
 * Open /dev/fuse and mount it on $HOME/RemoteDrive as the target user's
 * directory.  Returns the fuse fd on success (caller dup2s it to fd 4 in
 * the child and records the mount), or -1 if drive support is
 * unavailable.  A failure here is never fatal to the spawn: the session
 * simply runs without a drive mount.  *mp_out receives the mountpoint
 * path (caller-owned static buffer).
 */
static int
fuse_mount_setup(const struct passwd *pw, char *mp_out, size_t mp_cap)
{
	int fusefd, dfd;
	char opts[256];
	char target[64];
	struct stat sb;

	(void)snprintf(mp_out, mp_cap, "%s/RemoteDrive", pw->pw_dir);

	fusefd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
	if (fusefd < 0) {
		rdp_info("fuse: /dev/fuse unavailable (%s); no drive mount",
			strerror(errno));
		return -1;
	}

	/* $HOME is user-controlled, so RemoteDrive may already exist as a
	 * symlink the user planted.  Never touch the path as root: create it
	 * (ignoring EEXIST) then open it with O_NOFOLLOW|O_DIRECTORY and do
	 * every ownership and mode change through the resulting fd, so a
	 * symlink yields ELOOP rather than an arbitrary-target chown. */
	(void)mkdir(mp_out, 0700);
	dfd = open(mp_out, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0) {
		rdp_warn("fuse: open %s: %s; no drive mount",
			mp_out, strerror(errno));
		(void)close(fusefd);
		return -1;
	}
	if (fstat(dfd, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
		rdp_warn("fuse: %s is not a directory; no drive mount", mp_out);
		(void)close(dfd);
		(void)close(fusefd);
		return -1;
	}
	if (fchown(dfd, pw->pw_uid, pw->pw_gid) != 0) {
		rdp_warn("fuse: fchown %s: %s; no drive mount",
			mp_out, strerror(errno));
		(void)close(dfd);
		(void)close(fusefd);
		return -1;
	}
	(void)fchmod(dfd, 0700);

	/* default_permissions delegates access checks to the kernel against
	 * the attrs we report; rootmode is the synthetic root dir mode. */
	(void)snprintf(opts, sizeof opts,
		"fd=%d,rootmode=040000,user_id=%u,group_id=%u,"
		"default_permissions",
		fusefd, (unsigned)pw->pw_uid, (unsigned)pw->pw_gid);

	/* Mount onto the directory we already verified through /proc/self/fd
	 * rather than re-resolving mp_out, closing the window where the user
	 * could swap the directory for a symlink between open and mount. */
	(void)snprintf(target, sizeof target, "/proc/self/fd/%d", dfd);
	if (mount("rdpdrive", target, "fuse",
	    MS_NOSUID | MS_NODEV | MS_NOEXEC, opts) != 0) {
		rdp_warn("fuse: mount %s: %s", mp_out, strerror(errno));
		(void)close(dfd);
		(void)close(fusefd);
		return -1;
	}
	(void)close(dfd);
	rdp_info("fuse: mounted RemoteDrive at %s", mp_out);
	return fusefd;
}
#endif /* HAVE_FUSE */

#if HAVE_OBSD_FUSE
/*
 * OpenBSD privileged mount-helper.
 *
 * mount(2)/unmount(2) are root-only and forbidden by pledge, so the pledged
 * rdp-sessionmgr cannot mount per session.  Before pledging and before any
 * privilege drop, main() forks an unpledged root child -- the mount-helper --
 * connected to the parent by a SOCK_STREAM socketpair.  The parent (which
 * pledges with sendfd/recvfd) sends one fixed-size request per mount/unmount;
 * the helper performs the privileged syscall and, for a mount, hands the open
 * /dev/fuse fd back over SCM_RIGHTS.  The parent then dup2()s that fd to fd 4
 * in the session child, exactly as the Linux path passes its own fuse fd.
 *
 * The protocol is a single fixed-size struct in each direction with no
 * variable-length field and no allocation from any untrusted length, so a
 * malformed request can never drive an over-read or an allocation.  The
 * helper validates every mountpoint path (absolute, NUL-bounded, length
 * capped) and opens the directory with O_NOFOLLOW|O_DIRECTORY so a symlink the
 * user planted under $HOME cannot redirect a root mount.  The helper never
 * execs, never builds a shell command, and never copies a request field into
 * a heap buffer.
 */

#define FUSE_MREQ_MOUNT     1u
#define FUSE_MREQ_UNMOUNT   2u
#define FUSE_MP_MAX         1024   /* mountpoint[] capacity, incl. the NUL */

/* Request: parent -> helper.  Fixed size, no variable-length tail. */
struct fuse_mreq {
	uint32_t op;            /* FUSE_MREQ_MOUNT / FUSE_MREQ_UNMOUNT */
	uint32_t uid;           /* mountpoint owner (MOUNT) */
	uint32_t gid;
	int32_t  max_read;      /* requested max_read (MOUNT); clamped by helper */
	uint32_t flags;         /* reserved, sent zeroed */
	uint16_t mp_len;        /* strlen(mountpoint), < FUSE_MP_MAX */
	char     mountpoint[FUSE_MP_MAX];
};

/* Reply: helper -> parent.  For MOUNT success the /dev/fuse fd rides
 * SCM_RIGHTS alongside this header. */
struct fuse_mrep {
	int32_t  result;        /* 0 ok, -1 failure */
	int32_t  err;           /* errno when result == -1 */
};

/* The parent's end of the helper socketpair, or -1 when no helper runs. */
static int fuse_helper_fd = -1;

/*
 * Validate a request mountpoint: it must be NUL-terminated within mp_len,
 * mp_len must match strnlen, the path must be absolute, and it must fit the
 * buffer.  Returns 0 on success.  Runs in the root helper, so it is strict.
 */
static int
fuse_mp_valid(const struct fuse_mreq *r)
{
	size_t n;
	if (r->mp_len == 0 || r->mp_len >= FUSE_MP_MAX)
		return -1;
	/* strnlen never reads past the fixed buffer. */
	n = strnlen(r->mountpoint, FUSE_MP_MAX);
	if (n != r->mp_len)
		return -1;        /* missing NUL or embedded NUL */
	if (r->mountpoint[0] != '/')
		return -1;        /* must be absolute */
	return 0;
}

/*
 * Helper MOUNT: open the dir safely, open /dev/fuse, mount fusefs, and return
 * the fuse fd to the parent via SCM_RIGHTS on success.  *fd_out receives the
 * fd to pass (>= 0) or -1.  Returns 0 on a mounted filesystem, -1 otherwise
 * with errno set; the caller turns that into the reply.  Stays root, never
 * pledged.
 */
static int
fuse_helper_do_mount(const struct fuse_mreq *r, int *fd_out)
{
	struct fusefs_args args;
	struct stat sb;
	int fusefd, dfd, e;
	int mr;

	*fd_out = -1;
	if (fuse_mp_valid(r) != 0) {
		errno = EINVAL;
		return -1;
	}

	/* $HOME is user-controlled, so the mountpoint may already exist as a
	 * symlink the user planted.  Create it (ignoring EEXIST) then open it
	 * O_NOFOLLOW|O_DIRECTORY: a planted symlink yields ELOOP, never an
	 * arbitrary-target root operation. */
	(void)mkdir(r->mountpoint, 0700);
	dfd = open(r->mountpoint,
		O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return -1;
	if (fstat(dfd, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
		(void)close(dfd);
		errno = ENOTDIR;
		return -1;
	}
	(void)fchown(dfd, (uid_t)r->uid, (gid_t)r->gid);
	(void)fchmod(dfd, 0700);

	/* OpenBSD's fusefs device is /dev/fuse0; libfuse opens the same node. */
	fusefd = open("/dev/fuse0", O_RDWR | O_CLOEXEC);
	if (fusefd < 0) {
		e = errno;
		(void)close(dfd);
		errno = e;
		return -1;
	}

	memset(&args, 0, sizeof args);
	/* name is ignored by the kernel (libfuse also leaves it NULL). */
	args.fd = fusefd;
	/* max_read: 0 (or negative) means the kernel default (FUSEBUFMAXSIZE);
	 * clamp any positive request to that cap. */
	args.max_read = r->max_read > 0
		? (r->max_read > FUSEBUFMAXSIZE ? FUSEBUFMAXSIZE : r->max_read)
		: 0;
	args.allow_other = 0;

	/*
	 * mount(2) resolves its target path with FOLLOW (and re-walks it from
	 * scratch), so mounting on r->mountpoint by name would reopen a window
	 * for the user to swap RemoteDrive for a symlink after our O_NOFOLLOW
	 * check -- a TOCTOU that, as root, could land a fusefs over an
	 * arbitrary system directory.  Pin the verified directory instead:
	 * fchdir() to the fd we already validated and mount(".").  The kernel
	 * then resolves "." to exactly that vnode, with no path component left
	 * for a symlink to redirect.  The helper is single-threaded and
	 * serializes requests, so the transient cwd change is safe; restore it
	 * afterwards.  fchdir on the O_DIRECTORY fd cannot follow a symlink. */
	if (fchdir(dfd) != 0) {
		e = errno;
		(void)close(fusefd);
		(void)close(dfd);
		errno = e;
		return -1;
	}
	mr = mount(MOUNT_FUSEFS, ".", MNT_NOSUID | MNT_NODEV, &args);
	e = errno;
	if (chdir("/") != 0) {
		/* Unreachable in practice; if it ever happens, leave the cwd
		 * where it is rather than masking the mount result. */
	}
	(void)close(dfd);
	if (mr != 0) {
		(void)close(fusefd);
		errno = e;
		return -1;
	}
	*fd_out = fusefd;
	return 0;
}

/* Helper UNMOUNT: force-unmount the mountpoint.  Returns 0 / -1+errno. */
static int
fuse_helper_do_unmount(const struct fuse_mreq *r)
{
	if (fuse_mp_valid(r) != 0) {
		errno = EINVAL;
		return -1;
	}
	if (unmount(r->mountpoint, MNT_FORCE) != 0)
		return -1;
	return 0;
}

/*
 * Send a reply, optionally with one fd attached via SCM_RIGHTS.  Returns 0
 * on success.  Runs in the helper.
 */
static int
fuse_helper_reply(int sock, const struct fuse_mrep *rep, int attach_fd)
{
	struct fuse_mrep out = *rep;   /* local copy: iov_base is void *, not const */
	struct msghdr msg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	ssize_t w;

	memset(&msg, 0, sizeof msg);
	iov.iov_base = &out;
	iov.iov_len = sizeof out;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (attach_fd >= 0) {
		struct cmsghdr *cmsg;
		memset(cbuf, 0, sizeof cbuf);
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof cbuf;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &attach_fd, sizeof(int));
	}
	do { w = sendmsg(sock, &msg, 0); }
	while (w < 0 && errno == EINTR);
	return w == (ssize_t)sizeof out ? 0 : -1;
}

/*
 * The mount-helper request loop.  Runs in the unpledged root child on the
 * `sock` end of the socketpair; the parent holds the other end.  Reads one
 * fixed-size request at a time, performs the privileged operation, and
 * replies.  Exits cleanly when the parent closes the socket (read returns 0)
 * and never returns to the caller.
 */
static __dead void
fuse_helper_loop(int sock)
{
	for (;;) {
		struct fuse_mreq req;
		struct fuse_mrep rep;
		ssize_t n;
		int fd_out = -1;

		/* A single read of the whole fixed struct.  A SOCK_STREAM
		 * could in theory deliver a short read, so loop until the
		 * struct is complete (or the peer hangs up). */
		size_t got = 0;
		while (got < sizeof req) {
			do {
				n = read(sock, (char *)&req + got,
					sizeof req - got);
			} while (n < 0 && errno == EINTR);
			if (n <= 0)
				_exit(0);   /* parent gone or error: done */
			got += (size_t)n;
		}

		memset(&rep, 0, sizeof rep);
		switch (req.op) {
		case FUSE_MREQ_MOUNT:
			if (fuse_helper_do_mount(&req, &fd_out) == 0) {
				rep.result = 0;
				rep.err = 0;
			} else {
				rep.result = -1;
				rep.err = errno;
			}
			break;
		case FUSE_MREQ_UNMOUNT:
			if (fuse_helper_do_unmount(&req) == 0) {
				rep.result = 0;
				rep.err = 0;
			} else {
				rep.result = -1;
				rep.err = errno;
			}
			break;
		default:
			rep.result = -1;
			rep.err = EINVAL;
			break;
		}

		(void)fuse_helper_reply(sock, &rep, fd_out);
		if (fd_out >= 0)
			(void)close(fd_out);   /* the parent owns the copy now */
	}
}

/*
 * Fork the mount-helper.  Called from main() BEFORE pledge() and before any
 * privilege drop, while still root.  On success the parent's socket end is
 * stored in fuse_helper_fd and 0 is returned; on failure -1 is returned and
 * the session simply runs without drive support.  listen_fd is closed in the
 * child so the helper never holds the daemon's listening socket.
 */
static int
fuse_helper_start(int listen_fd)
{
	int sv[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		rdp_warn("fuse: socketpair: %s; no drive support",
			strerror(errno));
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		rdp_warn("fuse: fork mount-helper: %s; no drive support",
			strerror(errno));
		(void)close(sv[0]);
		(void)close(sv[1]);
		return -1;
	}
	if (pid == 0) {
		/* Child: the mount-helper.  Drop everything it must not keep:
		 * the listening socket and the parent's socket end, and any
		 * stray fd.  Keep stdio and sv[1].  Do NOT pledge (it needs
		 * mount/unmount) and stay root. */
		int i, keep = sv[1];
		(void)close(sv[0]);
		if (listen_fd >= 0)
			(void)close(listen_fd);
		for (i = 3; i < 64; i++)
			if (i != keep)
				(void)close(i);
		/* Default signal handling: the helper does not reap or shut
		 * down on the parent's signals; it exits when the socket
		 * closes. */
		(void)signal(SIGCHLD, SIG_DFL);
		(void)signal(SIGTERM, SIG_DFL);
		(void)signal(SIGINT, SIG_DFL);
		fuse_helper_loop(keep);   /* never returns */
	}
	/* Parent: keep sv[0], close the child's end. */
	(void)close(sv[1]);
	fuse_helper_fd = sv[0];

	/*
	 * The session child reserves fds 0-4 (3 = backend RPC, 4 = fuse) and
	 * closes 5..63 before exec.  If sv[0] landed in 0-4 it would collide
	 * with those (and a no-mount spawn would leak the helper socket into
	 * the user session past the close loop), so relocate it above that
	 * range.  Set FD_CLOEXEC too, as defense in depth: the helper socket
	 * must never survive into an exec'd session.
	 */
	if (fuse_helper_fd <= 4) {
		int hi = fcntl(fuse_helper_fd, F_DUPFD_CLOEXEC, 16);
		if (hi >= 0) {
			(void)close(fuse_helper_fd);
			fuse_helper_fd = hi;
		}
	}
	(void)fcntl(fuse_helper_fd, F_SETFD, FD_CLOEXEC);

	rdp_info("fuse: mount-helper started (pid %d)", (int)pid);
	return 0;
}

/*
 * Ask the helper to mount RemoteDrive for pw, returning the /dev/fuse fd on
 * success or -1 on any failure (a failure is never fatal to the spawn).
 * *mp_out receives the mountpoint path.  Synchronous: send the request, read
 * the fixed reply, and pick up the SCM_RIGHTS fd.
 */
static int
fuse_helper_request_mount(const struct passwd *pw, char *mp_out, size_t mp_cap)
{
	struct fuse_mreq req;
	struct fuse_mrep rep;
	struct msghdr msg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t r;
	int fusefd = -1;
	size_t mplen;

	if (fuse_helper_fd < 0)
		return -1;

	(void)snprintf(mp_out, mp_cap, "%s/RemoteDrive", pw->pw_dir);
	mplen = strlen(mp_out);
	if (mplen == 0 || mplen >= FUSE_MP_MAX) {
		rdp_warn("fuse: mountpoint path unusable for %s", pw->pw_name);
		return -1;
	}

	memset(&req, 0, sizeof req);
	req.op = FUSE_MREQ_MOUNT;
	req.uid = (uint32_t)pw->pw_uid;
	req.gid = (uint32_t)pw->pw_gid;
	req.max_read = 0;       /* kernel default (FUSEBUFMAXSIZE) */
	req.flags = 0;
	req.mp_len = (uint16_t)mplen;
	memcpy(req.mountpoint, mp_out, mplen);
	req.mountpoint[mplen] = '\0';

	do { r = send(fuse_helper_fd, &req, sizeof req, 0); }
	while (r < 0 && errno == EINTR);
	if (r != (ssize_t)sizeof req) {
		rdp_warn("fuse: send mount request: %s", strerror(errno));
		return -1;
	}

	memset(&msg, 0, sizeof msg);
	iov.iov_base = &rep;
	iov.iov_len = sizeof rep;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof cbuf);
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;
	do { r = recvmsg(fuse_helper_fd, &msg, 0); }
	while (r < 0 && errno == EINTR);
	if (r != (ssize_t)sizeof rep) {
		rdp_warn("fuse: recv mount reply: %s",
			r < 0 ? strerror(errno) : "short read");
		return -1;
	}
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS
		    && cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
			memcpy(&fusefd, CMSG_DATA(cmsg), sizeof(int));

	if (rep.result != 0) {
		if (fusefd >= 0)
			(void)close(fusefd);   /* defensive: no fd on failure */
		rdp_warn("fuse: mount %s: %s", mp_out, strerror(rep.err));
		return -1;
	}
	if (fusefd < 0) {
		rdp_warn("fuse: mount %s reported success but passed no fd",
			mp_out);
		return -1;
	}
	rdp_info("fuse: mounted RemoteDrive at %s", mp_out);
	return fusefd;
}

/* Ask the helper to unmount a mountpoint.  Best-effort; the reply is read so
 * the socket does not back up.  Runs only from the main flow (never a signal
 * handler) with SIGCHLD blocked by the caller. */
static void
fuse_helper_request_unmount(const char *mountpoint)
{
	struct fuse_mreq req;
	struct fuse_mrep rep;
	ssize_t r;
	size_t mplen;

	if (fuse_helper_fd < 0 || mountpoint == NULL)
		return;
	mplen = strlen(mountpoint);
	if (mplen == 0 || mplen >= FUSE_MP_MAX)
		return;

	memset(&req, 0, sizeof req);
	req.op = FUSE_MREQ_UNMOUNT;
	req.mp_len = (uint16_t)mplen;
	memcpy(req.mountpoint, mountpoint, mplen);
	req.mountpoint[mplen] = '\0';

	do { r = send(fuse_helper_fd, &req, sizeof req, 0); }
	while (r < 0 && errno == EINTR);
	if (r != (ssize_t)sizeof req)
		return;
	do { r = recv(fuse_helper_fd, &rep, sizeof rep, 0); }
	while (r < 0 && errno == EINTR);
	(void)rep;
}

/*
 * FUSE mount bookkeeping, OpenBSD edition.  Mirrors the Linux fuse_mounts[]
 * table: a pid -> mountpoint map so the session's RemoteDrive is torn down
 * when the session process dies (clean exit or crash) and never lingers.
 * The mount survives suspend/resume; only the death of the session pid
 * removes it.
 *
 * Unlike Linux, the pledged parent cannot unmount: that goes through the
 * mount-helper.  The SIGCHLD handler must stay async-signal-safe, so the
 * reaper does NOT touch the socket -- it only flags the slot (a fixed-buffer
 * write).  fuse_mount_drain(), called from the main flow with SIGCHLD
 * blocked, sends the actual UNMOUNT requests for the flagged slots.
 */
#define FUSE_MOUNT_MAX  64
#define FUSE_MOUNT_PATH 512   /* matches the spawn_session mountpoint buffer */

struct fuse_mount {
	int   in_use;
	int   pending_unmount;   /* set by the reaper, cleared by the drain */
	pid_t pid;
	char  mountpoint[FUSE_MOUNT_PATH];
};

static struct fuse_mount fuse_mounts[FUSE_MOUNT_MAX];

/* Record a fresh mount.  The caller holds SIGCHLD blocked so the reaper
 * cannot interrupt the table walk. */
static void
fuse_mount_record(pid_t pid, const char *mountpoint)
{
	int i;
	if (strlen(mountpoint) >= sizeof fuse_mounts[0].mountpoint) {
		rdp_warn("fuse: mountpoint too long, %s will not be "
			"auto-unmounted", mountpoint);
		return;
	}
	for (i = 0; i < FUSE_MOUNT_MAX; i++) {
		if (!fuse_mounts[i].in_use) {
			fuse_mounts[i].pid = pid;
			(void)strlcpy(fuse_mounts[i].mountpoint, mountpoint,
				sizeof fuse_mounts[i].mountpoint);
			fuse_mounts[i].pending_unmount = 0;
			fuse_mounts[i].in_use = 1;
			return;
		}
	}
	rdp_warn("fuse: mount table full, %s will not be auto-unmounted",
		mountpoint);
}

/*
 * Mark the mount of a dead session pid for unmounting.  Called from the
 * SIGCHLD handler (and, with SIGCHLD blocked, from sweep_expired), so it must
 * stay async-signal-safe: it only writes the fixed-size table.  The actual
 * unmount is deferred to fuse_mount_drain() in the main flow.
 */
static void
fuse_mount_reap(pid_t pid)
{
	int i;
	for (i = 0; i < FUSE_MOUNT_MAX; i++) {
		if (fuse_mounts[i].in_use && fuse_mounts[i].pid == pid)
			fuse_mounts[i].pending_unmount = 1;
	}
}

/*
 * Drain pending unmounts: for every slot flagged by the reaper, ask the
 * helper to unmount and release the slot.  Runs only from the main flow.
 * The caller blocks SIGCHLD across the walk so the reaper cannot flag a new
 * slot mid-iteration in a way that corrupts the scan.  The mountpoint is
 * copied to a local before the unmount request so the slot can be freed
 * first, keeping the table consistent if the send blocks.
 */
static void
fuse_mount_drain(void)
{
	int i;
	for (i = 0; i < FUSE_MOUNT_MAX; i++) {
		if (fuse_mounts[i].in_use && fuse_mounts[i].pending_unmount) {
			char mp[FUSE_MOUNT_PATH];
			(void)strlcpy(mp, fuse_mounts[i].mountpoint, sizeof mp);
			fuse_mounts[i].in_use = 0;
			fuse_mounts[i].pending_unmount = 0;
			fuse_helper_request_unmount(mp);
		}
	}
}
#endif /* HAVE_OBSD_FUSE */

static int
spawn_session(const struct passwd *pw, uint16_t w, uint16_t h,
		uint32_t lcid, const char *tz, int *out_fd)
{
	int sv[2];
	pid_t pid;
#if HAVE_FUSE || HAVE_OBSD_FUSE
	int fusefd = -1;
	char mountpoint[512];
	sigset_t chld_mask, old_mask;
	int masked = 0;
	mountpoint[0] = '\0';
#endif

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		return -1;
#if HAVE_FUSE
	/* Set up the mount before fork so the privileged daemon owns it; the
	 * fuse fd is passed to the child on fd 4. */
	fusefd = fuse_mount_setup(pw, mountpoint, sizeof mountpoint);
#elif HAVE_OBSD_FUSE
	/* The pledged daemon cannot mount: ask the root mount-helper to mount
	 * RemoteDrive and hand back the /dev/fuse fd, which is passed to the
	 * child on fd 4.  A failure is never fatal -- the session just runs
	 * without a drive. */
	fusefd = fuse_helper_request_mount(pw, mountpoint, sizeof mountpoint);
#endif
#if HAVE_FUSE || HAVE_OBSD_FUSE
	/* Block SIGCHLD across fork + fuse_mount_record so the reaper can
	 * never run for this pid before its mount is recorded (the child
	 * could otherwise exit and be reaped before we record it). */
	if (fusefd >= 0) {
		sigemptyset(&chld_mask);
		sigaddset(&chld_mask, SIGCHLD);
		if (sigprocmask(SIG_BLOCK, &chld_mask, &old_mask) == 0)
			masked = 1;
	}
#endif
	pid = fork();
	if (pid < 0) {
#if HAVE_FUSE
		if (masked)
			(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
		if (fusefd >= 0) {
			(void)umount2(mountpoint, MNT_DETACH);
			(void)close(fusefd);
		}
#elif HAVE_OBSD_FUSE
		if (masked)
			(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
		if (fusefd >= 0) {
			/* The helper holds the mount; ask it to unmount and drop
			 * our copy of the fuse fd. */
			(void)close(fusefd);
			fuse_helper_request_unmount(mountpoint);
		}
#endif
		(void)close(sv[0]); (void)close(sv[1]);
		return -1;
	}
	if (pid == 0) {
		char wbuf[8], hbuf[8], kbuf[16], mbuf[16];
		char tzbuf[RDP_SESSMGR_TZ_MAX + 1];
		int i;

		(void)close(sv[0]);
#if HAVE_FUSE || HAVE_OBSD_FUSE
		/* Restore the inherited SIGCHLD mask so the session starts
		 * with default signal handling. */
		if (masked)
			(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
#endif
		if (sv[1] != 3) {
			if (dup2(sv[1], 3) < 0) _exit(127);
			(void)close(sv[1]);
		}
#if HAVE_FUSE || HAVE_OBSD_FUSE
		/* The session probes fd 4 for a FUSE device; nothing new on
		 * argv.  If there is no mount, fd 4 stays closed and the
		 * session simply runs without drive support.  dup2 clears
		 * FD_CLOEXEC on the target, but when the fuse fd is already
		 * fd 4 there is no dup2, so clear it explicitly or the fd
		 * would close at exec and drop the mount. */
		if (fusefd >= 0 && fusefd != 4) {
			if (dup2(fusefd, 4) < 0) _exit(127);
			(void)close(fusefd);
		} else if (fusefd == 4) {
			(void)fcntl(4, F_SETFD, 0);
		}
		/* Close all fds except 0-4 (3 = backend RPC, 4 = fuse). */
		for (i = 5; i < 64; i++)
			(void)close(i);
#else
		/* Close all fds except 0-3 so leaked sessmgr sockets
		 * don't persist into the user session. */
		for (i = 4; i < 64; i++)
			(void)close(i);
#endif
		(void)setsid();
		if (chdir(pw->pw_dir) != 0) {
			if (chdir("/") != 0) { /* unreachable in practice */ }
		}
		(void)setenv("HOME", pw->pw_dir, 1);
		(void)setenv("USER", pw->pw_name, 1);
		(void)setenv("LOGNAME", pw->pw_name, 1);
		(void)setenv("SHELL", pw->pw_shell[0] ? pw->pw_shell : "/bin/sh", 1);
		(void)setenv("PATH",
			"/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin"
			":/usr/bin:/usr/sbin:/bin:/sbin",
			1);
		(void)setenv("XDG_RUNTIME_DIR", "/tmp", 0);

		if (initgroups(pw->pw_name, pw->pw_gid) != 0
#if HAVE_SETRESUID
		    || setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0
		    || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0
#else
		    || setgid(pw->pw_gid) != 0
		    || setuid(pw->pw_uid) != 0
#endif
		    ) {
			rdp_err("drop privs: %s", strerror(errno));
			_exit(127);
		}

		(void)snprintf(wbuf, sizeof wbuf, "%u", (unsigned)w);
		(void)snprintf(hbuf, sizeof hbuf, "%u", (unsigned)h);
		(void)snprintf(kbuf, sizeof kbuf, "%u", (unsigned)lcid);
		(void)snprintf(tzbuf, sizeof tzbuf, "%s",
			(tz != NULL) ? tz : "");
		(void)snprintf(mbuf, sizeof mbuf, "%dx%d", max_w, max_h);
		execl(session_path, "rdp-session",
			"-w", wbuf, "-H", hbuf, "-k", kbuf,
			"-z", tzbuf, "-m", mbuf, (char *)NULL);
		(void)dprintf(2, "exec %s: %s\n",
			session_path, strerror(errno));
		_exit(127);
	}
	(void)close(sv[1]);
#if HAVE_FUSE || HAVE_OBSD_FUSE
	/* Parent keeps no copy of the fuse fd; the kernel holds the mount via
	 * the child's fd 4.  Remember the mountpoint so we can unmount when
	 * the session pid dies, then re-enable SIGCHLD now that the record
	 * is in place. */
	if (fusefd >= 0) {
		(void)close(fusefd);
		fuse_mount_record(pid, mountpoint);
	}
	if (masked)
		(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
#endif
	*out_fd = sv[0];
	rdp_info("spawned rdp-session pid %d for uid %u (%ux%u)",
		(int)pid, (unsigned)pw->pw_uid, (unsigned)w, (unsigned)h);
	return 0;
}

#define NTHASH_DIR  "/etc/rdpserver"
#define NTHASH_PATH NTHASH_DIR "/nthashes"

static void
cache_nthash(const char *user, const char *pass)
{
	uint8_t pw16[512], hash[16];
	size_t pw16_len;
	char line[512], tmp[512];
	FILE *out, *in;
	int found = 0;

	pw16_len = rdp_utf8_to_utf16le(pw16, sizeof pw16,
		pass, strlen(pass));
	if (pw16_len == (size_t)-1)
		return;

	{
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		const EVP_MD *md4 = EVP_md4();
		unsigned int hlen = 16;
		if (ctx == NULL || md4 == NULL) {
			EVP_MD_CTX_free(ctx);
			explicit_bzero(pw16, sizeof pw16);
			return;
		}
		if (EVP_DigestInit_ex(ctx, md4, NULL) != 1) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			OSSL_PROVIDER_load(NULL, "legacy");
			OSSL_PROVIDER_load(NULL, "default");
			if (EVP_DigestInit_ex(ctx, md4, NULL) != 1) {
				EVP_MD_CTX_free(ctx);
				explicit_bzero(pw16, sizeof pw16);
				return;
			}
#else
			EVP_MD_CTX_free(ctx);
			explicit_bzero(pw16, sizeof pw16);
			return;
#endif
		}
		EVP_DigestUpdate(ctx, pw16, pw16_len);
		EVP_DigestFinal_ex(ctx, hash, &hlen);
		EVP_MD_CTX_free(ctx);
	}
	explicit_bzero(pw16, sizeof pw16);

	(void)mkdir(NTHASH_DIR, 0700);
	snprintf(tmp, sizeof tmp, "%s.tmp", NTHASH_PATH);
	out = fopen(tmp, "w");
	if (out == NULL)
		return;
	(void)fchmod(fileno(out), 0600);

	in = fopen(NTHASH_PATH, "r");
	if (in != NULL) {
		while (fgets(line, sizeof line, in) != NULL) {
			char *colon = strchr(line, ':');
			if (colon != NULL
			    && (size_t)(colon - line) == strlen(user)
			    && strncmp(line, user, strlen(user)) == 0) {
				found = 1;
				fprintf(out, "%s:", user);
				for (int i = 0; i < 16; i++)
					fprintf(out, "%02x", hash[i]);
				fprintf(out, "\n");
			} else {
				fputs(line, out);
			}
		}
		fclose(in);
	}
	if (!found) {
		fprintf(out, "%s:", user);
		for (int i = 0; i < 16; i++)
			fprintf(out, "%02x", hash[i]);
		fprintf(out, "\n");
	}
	fclose(out);
	(void)rename(tmp, NTHASH_PATH);
	explicit_bzero(hash, sizeof hash);
	rdp_info("cached NT hash for '%s'", user);
}

/*
 * Per-source-IP authentication rate limiting.  An IP that fails
 * AUTH_FAIL_MAX times within AUTH_FAIL_WINDOW seconds is rejected
 * without touching the auth backend until the window passes; a
 * successful auth clears the IP.  Fixed table, oldest-window eviction.
 */
#define AUTH_THROTTLE_MAX  256
#define AUTH_FAIL_MAX      5
#define AUTH_FAIL_WINDOW   60   /* seconds */

static struct auth_throttle {
	char    ip[RDP_SESSMGR_IP_MAX + 1];
	int     fails;
	time_t  window_start;
} auth_throttle[AUTH_THROTTLE_MAX];

static struct auth_throttle *
auth_throttle_find(const char *ip)
{
	int i;
	if (ip == NULL || ip[0] == '\0')
		return NULL;
	for (i = 0; i < AUTH_THROTTLE_MAX; i++)
		if (strcmp(auth_throttle[i].ip, ip) == 0)
			return &auth_throttle[i];
	return NULL;
}

static void
auth_throttle_fail(const char *ip, time_t now)
{
	struct auth_throttle *s, *evict;
	int i;
	if (ip == NULL || ip[0] == '\0')
		return;
	s = auth_throttle_find(ip);
	if (s == NULL) {
		evict = &auth_throttle[0];
		for (i = 0; i < AUTH_THROTTLE_MAX; i++) {
			if (auth_throttle[i].ip[0] == '\0') {
				evict = &auth_throttle[i];
				break;
			}
			if (auth_throttle[i].window_start < evict->window_start)
				evict = &auth_throttle[i];
		}
		s = evict;
		memset(s, 0, sizeof *s);
		(void)snprintf(s->ip, sizeof s->ip, "%s", ip);
		s->window_start = now;
	} else if (now - s->window_start >= AUTH_FAIL_WINDOW) {
		s->fails = 0;
		s->window_start = now;
	}
	s->fails++;
}

static void
auth_throttle_clear(const char *ip)
{
	struct auth_throttle *s = auth_throttle_find(ip);
	if (s != NULL)
		s->ip[0] = '\0';
}

static int
handle_auth(int cfd, const uint8_t *req, size_t req_len,
		const char *service, char *user_out, size_t user_out_sz)
{
	size_t user_len, pass_len, ip_len;
	char  user[RDP_SESSMGR_USER_MAX + 1];
	char  pass[RDP_SESSMGR_PASS_MAX + 1];
	char  ip[RDP_SESSMGR_IP_MAX + 1];
	time_t now;
	int   rc;

	if (req_len < 8) return reply(cfd, RDP_SESSMGR_FAIL, -1);
	user_len = (size_t)req[2] | ((size_t)req[3] << 8);
	pass_len = (size_t)req[4] | ((size_t)req[5] << 8);
	ip_len   = (size_t)req[6] | ((size_t)req[7] << 8);
	if (user_len > RDP_SESSMGR_USER_MAX
	    || pass_len > RDP_SESSMGR_PASS_MAX
	    || ip_len > RDP_SESSMGR_IP_MAX
	    || 8 + user_len + pass_len + ip_len > req_len)
		return reply(cfd, RDP_SESSMGR_FAIL, -1);

	memcpy(user, req + 8, user_len);              user[user_len] = '\0';
	memcpy(pass, req + 8 + user_len, pass_len);   pass[pass_len] = '\0';
	memcpy(ip, req + 8 + user_len + pass_len, ip_len);   ip[ip_len] = '\0';

	/* Reject early if this source IP is over the failure threshold,
	 * without touching the auth backend. */
	now = time(NULL);
	{
		struct auth_throttle *s = auth_throttle_find(ip);
		if (s != NULL && now - s->window_start < AUTH_FAIL_WINDOW
		    && s->fails >= AUTH_FAIL_MAX) {
			rdp_warn("auth: rate-limited %s after %d failures",
				ip, s->fails);
			explicit_bzero(pass, sizeof pass);
			return reply(cfd, RDP_SESSMGR_FAIL, -1);
		}
	}

	/* PAM and bsd_auth both fork an external helper and waitpid()
	 * for it.  Our SIGCHLD reaper races with that wait, so suppress
	 * it briefly: set the handler to SIG_DFL across the auth call
	 * and restore on exit. */
	{
		struct sigaction saved, dfl;
		memset(&dfl, 0, sizeof dfl);
		dfl.sa_handler = SIG_DFL;
		sigemptyset(&dfl.sa_mask);
		(void)sigaction(SIGCHLD, &dfl, &saved);

		rc = rdp_auth_user(service, user, pass);

		(void)sigaction(SIGCHLD, &saved, NULL);
	}
	if (rc == 0)
		cache_nthash(user, pass);
	explicit_bzero(pass, sizeof pass);
	if (rc == 0) {
		size_t n = user_len < user_out_sz - 1 ? user_len : user_out_sz - 1;
		memcpy(user_out, user, n);
		user_out[n] = '\0';
		auth_throttle_clear(ip);
		return reply(cfd, RDP_SESSMGR_OK, -1);
	}
	auth_throttle_fail(ip, now);
	return reply(cfd, RDP_SESSMGR_FAIL, -1);
}

/* The TZ string is forwarded into the session environment, so validate
 * it against the worker's synthesized grammar before setenv.  A leading
 * ':' or '/' makes glibc treat TZ as a tzfile pathname; the synthesized
 * value always starts with a '<...>' numeric label, so reject those
 * forms outright (defense in depth against a compromised worker) and
 * otherwise allow only the POSIX TZ alphabet. */
static int
tz_is_safe(const char *s)
{
	size_t i;
	if (s[0] == ':' || s[0] == '/')
		return 0;
	for (i = 0; s[i] != '\0'; i++) {
		char c = s[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		    || (c >= '0' && c <= '9'))
			continue;
		if (c == '<' || c == '>' || c == '+' || c == '-'
		    || c == ':' || c == '.' || c == ',' || c == '/')
			continue;
		return 0;
	}
	return 1;
}

static int
handle_spawn(int cfd, const uint8_t *req, size_t req_len,
		const char *auth_user, int *retained_fd)
{
	uint16_t w, h, tz_len;
	uint32_t lcid;
	struct passwd *pw;
	char tz[RDP_SESSMGR_TZ_MAX + 1];
	int fd = -1;

	if (req_len < 12) return reply(cfd, RDP_SESSMGR_FAIL, -1);
	if (auth_user == NULL || auth_user[0] == '\0')
		return reply(cfd, RDP_SESSMGR_EPERM, -1);
	w = (uint16_t)req[2] | ((uint16_t)req[3] << 8);
	h = (uint16_t)req[4] | ((uint16_t)req[5] << 8);
	tz_len = (uint16_t)req[6] | ((uint16_t)req[7] << 8);
	lcid = (uint32_t)req[8] | ((uint32_t)req[9] << 8)
		| ((uint32_t)req[10] << 16) | ((uint32_t)req[11] << 24);
	if (w == 0 || h == 0) { w = 1024; h = 768; }

	/* Extract and validate the trailing POSIX TZ string. */
	tz[0] = '\0';
	if (tz_len > 0 && tz_len <= RDP_SESSMGR_TZ_MAX
	    && (size_t)12 + tz_len <= req_len) {
		memcpy(tz, req + 12, tz_len);
		tz[tz_len] = '\0';
		if (!tz_is_safe(tz)) {
			rdp_warn("SPAWN: rejecting unsafe TZ string");
			tz[0] = '\0';
		}
	}

	pw = getpwnam(auth_user);
	if (pw == NULL) {
		rdp_warn("SPAWN: user %s vanished after AUTH", auth_user);
		return reply(cfd, RDP_SESSMGR_FAIL, -1);
	}
	if (pw->pw_uid == 0) {
		rdp_warn("SPAWN: refusing to launch as root");
		return reply(cfd, RDP_SESSMGR_EPERM, -1);
	}
	if (spawn_session(pw, w, h, lcid, tz, &fd) != 0) {
		rdp_err("spawn_session %s: %s", auth_user, strerror(errno));
		return reply(cfd, RDP_SESSMGR_FAIL, -1);
	}

	if (*retained_fd >= 0)
		(void)close(*retained_fd);
	*retained_fd = dup(fd);

	if (reply(cfd, RDP_SESSMGR_OK, fd) != 0) {
		(void)close(fd);
		return -1;
	}
	(void)close(fd);
	return 0;
}

/* Suspended (disconnected) sessions awaiting reconnect. */
struct suspended_session {
	int      in_use;
	uint32_t logon_id;
	int      be_fd;
	time_t   suspended_at;
	uint8_t  arc_random[16];
};

static struct suspended_session
	suspended[RDP_SESSMGR_SUSPEND_MAX];

/* Pending NLA tokens: a worker registers a nonce after successful
 * NLA+password auth; the next worker must present the same nonce
 * with NLA_AUTH to bypass password authentication. */
#define NLA_PENDING_MAX 16
#define NLA_PENDING_TIMEOUT 120  /* seconds */

struct nla_pending {
	int      in_use;
	char     user[RDP_SESSMGR_USER_MAX + 1];
	uint8_t  nonce[RDP_SESSMGR_NLA_NONCE_LEN];
	time_t   created_at;
};

static struct nla_pending nla_pending[NLA_PENDING_MAX];

static int
fd_alive(int fd)
{
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = 0;
	pfd.revents = 0;
	if (poll(&pfd, 1, 0) < 0) return 0;
	return !(pfd.revents & (POLLHUP | POLLERR | POLLNVAL));
}

static void
sweep_expired(void)
{
	time_t now = time(NULL);
	int i;
#if HAVE_FUSE
	/* Safety net for any SIGCHLD that was coalesced and lost: unmount
	 * RemoteDrive for session pids that are no longer alive.  Block
	 * SIGCHLD across the table walk so the reaper cannot interrupt it. */
	{
		sigset_t chld_mask, old_mask;
		int masked = 0;
		sigemptyset(&chld_mask);
		sigaddset(&chld_mask, SIGCHLD);
		if (sigprocmask(SIG_BLOCK, &chld_mask, &old_mask) == 0)
			masked = 1;
		for (i = 0; i < FUSE_MOUNT_MAX; i++) {
			if (fuse_mounts[i].in_use
			    && kill(fuse_mounts[i].pid, 0) != 0
			    && errno == ESRCH)
				fuse_mount_reap(fuse_mounts[i].pid);
		}
		if (masked)
			(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
	}
#elif HAVE_OBSD_FUSE
	/* Safety net for any SIGCHLD that was coalesced and lost: flag the
	 * mounts of session pids that are no longer alive, then drain the
	 * pending unmounts to the helper.  Block SIGCHLD across the walk so
	 * the reaper cannot interrupt it; the drain runs in this main flow
	 * (it talks to the helper socket, which the signal handler must not). */
	{
		sigset_t chld_mask, old_mask;
		int masked = 0;
		sigemptyset(&chld_mask);
		sigaddset(&chld_mask, SIGCHLD);
		if (sigprocmask(SIG_BLOCK, &chld_mask, &old_mask) == 0)
			masked = 1;
		for (i = 0; i < FUSE_MOUNT_MAX; i++) {
			if (fuse_mounts[i].in_use
			    && kill(fuse_mounts[i].pid, 0) != 0
			    && errno == ESRCH)
				fuse_mount_reap(fuse_mounts[i].pid);
		}
		fuse_mount_drain();
		if (masked)
			(void)sigprocmask(SIG_SETMASK, &old_mask, NULL);
	}
#endif
	for (i = 0; i < RDP_SESSMGR_SUSPEND_MAX; i++) {
		if (!suspended[i].in_use) continue;
		if (now - suspended[i].suspended_at
		    > RDP_SESSMGR_SUSPEND_TIMEOUT
		    || !fd_alive(suspended[i].be_fd)) {
			rdp_info("sweep: logonId %u %s",
				(unsigned)suspended[i].logon_id,
				!fd_alive(suspended[i].be_fd)
				    ? "dead" : "timed out");
			(void)close(suspended[i].be_fd);
			suspended[i].in_use = 0;
		}
	}
}

static int
handle_suspend(int cfd, const uint8_t *req, size_t req_len, int recvd_fd)
{
	uint32_t logon_id;
	int i, slot = -1;

	if (req_len < 24 || recvd_fd < 0)
		return reply(cfd, RDP_SESSMGR_FAIL, -1);
	logon_id = (uint32_t)req[4] | ((uint32_t)req[5] << 8)
		| ((uint32_t)req[6] << 16) | ((uint32_t)req[7] << 24);
	sweep_expired();
	for (i = 0; i < RDP_SESSMGR_SUSPEND_MAX; i++) {
		if (!suspended[i].in_use) { slot = i; break; }
	}
	if (slot < 0) {
		rdp_warn("SUSPEND: no free slot");
		(void)close(recvd_fd);
		return reply(cfd, RDP_SESSMGR_FAIL, -1);
	}
	suspended[slot].in_use = 1;
	suspended[slot].logon_id = logon_id;
	suspended[slot].be_fd = recvd_fd;
	suspended[slot].suspended_at = time(NULL);
	memcpy(suspended[slot].arc_random, req + 8, 16);
	rdp_info("SUSPEND: logonId %u in slot %d",
		(unsigned)logon_id, slot);
	return reply(cfd, RDP_SESSMGR_OK, -1);
}

static int resume_fail_count;

static int
handle_resume(int cfd, const uint8_t *req, size_t req_len)
{
	uint32_t logon_id;
	int i;

	if (req_len < 8) return reply(cfd, RDP_SESSMGR_FAIL, -1);
	if (resume_fail_count > 5) {
		usleep(500000);
		resume_fail_count = 0;
	}
	logon_id = (uint32_t)req[4] | ((uint32_t)req[5] << 8)
		| ((uint32_t)req[6] << 16) | ((uint32_t)req[7] << 24);
	sweep_expired();
	for (i = 0; i < RDP_SESSMGR_SUSPEND_MAX; i++) {
		if (suspended[i].in_use
		    && suspended[i].logon_id == logon_id) {
			int fd = suspended[i].be_fd;
			suspended[i].in_use = 0;
			if (!fd_alive(fd)) {
				rdp_warn("RESUME: logonId %u fd dead",
					(unsigned)logon_id);
				(void)close(fd);
				return reply(cfd, RDP_SESSMGR_FAIL, -1);
			}
			rdp_info("RESUME: logonId %u from slot %d",
				(unsigned)logon_id, i);
			{
				uint8_t rbuf[24];
				struct msghdr rmsg;
				struct iovec riov;
				char rcb[CMSG_SPACE(sizeof(int))];
				struct cmsghdr *rc;
				ssize_t rr;

				memset(rbuf, 0, 8);
				rbuf[0] = RDP_SESSMGR_OK;
				memcpy(rbuf + 8,
				    suspended[i].arc_random, 16);
				memset(&rmsg, 0, sizeof rmsg);
				riov.iov_base = rbuf;
				riov.iov_len = sizeof rbuf;
				rmsg.msg_iov = &riov;
				rmsg.msg_iovlen = 1;
				memset(rcb, 0, sizeof rcb);
				rmsg.msg_control = rcb;
				rmsg.msg_controllen = sizeof rcb;
				rc = CMSG_FIRSTHDR(&rmsg);
				rc->cmsg_level = SOL_SOCKET;
				rc->cmsg_type = SCM_RIGHTS;
				rc->cmsg_len = CMSG_LEN(sizeof(int));
				memcpy(CMSG_DATA(rc), &fd, sizeof(int));
				do { rr = sendmsg(cfd, &rmsg, 0); }
				while (rr < 0 && errno == EINTR);
				if (rr < 0) {
					(void)close(fd);
					return -1;
				}
			}
			(void)close(fd);
			return 0;
		}
	}
	rdp_debug("RESUME: logonId %u not found", (unsigned)logon_id);
	resume_fail_count++;
	return reply(cfd, RDP_SESSMGR_FAIL, -1);
}

static void
auto_suspend(int be_fd)
{
	int i, slot = -1;
	uint32_t logon_id;

	sweep_expired();
	for (i = 0; i < RDP_SESSMGR_SUSPEND_MAX; i++) {
		if (!suspended[i].in_use) { slot = i; break; }
	}
	if (slot < 0) {
		rdp_warn("auto-suspend: no free slot");
		(void)close(be_fd);
		return;
	}
	rdp_rand_bytes((uint8_t *)&logon_id, sizeof logon_id);
	suspended[slot].in_use = 1;
	suspended[slot].logon_id = logon_id;
	suspended[slot].be_fd = be_fd;
	suspended[slot].suspended_at = time(NULL);
	memset(suspended[slot].arc_random, 0, sizeof suspended[slot].arc_random);
	rdp_info("auto-suspend: logonId %u in slot %d (worker died)",
		(unsigned)logon_id, slot);
}

static void
handle_client(int cfd, const char *service)
{
	char auth_user[RDP_SESSMGR_USER_MAX + 1] = {0};
	int retained_fd = -1;
	int spawn_done = 0;

	for (;;) {
		uint8_t buf[RDP_SESSMGR_FRAME_MAX];
		ssize_t n;
		struct pollfd pfd_wait;
		struct msghdr rmsg;
		struct iovec riov;
		char rcbuf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr *rcmsg;
		int recv_fd = -1;

		pfd_wait.fd = cfd;
		pfd_wait.events = POLLIN;
		if (poll(&pfd_wait, 1, 30000) <= 0) break;

		memset(&rmsg, 0, sizeof rmsg);
		riov.iov_base = buf;
		riov.iov_len = sizeof buf;
		rmsg.msg_iov = &riov;
		rmsg.msg_iovlen = 1;
		memset(rcbuf, 0, sizeof rcbuf);
		rmsg.msg_control = rcbuf;
		rmsg.msg_controllen = sizeof rcbuf;
		n = recvmsg(cfd, &rmsg, 0);
		if (n <= 0) break;
		for (rcmsg = CMSG_FIRSTHDR(&rmsg); rcmsg;
		     rcmsg = CMSG_NXTHDR(&rmsg, rcmsg))
			if (rcmsg->cmsg_level == SOL_SOCKET
			    && rcmsg->cmsg_type == SCM_RIGHTS
			    && rcmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
				memcpy(&recv_fd, CMSG_DATA(rcmsg),
				    sizeof(int));
		switch (buf[0]) {
		case RDP_SESSMGR_OP_AUTH:
			(void)handle_auth(cfd, buf, (size_t)n, service,
				auth_user, sizeof auth_user);
			explicit_bzero(buf, (size_t)n);
			break;
		case RDP_SESSMGR_OP_SPAWN:
			if (handle_spawn(cfd, buf, (size_t)n, auth_user,
			    &retained_fd) == 0)
				spawn_done = 1;
			break;
		case RDP_SESSMGR_OP_SUSPEND:
			if (retained_fd >= 0) {
				(void)close(retained_fd);
				retained_fd = -1;
			}
			(void)handle_suspend(cfd, buf, (size_t)n, recv_fd);
			recv_fd = -1;
			break;
		case RDP_SESSMGR_OP_RESUME:
			(void)handle_resume(cfd, buf, (size_t)n);
			break;
		case RDP_SESSMGR_OP_NLA_AUTH:
			{
				size_t ulen = (size_t)buf[2]
					| ((size_t)buf[3] << 8);
				size_t nonce_off = 8 + ulen;
				if (n >= 8 && ulen <= RDP_SESSMGR_USER_MAX
				    && nonce_off + RDP_SESSMGR_NLA_NONCE_LEN
				    <= (size_t)n) {
					char tuser[RDP_SESSMGR_USER_MAX + 1];
					size_t nn = ulen < sizeof tuser - 1
						? ulen : sizeof tuser - 1;
					int found = 0, i;
					time_t now = time(NULL);
					memcpy(tuser, buf + 8, nn);
					tuser[nn] = '\0';
					for (i = 0; i < NLA_PENDING_MAX; i++) {
						if (!nla_pending[i].in_use)
							continue;
						if (now - nla_pending[i].created_at
						    > NLA_PENDING_TIMEOUT) {
							nla_pending[i].in_use = 0;
							continue;
						}
						if (strcmp(nla_pending[i].user, tuser) == 0
						    && memcmp(nla_pending[i].nonce,
						    buf + nonce_off,
						    RDP_SESSMGR_NLA_NONCE_LEN) == 0) {
							found = 1;
							nla_pending[i].in_use = 0;
							break;
						}
					}
					if (found) {
						memcpy(auth_user, tuser, nn + 1);
						rdp_info("NLA_AUTH: accepted '%s'",
							auth_user);
						(void)reply(cfd, RDP_SESSMGR_OK, -1);
					} else {
						rdp_warn("NLA_AUTH: rejected '%s' "
							"(bad nonce)", tuser);
						(void)reply(cfd, RDP_SESSMGR_FAIL, -1);
					}
				} else {
					(void)reply(cfd, RDP_SESSMGR_FAIL, -1);
				}
			}
			break;
		case RDP_SESSMGR_OP_NLA_STORE:
			{
				size_t ulen = (size_t)buf[2]
					| ((size_t)buf[3] << 8);
				size_t nonce_off = 8 + ulen;
				if (n >= 8 && ulen <= RDP_SESSMGR_USER_MAX
				    && nonce_off + RDP_SESSMGR_NLA_NONCE_LEN
				    <= (size_t)n) {
					int i, slot = -1;
					time_t now = time(NULL);
					for (i = 0; i < NLA_PENDING_MAX; i++) {
						if (!nla_pending[i].in_use
						    || now - nla_pending[i].created_at
						    > NLA_PENDING_TIMEOUT) {
							if (slot < 0) slot = i;
							if (nla_pending[i].in_use)
								nla_pending[i].in_use = 0;
						}
					}
					if (slot >= 0) {
						size_t nn = ulen < RDP_SESSMGR_USER_MAX
							? ulen : RDP_SESSMGR_USER_MAX;
						nla_pending[slot].in_use = 1;
						memcpy(nla_pending[slot].user,
							buf + 8, nn);
						nla_pending[slot].user[nn] = '\0';
						memcpy(nla_pending[slot].nonce,
							buf + nonce_off,
							RDP_SESSMGR_NLA_NONCE_LEN);
						nla_pending[slot].created_at = now;
						rdp_info("NLA_STORE: registered "
							"nonce for '%s'",
							nla_pending[slot].user);
						(void)reply(cfd, RDP_SESSMGR_OK, -1);
					} else {
						(void)reply(cfd, RDP_SESSMGR_FAIL, -1);
					}
				} else {
					(void)reply(cfd, RDP_SESSMGR_FAIL, -1);
				}
			}
			break;
		default:
			(void)reply(cfd, RDP_SESSMGR_ENOSYS, -1);
			break;
		}
		if (recv_fd >= 0) {
			(void)close(recv_fd);
			recv_fd = -1;
		}
	}

	if (retained_fd >= 0) {
		if (!spawn_done) {
			struct pollfd pfd;
			pfd.fd = retained_fd;
			pfd.events = 0;
			pfd.revents = 0;
			if (poll(&pfd, 1, 0) >= 0
			    && !(pfd.revents & (POLLHUP | POLLERR)))
				auto_suspend(retained_fd);
			else
				(void)close(retained_fd);
		} else {
			(void)close(retained_fd);
		}
		retained_fd = -1;
	}
	explicit_bzero(auth_user, sizeof auth_user);
}

static int
try_drop_privs(const char *username)
{
	struct passwd *pw;
	if (geteuid() != 0) return 0;
	pw = getpwnam(username);
	if (pw == NULL) {
		rdp_warn("user '%s' not present; staying as root", username);
		return 0;
	}
	if (setgroups(1, &pw->pw_gid) != 0
#if HAVE_SETRESUID
	    || setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0
	    || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0
#else
	    || setgid(pw->pw_gid) != 0
	    || setuid(pw->pw_uid) != 0
#endif
	    ) {
		rdp_err("drop privs to '%s': %s", username, strerror(errno));
		return -1;
	}
	rdp_info("dropped privileges to %s", username);
	return 0;
}

static void
usage(const char *prog)
{
	(void)fprintf(stderr,
"usage: %s [-d] [-f] [-s socket] [-u drop-user] [-S service] [-X path]\n"
"          [-m WxH]\n"
"  -d         enable debug log level\n"
"  -f         run in foreground; log to stderr\n"
"  -s path    listen socket path (default %s)\n"
"  -u user    drop privileges to this user after bind\n"
"             (only safe if SPAWN is not used)\n"
"  -S name    PAM service name (default 'login')\n"
"  -X path    rdp-session binary path (default %s)\n"
"  -m WxH     max desktop size for dynamic resize (default 3840x2160)\n",
		prog, RDP_SESSMGR_DEFAULT_SOCK, RDP_SESSION_PATH);
}

int
main(int argc, char *argv[])
{
	const char *sock_path = RDP_SESSMGR_DEFAULT_SOCK;
	const char *drop_user = NULL;
	const char *service   = "login";
	int debug = 0, foreground = 0, opt, listen_fd;
	struct rdp_log_cfg lc;

	while ((opt = getopt(argc, argv, "dfs:u:S:X:m:h?")) != -1) {
		switch (opt) {
		case 'd': debug = 1; break;
		case 'f': foreground = 1; break;
		case 's': sock_path = optarg; break;
		case 'u': drop_user = optarg; break;
		case 'S': service = optarg; break;
		case 'X': session_path = optarg; break;
		case 'm':
			if (sscanf(optarg, "%dx%d", &max_w, &max_h) != 2
			    || max_w < 200 || max_h < 200
			    || max_w > 8192 || max_h > 8192) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'h':
		case '?':
			usage(argv[0]);
			return opt == '?' ? 1 : 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	memset(&lc, 0, sizeof lc);
	lc.ident = "rdp-sessionmgr";
	lc.foreground = foreground;
	lc.level = debug ? RDP_LOG_DEBUG : RDP_LOG_INFO;
	rdp_log_init(&lc);

	install_signal_handlers();

	listen_fd = bind_listener(sock_path);
	if (listen_fd < 0) {
		rdp_err("bind %s: %s", sock_path, strerror(errno));
		rdp_log_close();
		return 1;
	}
	rdp_info("rdp-sessionmgr listening on %s (service=%s)",
		sock_path, service);

#if HAVE_OBSD_FUSE
	/* Fork the privileged mount-helper BEFORE pledge and BEFORE any
	 * privilege drop, while still root: mount(2)/unmount(2) are root-only
	 * and pledge-forbidden, so the pledged daemon delegates them to this
	 * unpledged root child.  A failure here is not fatal -- sessions just
	 * run without a drive mount. */
	if (geteuid() == 0)
		(void)fuse_helper_start(listen_fd);
	else
		rdp_info("fuse: not root, no mount-helper; no drive support");
#endif

	if (drop_user != NULL && try_drop_privs(drop_user) != 0) {
		(void)close(listen_fd);
		(void)unlink(sock_path);
		rdp_log_close();
		return 1;
	}

	/* We need: accept on the AF_UNIX socket (`unix`), PAM/bsd_auth
	 * which fork/exec helpers (`proc exec`), getpwnam on the
	 * authenticated user (`getpw`), setuid in spawn_session (`id`),
	 * read /etc/master.passwd (`rpath`) for getpwnam.  No outbound
	 * TCP.  Non-OpenBSD systems get a no-op. */
	if (pledge("stdio rpath wpath cpath unix sendfd recvfd proc exec "
		"id getpw dpath fattr", NULL) != 0)
		rdp_warn("pledge sessmgr: %s", strerror(errno));

	while (!want_shutdown) {
		int cfd = accept(listen_fd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR) {
#if HAVE_OBSD_FUSE
				/* A SIGCHLD that interrupted accept may have
				 * flagged a dead session's mount; drain it. */
				{
					sigset_t m, o;
					sigemptyset(&m);
					sigaddset(&m, SIGCHLD);
					if (sigprocmask(SIG_BLOCK, &m, &o) == 0) {
						fuse_mount_drain();
						(void)sigprocmask(SIG_SETMASK,
							&o, NULL);
					}
				}
#endif
				continue;
			}
			rdp_err("accept: %s", strerror(errno));
			break;
		}
		handle_client(cfd, service);
		(void)close(cfd);
#if HAVE_OBSD_FUSE
		/* Drain any unmounts flagged while servicing this client. */
		{
			sigset_t m, o;
			sigemptyset(&m);
			sigaddset(&m, SIGCHLD);
			if (sigprocmask(SIG_BLOCK, &m, &o) == 0) {
				fuse_mount_drain();
				(void)sigprocmask(SIG_SETMASK, &o, NULL);
			}
		}
#endif
	}

	rdp_info("rdp-sessionmgr shutting down");
	(void)close(listen_fd);
	(void)unlink(sock_path);
	rdp_log_close();
	return 0;
}
