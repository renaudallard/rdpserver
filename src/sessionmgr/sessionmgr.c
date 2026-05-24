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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

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

static volatile sig_atomic_t want_shutdown;

static void
on_signal(int sig)
{
	(void)sig;
	want_shutdown = 1;
}

static void
on_sigchld(int sig)
{
	int saved = errno;
	(void)sig;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
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

static int
spawn_session(const struct passwd *pw, uint16_t w, uint16_t h, int *out_fd)
{
	int sv[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		(void)close(sv[0]); (void)close(sv[1]);
		return -1;
	}
	if (pid == 0) {
		char wbuf[8], hbuf[8];
		int i;

		(void)close(sv[0]);
		if (sv[1] != 3) {
			if (dup2(sv[1], 3) < 0) _exit(127);
			(void)close(sv[1]);
		}
		/* Close all fds except 0-3 so leaked sessmgr sockets
		 * don't persist into the user session. */
		for (i = 4; i < 64; i++)
			(void)close(i);
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
		execl(session_path, "rdp-session",
			"-w", wbuf, "-H", hbuf, (char *)NULL);
		(void)dprintf(2, "exec %s: %s\n",
			session_path, strerror(errno));
		_exit(127);
	}
	(void)close(sv[1]);
	*out_fd = sv[0];
	rdp_info("spawned rdp-session pid %d for uid %u (%ux%u)",
		(int)pid, (unsigned)pw->pw_uid, (unsigned)w, (unsigned)h);
	return 0;
}

static int
handle_auth(int cfd, const uint8_t *req, size_t req_len,
		const char *service, char *user_out, size_t user_out_sz)
{
	size_t user_len, pass_len;
	char  user[RDP_SESSMGR_USER_MAX + 1];
	char  pass[RDP_SESSMGR_PASS_MAX + 1];
	int   rc;

	if (req_len < 8) return reply(cfd, RDP_SESSMGR_FAIL, -1);
	user_len = (size_t)req[2] | ((size_t)req[3] << 8);
	pass_len = (size_t)req[4] | ((size_t)req[5] << 8);
	if (user_len > RDP_SESSMGR_USER_MAX
	    || pass_len > RDP_SESSMGR_PASS_MAX
	    || 8 + user_len + pass_len > req_len)
		return reply(cfd, RDP_SESSMGR_FAIL, -1);

	memcpy(user, req + 8, user_len);              user[user_len] = '\0';
	memcpy(pass, req + 8 + user_len, pass_len);   pass[pass_len] = '\0';

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
	explicit_bzero(pass, sizeof pass);
	if (rc == 0) {
		size_t n = user_len < user_out_sz - 1 ? user_len : user_out_sz - 1;
		memcpy(user_out, user, n);
		user_out[n] = '\0';
		return reply(cfd, RDP_SESSMGR_OK, -1);
	}
	return reply(cfd, RDP_SESSMGR_FAIL, -1);
}

static int
handle_spawn(int cfd, const uint8_t *req, size_t req_len,
		const char *auth_user, int *retained_fd)
{
	uint16_t w, h;
	struct passwd *pw;
	int fd = -1;

	if (req_len < 8) return reply(cfd, RDP_SESSMGR_FAIL, -1);
	if (auth_user == NULL || auth_user[0] == '\0')
		return reply(cfd, RDP_SESSMGR_EPERM, -1);
	w = (uint16_t)req[2] | ((uint16_t)req[3] << 8);
	h = (uint16_t)req[4] | ((uint16_t)req[5] << 8);
	if (w == 0 || h == 0) { w = 1024; h = 768; }

	pw = getpwnam(auth_user);
	if (pw == NULL) {
		rdp_warn("SPAWN: user %s vanished after AUTH", auth_user);
		return reply(cfd, RDP_SESSMGR_FAIL, -1);
	}
	if (pw->pw_uid == 0) {
		rdp_warn("SPAWN: refusing to launch as root");
		return reply(cfd, RDP_SESSMGR_EPERM, -1);
	}
	if (spawn_session(pw, w, h, &fd) != 0) {
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
};

static struct suspended_session
	suspended[RDP_SESSMGR_SUSPEND_MAX];

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
handle_suspend(int cfd)
{
	/* Receive the backend fd via SCM_RIGHTS alongside the request. */
	uint8_t buf[16];
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	int recvd_fd = -1;
	ssize_t n;
	uint32_t logon_id;
	int i, slot = -1;

	memset(&msg, 0, sizeof msg);
	iov.iov_base = buf;
	iov.iov_len = sizeof buf;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;
	n = recvmsg(cfd, &msg, 0);
	if (n < 8) return reply(cfd, RDP_SESSMGR_FAIL, -1);
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS
		    && cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
			memcpy(&recvd_fd, CMSG_DATA(cmsg), sizeof(int));
	}
	if (recvd_fd < 0)
		return reply(cfd, RDP_SESSMGR_FAIL, -1);
	logon_id = (uint32_t)buf[4] | ((uint32_t)buf[5] << 8)
		| ((uint32_t)buf[6] << 16) | ((uint32_t)buf[7] << 24);
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
	rdp_info("SUSPEND: logonId %u in slot %d",
		(unsigned)logon_id, slot);
	return reply(cfd, RDP_SESSMGR_OK, -1);
}

static int
handle_resume(int cfd, const uint8_t *req, size_t req_len)
{
	uint32_t logon_id;
	int i;

	if (req_len < 8) return reply(cfd, RDP_SESSMGR_FAIL, -1);
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
			if (reply(cfd, RDP_SESSMGR_OK, fd) != 0) {
				(void)close(fd);
				return -1;
			}
			(void)close(fd);
			return 0;
		}
	}
	rdp_debug("RESUME: logonId %u not found", (unsigned)logon_id);
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
	rdp_info("auto-suspend: logonId %u in slot %d (worker died)",
		(unsigned)logon_id, slot);
}

static void
handle_client(int cfd, const char *service)
{
	char auth_user[RDP_SESSMGR_USER_MAX + 1] = {0};
	int retained_fd = -1;

	for (;;) {
		uint8_t buf[RDP_SESSMGR_FRAME_MAX];
		ssize_t n = recv(cfd, buf, sizeof buf, 0);
		if (n <= 0) break;
		if (n < 1) break;
		switch (buf[0]) {
		case RDP_SESSMGR_OP_AUTH:
			(void)handle_auth(cfd, buf, (size_t)n, service,
				auth_user, sizeof auth_user);
			explicit_bzero(buf, (size_t)n);
			break;
		case RDP_SESSMGR_OP_SPAWN:
			(void)handle_spawn(cfd, buf, (size_t)n, auth_user,
				&retained_fd);
			break;
		case RDP_SESSMGR_OP_SUSPEND:
			if (retained_fd >= 0) {
				(void)close(retained_fd);
				retained_fd = -1;
			}
			(void)handle_suspend(cfd);
			break;
		case RDP_SESSMGR_OP_RESUME:
			(void)handle_resume(cfd, buf, (size_t)n);
			break;
		default:
			(void)reply(cfd, RDP_SESSMGR_ENOSYS, -1);
			break;
		}
	}

	if (retained_fd >= 0) {
		struct pollfd pfd;
		pfd.fd = retained_fd;
		pfd.events = 0;
		pfd.revents = 0;
		if (poll(&pfd, 1, 0) >= 0 && !(pfd.revents & (POLLHUP | POLLERR)))
			auto_suspend(retained_fd);
		else
			(void)close(retained_fd);
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
"  -d         enable debug log level\n"
"  -f         run in foreground; log to stderr\n"
"  -s path    listen socket path (default %s)\n"
"  -u user    drop privileges to this user after bind\n"
"             (only safe if SPAWN is not used)\n"
"  -S name    PAM service name (default 'login')\n"
"  -X path    rdp-session binary path (default %s)\n",
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

	while ((opt = getopt(argc, argv, "dfs:u:S:X:h?")) != -1) {
		switch (opt) {
		case 'd': debug = 1; break;
		case 'f': foreground = 1; break;
		case 's': sock_path = optarg; break;
		case 'u': drop_user = optarg; break;
		case 'S': service = optarg; break;
		case 'X': session_path = optarg; break;
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
			if (errno == EINTR) continue;
			rdp_err("accept: %s", strerror(errno));
			break;
		}
		handle_client(cfd, service);
		(void)close(cfd);
	}

	rdp_info("rdp-sessionmgr shutting down");
	(void)close(listen_fd);
	(void)unlink(sock_path);
	rdp_log_close();
	return 0;
}
