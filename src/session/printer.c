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
 * printer.c -- session side of RDP printer redirection.  See printer.h
 * for the wire framing and the overall design.
 */

#define _GNU_SOURCE   /* getpeereid on glibc */

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/io.h"
#include "../backend/proto.h"
#include "../backend/proto_api.h"
#include "printer.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <poll.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Path to lpadmin.  CUPS installs it in /usr/sbin on Linux and /usr/sbin
 * on OpenBSD too; configure could override this later, but a fixed path
 * keeps us from running an attacker planted lpadmin via $PATH. */
#ifndef RDP_LPADMIN_PATH
# define RDP_LPADMIN_PATH "/usr/sbin/lpadmin"
#endif

/*
 * Sanitize a raw printer name into a CUPS queue name.  CUPS queue names may
 * not contain spaces, slashes, '#' or control characters; to be safe we
 * keep only ASCII alphanumerics, dash and underscore and map everything else
 * (including UTF-8 multibyte lead/continuation bytes) to '_'.  The result is
 * prefixed with "rdp-" so session queues are easy to spot and never collide
 * with a real local queue, and the body is bounded so the whole name fits.
 * An empty or all junk name yields "rdp-printer".
 */
int
rdp_printer_sanitize(const char *name, char *out, size_t outsz)
{
	static const char prefix[] = "rdp-";
	size_t pi = sizeof prefix - 1;
	size_t oi;
	size_t body = 0;

	if (outsz <= pi + 1)
		return -1;
	memcpy(out, prefix, pi);
	oi = pi;
	for (; name != NULL && *name != '\0' && oi + 1 < outsz; name++) {
		unsigned char c = (unsigned char)*name;
		char m;
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		    || (c >= '0' && c <= '9') || c == '-' || c == '_')
			m = (char)c;
		else
			m = '_';
		out[oi++] = m;
		body++;
	}
	out[oi] = '\0';
	if (body == 0) {
		/* Nothing usable survived; fall back to a fixed stem. */
		(void)snprintf(out, outsz, "%sprinter", prefix);
	}
	return 0;
}

/* Build the per session print socket path under the best available runtime
 * directory.  Bounds the result to fit a sockaddr_un.sun_path. */
static int
build_sock_path(char *out, size_t outsz)
{
	const char *dir = getenv("XDG_RUNTIME_DIR");
	int n;

	if (dir == NULL || dir[0] != '/')
		dir = getenv("TMPDIR");
	if (dir == NULL || dir[0] != '/')
		dir = "/tmp";
	n = snprintf(out, outsz, "%s/rdp-print-%ld.sock", dir,
	    (long)getpid());
	if (n < 0 || (size_t)n >= outsz)
		return -1;
	return 0;
}

/* Probe whether lpadmin exists and is executable. */
static int
lpadmin_present(void)
{
	return access(RDP_LPADMIN_PATH, X_OK) == 0;
}

/*
 * Run lpadmin with the given NULL terminated argv (argv[0] is the path).
 * Returns 0 if lpadmin exited 0, -1 otherwise.  Output is sent to the bit
 * bucket so a noisy CUPS does not pollute the session log; errors are
 * summarized by the caller.  No shell is involved, so the printer name and
 * URI cannot be interpreted as shell metacharacters.
 */
/* Maximum lpadmin arguments we ever pass (queue create is the longest). */
#define LPADMIN_MAX_ARGS 12

static int
run_lpadmin(const char *const argv[])
{
	char *child[LPADMIN_MAX_ARGS + 1];
	size_t nargs = 0;
	pid_t pid;
	int st;

	/* Copy the const argv into a mutable child argv so execv gets a clean
	 * char *const[] without a const-discarding cast.  The copies live in
	 * the child only briefly before exec; on the error path we free them. */
	while (argv[nargs] != NULL) {
		if (nargs >= LPADMIN_MAX_ARGS)
			return -1;
		child[nargs] = strdup(argv[nargs]);
		if (child[nargs] == NULL) {
			while (nargs > 0)
				free(child[--nargs]);
			return -1;
		}
		nargs++;
	}
	child[nargs] = NULL;

	pid = fork();
	if (pid < 0) {
		while (nargs > 0)
			free(child[--nargs]);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			(void)dup2(devnull, STDIN_FILENO);
			(void)dup2(devnull, STDOUT_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				(void)close(devnull);
		}
		execv(RDP_LPADMIN_PATH, child);
		_exit(127);
	}
	while (nargs > 0)
		free(child[--nargs]);
	while (waitpid(pid, &st, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
		return 0;
	return -1;
}

int
rdp_printer_init(struct rdp_printer *p, int be_fd)
{
	struct sockaddr_un sa;
	int fd;
	size_t i;

	memset(p, 0, sizeof *p);
	p->be_fd = be_fd;
	p->listen_fd = -1;
	for (i = 0; i < RDP_PRINTER_MAX_CONNS; i++)
		p->conns[i].fd = -1;

	if (build_sock_path(p->sock_path, sizeof p->sock_path) != 0) {
		rdp_warn("printer: runtime dir path too long; redirection off");
		return -1;
	}
	if (sizeof sa.sun_path <= strlen(p->sock_path)) {
		rdp_warn("printer: socket path too long; redirection off");
		p->sock_path[0] = '\0';
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		rdp_warn("printer: socket: %s", strerror(errno));
		p->sock_path[0] = '\0';
		return -1;
	}
	(void)rdp_set_cloexec(fd);
	/* Non-blocking so a connect-then-abort on this world-addressable
	 * socket cannot make a poll-gated accept() block and stall the
	 * single-threaded session loop (BSD accept semantics).  accept_conn
	 * already treats a failed accept as nothing to do. */
	(void)rdp_set_nonblock(fd);

	(void)unlink(p->sock_path);
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	(void)strlcpy(sa.sun_path, p->sock_path, sizeof sa.sun_path);

	/*
	 * Bind, then make the socket connectable by the CUPS backend.  A
	 * system cupsd runs the print backend as the "lp" user, not as the
	 * session user, so a 0600 socket would refuse the backend's connect
	 * with EACCES.  We create the path in the session's runtime dir (whose
	 * own permissions still gate who can even reach it) and grant connect
	 * to others, since the only thing reachable through it is the client's
	 * own redirected printer, which the client already shared into this
	 * session.  We bind under a tight umask first so there is no brief
	 * window where the path is world writable before the explicit chmod.
	 */
	{
		mode_t old = umask(0177);
		int r = bind(fd, (struct sockaddr *)&sa, sizeof sa);
		(void)umask(old);
		if (r != 0) {
			rdp_warn("printer: bind %s: %s", p->sock_path,
			    strerror(errno));
			(void)close(fd);
			p->sock_path[0] = '\0';
			return -1;
		}
		(void)chmod(p->sock_path, 0666);
	}
	if (listen(fd, 8) != 0) {
		rdp_warn("printer: listen: %s", strerror(errno));
		(void)close(fd);
		(void)unlink(p->sock_path);
		p->sock_path[0] = '\0';
		return -1;
	}

	p->listen_fd = fd;

	/* Resolve who may connect to the socket and who may submit to the
	 * queues: the session user (and its name for the queue ACL), root, and
	 * the CUPS backend account (cupsd runs the backend as "lp" or
	 * "_cups", not as the session user). */
	{
		uid_t me = geteuid();
		struct passwd *pw;
		const char *backend_acct[] = { "lp", "_cups" };
		size_t bi;

		p->n_allow = 0;
		p->allow_uids[p->n_allow++] = me;
		if (me != 0)
			p->allow_uids[p->n_allow++] = 0;
		pw = getpwuid(me);
		if (pw != NULL && pw->pw_name != NULL) {
			size_t n = strlen(pw->pw_name);
			if (n < sizeof p->user)
				memcpy(p->user, pw->pw_name, n + 1);
		}
		for (bi = 0; bi < 2
		    && p->n_allow < (int)(sizeof p->allow_uids
		    / sizeof p->allow_uids[0]); bi++) {
			struct passwd *b = getpwnam(backend_acct[bi]);
			if (b != NULL && b->pw_uid != me && b->pw_uid != 0)
				p->allow_uids[p->n_allow++] = b->pw_uid;
		}
	}

	p->lpadmin_ok = lpadmin_present();
	if (!p->lpadmin_ok)
		rdp_info("printer: %s not found; queues will be skipped",
		    RDP_LPADMIN_PATH);
	else
		rdp_info("printer: redirection ready at %s", p->sock_path);
	return 0;
}

/* Find a queue slot by device id, or NULL. */
static struct rdp_printer_queue *
find_queue_by_dev(struct rdp_printer *p, uint32_t device_id)
{
	size_t i;
	for (i = 0; i < RDP_PRINTER_MAX_QUEUES; i++) {
		if (p->queues[i].used
		    && p->queues[i].device_id == device_id)
			return &p->queues[i];
	}
	return NULL;
}

/* Return 1 if any used queue already has this exact name. */
static int
queue_name_taken(struct rdp_printer *p, const char *name)
{
	size_t i;
	for (i = 0; i < RDP_PRINTER_MAX_QUEUES; i++) {
		if (p->queues[i].used
		    && strcmp(p->queues[i].queue, name) == 0)
			return 1;
	}
	return 0;
}

void
rdp_printer_handle_device(struct rdp_printer *p, const uint8_t *buf,
    size_t len)
{
	struct rdp_be_printer_device pd;
	char qname[64];
	/* base is sized so a "-NNN" disambiguator always fits in qname. */
	char base[sizeof ((struct rdp_printer *)0)->queues[0].queue - 5];
	char uri[160];
	struct rdp_printer_queue *q;
	size_t i;
	int suffix;

	if (len < sizeof pd)
		return;
	memcpy(&pd, buf, sizeof pd);
	pd.name[sizeof pd.name - 1] = '\0';
	pd.driver[sizeof pd.driver - 1] = '\0';

	if (p->listen_fd < 0 || !p->lpadmin_ok)
		return;

	/* Already have a queue for this device id: keep it. */
	if (find_queue_by_dev(p, pd.device_id) != NULL)
		return;

	if (rdp_printer_sanitize(pd.name, base, sizeof base) != 0)
		return;

	/* Resolve a name unique within this session.  The "rdp-" prefix plus
	 * a "-N" disambiguator keeps us clear of any pre-existing local queue
	 * of the same sanitized name too. */
	(void)strlcpy(qname, base, sizeof qname);
	for (suffix = 1; queue_name_taken(p, qname) && suffix < 1000; suffix++)
		(void)snprintf(qname, sizeof qname, "%s-%d", base, suffix);

	/* Find a free tracking slot. */
	q = NULL;
	for (i = 0; i < RDP_PRINTER_MAX_QUEUES; i++) {
		if (!p->queues[i].used) {
			q = &p->queues[i];
			break;
		}
	}
	if (q == NULL) {
		rdp_warn("printer: too many redirected printers; dropping %s",
		    pd.name);
		return;
	}

	if (snprintf(uri, sizeof uri, "rdp://%s?dev=%u", p->sock_path,
	    (unsigned)pd.device_id) >= (int)sizeof uri) {
		rdp_warn("printer: device uri too long; dropping %s", pd.name);
		return;
	}

	{
		char allowarg[80];
		const char *av[LPADMIN_MAX_ARGS + 1];
		size_t n = 0;

		av[n++] = RDP_LPADMIN_PATH;
		av[n++] = "-p"; av[n++] = qname;
		av[n++] = "-E";
		av[n++] = "-v"; av[n++] = uri;
		av[n++] = "-m"; av[n++] = "raw";
		/* Restrict job submission to the session user so another local
		 * user cannot print to the client's redirected printer. */
		if (p->user[0] != '\0'
		    && (size_t)snprintf(allowarg, sizeof allowarg, "allow:%s",
		    p->user) < sizeof allowarg) {
			av[n++] = "-u"; av[n++] = allowarg;
		}
		av[n] = NULL;
		if (run_lpadmin(av) != 0) {
			rdp_warn("printer: lpadmin failed for %s (queue %s); "
			    "skipping", pd.name, qname);
			return;
		}
	}

	q->used = 1;
	q->device_id = pd.device_id;
	(void)strlcpy(q->queue, qname, sizeof q->queue);
	rdp_info("printer: queue %s -> device %u%s", qname,
	    (unsigned)pd.device_id,
	    (pd.flags & RDP_BE_PRINTER_FLAG_DEFAULT) ? " (default)" : "");
}

/* Free a connection slot: close its fd and release its spool buffer. */
static void
conn_reset(struct rdp_printer_conn *c)
{
	if (c->fd >= 0)
		(void)close(c->fd);
	c->fd = -1;
	free(c->spool);
	c->spool = NULL;
	c->spool_got = 0;
	c->hdr_got = 0;
	memset(&c->hdr, 0, sizeof c->hdr);
}

/* Forward a completed job to the worker as one RDP_BE_PRINT_JOB.  The
 * payload is the device id header followed by the spool bytes. */
static void
forward_job(struct rdp_printer *p, uint32_t device_id, const uint8_t *spool,
    size_t spool_len)
{
	struct rdp_be_print_job_hdr hdr;
	uint8_t *msg;
	size_t msglen = sizeof hdr + spool_len;

	hdr.device_id = device_id;
	msg = malloc(msglen);
	if (msg == NULL) {
		rdp_warn("printer: out of memory forwarding %zu byte job",
		    spool_len);
		return;
	}
	memcpy(msg, &hdr, sizeof hdr);
	if (spool_len > 0)
		memcpy(msg + sizeof hdr, spool, spool_len);
	if (rdp_be_send(p->be_fd, RDP_BE_PRINT_JOB, msg, msglen) != 0)
		rdp_warn("printer: forwarding print job failed: %s",
		    strerror(errno));
	else
		rdp_info("printer: forwarded %zu byte job to device %u",
		    spool_len, (unsigned)device_id);
	free(msg);
}

/* Peer uid of a connected AF_UNIX socket; 0 on success.  SO_PEERCRED on
 * Linux, getpeereid elsewhere. */
static int
peer_uid(int fd, uid_t *uid)
{
#if defined(SO_PEERCRED)
	struct ucred uc;
	socklen_t l = sizeof uc;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0)
		return -1;
	*uid = uc.uid;
	return 0;
#else
	gid_t g;
	return getpeereid(fd, uid, &g);
#endif
}

/* Accept one pending backend connection into a free slot, if any. */
static void
accept_conn(struct rdp_printer *p)
{
	int fd = accept(p->listen_fd, NULL, NULL);
	uid_t puid;
	size_t i;
	int ok = 0, k;

	if (fd < 0)
		return;
	/* The socket is world addressable so the CUPS backend (run as a
	 * different user) can reach it; authenticate the peer by credentials
	 * so no other local user can inject a job by connecting directly. */
	if (peer_uid(fd, &puid) == 0) {
		for (k = 0; k < p->n_allow; k++)
			if (p->allow_uids[k] == puid) {
				ok = 1;
				break;
			}
	}
	if (!ok) {
		(void)close(fd);
		return;
	}
	(void)rdp_set_cloexec(fd);
	(void)rdp_set_nonblock(fd);
	for (i = 0; i < RDP_PRINTER_MAX_CONNS; i++) {
		if (p->conns[i].fd < 0) {
			conn_reset(&p->conns[i]);
			p->conns[i].fd = fd;
			return;
		}
	}
	/* No free slot: drop the connection (CUPS will retry the job). */
	(void)close(fd);
}

/*
 * Drain one ready connection.  Reads the fixed header first, then up to
 * spool_len bytes (bounded at RDP_PRINTER_MAX_SPOOL).  On EOF or a complete
 * job the job is forwarded and the slot is freed.  Non-blocking: a short
 * read just returns and the slot is retried on the next wakeup.
 */
static void
service_conn(struct rdp_printer *p, struct rdp_printer_conn *c)
{
	for (;;) {
		if (c->hdr_got < sizeof c->hdr) {
			ssize_t r = read(c->fd,
			    (uint8_t *)&c->hdr + c->hdr_got,
			    sizeof c->hdr - c->hdr_got);
			if (r < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return;
				conn_reset(c);
				return;
			}
			if (r == 0) {
				/* EOF before a full header: nothing to do. */
				conn_reset(c);
				return;
			}
			c->hdr_got += (size_t)r;
			if (c->hdr_got < sizeof c->hdr)
				continue;
			/* Header complete: validate and allocate the spool. */
			if (c->hdr.spool_len > RDP_PRINTER_MAX_SPOOL) {
				rdp_warn("printer: job claims %u bytes "
				    "(> %u cap); truncating",
				    (unsigned)c->hdr.spool_len,
				    (unsigned)RDP_PRINTER_MAX_SPOOL);
				c->hdr.spool_len = RDP_PRINTER_MAX_SPOOL;
			}
			if (c->hdr.spool_len > 0) {
				c->spool = malloc(c->hdr.spool_len);
				if (c->spool == NULL) {
					rdp_warn("printer: out of memory for "
					    "%u byte spool",
					    (unsigned)c->hdr.spool_len);
					conn_reset(c);
					return;
				}
			}
		}

		if (c->spool_got >= c->hdr.spool_len) {
			/* Spool fully read (or zero length): forward it. */
			forward_job(p, c->hdr.device_id, c->spool,
			    c->spool_got);
			conn_reset(c);
			return;
		}

		{
			size_t want = c->hdr.spool_len - c->spool_got;
			ssize_t r = read(c->fd, c->spool + c->spool_got, want);
			if (r < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return;
				conn_reset(c);
				return;
			}
			if (r == 0) {
				/* Backend closed early: forward what we have. */
				forward_job(p, c->hdr.device_id, c->spool,
				    c->spool_got);
				conn_reset(c);
				return;
			}
			c->spool_got += (size_t)r;
		}
	}
}

int
rdp_printer_fill_pollfds(struct rdp_printer *p, struct pollfd *pfd, int *n,
    int cap)
{
	size_t i;
	int added = 0;

	if (p->listen_fd < 0)
		return 0;
	if (*n < cap) {
		pfd[*n].fd = p->listen_fd;
		pfd[*n].events = POLLIN;
		pfd[*n].revents = 0;
		(*n)++;
		added++;
	}
	for (i = 0; i < RDP_PRINTER_MAX_CONNS; i++) {
		if (p->conns[i].fd < 0)
			continue;
		if (*n >= cap)
			break;
		pfd[*n].fd = p->conns[i].fd;
		pfd[*n].events = POLLIN;
		pfd[*n].revents = 0;
		(*n)++;
		added++;
	}
	return added;
}

void
rdp_printer_service(struct rdp_printer *p, struct pollfd *pfd, int n)
{
	int i;
	size_t j;

	if (p->listen_fd < 0)
		return;

	for (i = 0; i < n; i++) {
		if (pfd[i].fd == p->listen_fd) {
			if (pfd[i].revents & POLLIN)
				accept_conn(p);
			continue;
		}
		for (j = 0; j < RDP_PRINTER_MAX_CONNS; j++) {
			if (p->conns[j].fd < 0
			    || p->conns[j].fd != pfd[i].fd)
				continue;
			if (pfd[i].revents
			    & (POLLIN | POLLHUP | POLLERR))
				service_conn(p, &p->conns[j]);
			break;
		}
	}
}

void
rdp_printer_close(struct rdp_printer *p)
{
	size_t i;

	if (p == NULL)
		return;

	/* Remove every queue we created. */
	for (i = 0; i < RDP_PRINTER_MAX_QUEUES; i++) {
		if (!p->queues[i].used)
			continue;
		if (p->lpadmin_ok) {
			const char *av[] = {
				RDP_LPADMIN_PATH,
				"-x", p->queues[i].queue,
				NULL
			};
			(void)run_lpadmin(av);
		}
		p->queues[i].used = 0;
	}

	for (i = 0; i < RDP_PRINTER_MAX_CONNS; i++)
		conn_reset(&p->conns[i]);

	if (p->listen_fd >= 0) {
		(void)close(p->listen_fd);
		p->listen_fd = -1;
	}
	if (p->sock_path[0] != '\0') {
		(void)unlink(p->sock_path);
		p->sock_path[0] = '\0';
	}
}
