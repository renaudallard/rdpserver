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
 * rdpd.c -- the Remote Desktop Protocol daemon.
 *
 * Phase 0 scope: open a TCP listener, accept connections, log each
 * peer, close the socket.  No protocol work happens yet -- that
 * arrives starting with Phase A (TPKT, X.224, TLS, MCS).
 *
 * The shape of main() here is intentionally what later phases will
 * fork off worker processes from; keeping it minimal makes the
 * privilege-separation boundary obvious when we add it.
 */

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include "../common/io.h"
#include "../sec/tls.h"
#include "conn.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RDP_DEFAULT_PORT "3389"
#define RDP_CERT_PATH "tmp/server.crt"
#define RDP_KEY_PATH  "tmp/server.key"

static volatile sig_atomic_t want_shutdown = 0;

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
	(void)sigaction(SIGHUP,  &sa, NULL);

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_sigchld;
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGCHLD, &sa, NULL);
}

static void
peer_to_str(const struct sockaddr *sa, socklen_t sl, char *out, size_t outsz)
{
	char host[64];
	int rc;

	rc = getnameinfo(sa, sl, host, sizeof host, NULL, 0,
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc != 0) {
		(void)strncpy(out, "?", outsz);
		out[outsz - 1] = '\0';
		return;
	}
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const void *)sa;
		(void)snprintf(out, outsz, "%s:%u",
			host, (unsigned)ntohs(sin->sin_port));
	} else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const void *)sa;
		(void)snprintf(out, outsz, "[%s]:%u",
			host, (unsigned)ntohs(s6->sin6_port));
	} else {
		(void)snprintf(out, outsz, "%s", host);
	}
}

static void
usage(const char *prog)
{
	(void)fprintf(stderr,
"usage: %s [-d] [-f] [-p port] [-h host] [-S sock]\n"
"  -d        enable debug log level\n"
"  -f        run in foreground; log to stderr\n"
"  -p port   listen port (default %s)\n"
"  -h host   bind address (default: all)\n"
"  -S sock   path to rdp-sessionmgr AF_UNIX socket\n"
"            (when omitted, the built-in stub auth accepts any non-empty\n"
"             username/password pair)\n",
		prog, RDP_DEFAULT_PORT);
}

int
main(int argc, char *argv[])
{
	const char *port = RDP_DEFAULT_PORT;
	const char *host = NULL;
	const char *sessmgr_sock = NULL;
	int debug = 0, foreground = 0, auto_login = 0;
	int opt, listen_fd;
	struct rdp_log_cfg lc;

	while ((opt = getopt(argc, argv, "Adfp:h:S:H?")) != -1) {
		switch (opt) {
		case 'A': auto_login = 1; break;
		case 'd': debug = 1; break;
		case 'f': foreground = 1; break;
		case 'p': port = optarg; break;
		case 'h': host = optarg; break;
		case 'S': sessmgr_sock = optarg; break;
		case 'H':
		case '?':
			usage(argv[0]);
			return opt == '?' ? 1 : 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	memset(&lc, 0, sizeof lc);
	lc.ident = "rdpd";
	lc.foreground = foreground;
	lc.level = debug ? RDP_LOG_DEBUG : RDP_LOG_INFO;
	rdp_log_init(&lc);

	install_signal_handlers();

	listen_fd = rdp_listen_tcp(host, port);
	if (listen_fd < 0) {
		rdp_err("listen on %s:%s: %s",
			host ? host : "*", port, strerror(errno));
		rdp_log_close();
		return 1;
	}

	if (rdp_tls_ensure_selfsigned(RDP_CERT_PATH, RDP_KEY_PATH, "rdpd") != 0) {
		rdp_err("failed to ensure self-signed certificate");
		(void)close(listen_fd);
		rdp_log_close();
		return 1;
	}
	struct rdp_tls_ctx *tls = rdp_tls_ctx_new(RDP_CERT_PATH, RDP_KEY_PATH);
	if (tls == NULL) {
		rdp_err("failed to load TLS context");
		(void)close(listen_fd);
		rdp_log_close();
		return 1;
	}

	rdp_info("rdpd %s listening on %s:%s",
		RDP_VERSION_STR, host ? host : "*", port);

	while (!want_shutdown) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof ss;
		char peer[96];
		int cfd;
		pid_t pid;

		cfd = accept(listen_fd, (struct sockaddr *)&ss, &sl);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			rdp_err("accept: %s", strerror(errno));
			break;
		}

		peer_to_str((struct sockaddr *)&ss, sl, peer, sizeof peer);
		rdp_info("accept from %s", peer);

		/* Half-open detection.  Default 60s idle, 10s probe
		 * interval, 6 probes -- about two minutes of silence
		 * before the worker notices a dead client. */
		(void)rdp_set_tcp_keepalive(cfd);

		pid = fork();
		if (pid < 0) {
			rdp_err("fork: %s", strerror(errno));
			(void)close(cfd);
			continue;
		}
		if (pid == 0) {
			struct rdp_conn_cfg ccfg = { tls, sessmgr_sock, auto_login };
			(void)close(listen_fd);
			/* Worker only needs: TLS read/write on the TCP fd,
			 * the AF_UNIX socket to sessmgr, and writing tmp/
			 * cert files isn't its job (already done by the
			 * listener).  On non-OpenBSD this is a no-op. */
			/* pledge disabled for debugging */
			/* if (pledge("stdio inet unix", NULL) != 0)
				rdp_warn("pledge worker: %s", strerror(errno)); */
			rdp_conn_run(cfd, &ccfg, peer);
			rdp_tls_ctx_free(tls);
			rdp_log_close();
			_exit(0);
		}
		(void)close(cfd);
	}

	rdp_info("shutting down");
	rdp_tls_ctx_free(tls);
	(void)close(listen_fd);
	rdp_log_close();
	return 0;
}
