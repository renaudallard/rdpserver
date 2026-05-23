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
 * io.c -- I/O helpers.
 */

#include "io.h"

#include "../include/rdp_log.h"

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

ssize_t
rdp_read_full(int fd, void *buf, size_t n)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < n) {
		ssize_t r = read(fd, p + got, n - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return (ssize_t)got;
		got += (size_t)r;
	}
	return (ssize_t)got;
}

ssize_t
rdp_write_full(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	size_t sent = 0;

	while (sent < n) {
		ssize_t r = write(fd, p + sent, n - sent);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		sent += (size_t)r;
	}
	return (ssize_t)sent;
}

int
rdp_set_cloexec(int fd)
{
	int f = fcntl(fd, F_GETFD);
	if (f < 0)
		return -1;
	if (fcntl(fd, F_SETFD, f | FD_CLOEXEC) < 0)
		return -1;
	return 0;
}

int
rdp_set_nonblock(int fd)
{
	int f = fcntl(fd, F_GETFL);
	if (f < 0)
		return -1;
	if (fcntl(fd, F_SETFL, f | O_NONBLOCK) < 0)
		return -1;
	return 0;
}

int
rdp_set_tcp_keepalive(int fd)
{
	int on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof on) != 0)
		return -1;
#ifdef TCP_KEEPIDLE
	{
		int idle = 60;
		(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
			&idle, sizeof idle);
	}
#endif
#ifdef TCP_KEEPINTVL
	{
		int intvl = 10;
		(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
			&intvl, sizeof intvl);
	}
#endif
#ifdef TCP_KEEPCNT
	{
		int cnt = 6;
		(void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
			&cnt, sizeof cnt);
	}
#endif
	return 0;
}

int
rdp_listen_tcp(const char *host, const char *port)
{
	struct addrinfo hints, *res, *ai;
	int rc, fd = -1, on = 1;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(host, port, &hints, &res);
	if (rc != 0) {
		rdp_err("getaddrinfo(%s, %s): %s",
			host ? host : "*", port, gai_strerror(rc));
		errno = EINVAL;
		return -1;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		fd = socket(ai->ai_family,
			ai->ai_socktype | SOCK_CLOEXEC,
			ai->ai_protocol);
		if (fd < 0)
			continue;
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			&on, sizeof on);
		if (ai->ai_family == AF_INET6) {
			(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				&on, sizeof on);
		}
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		(void)close(fd);
		fd = -1;
	}

	freeaddrinfo(res);

	if (fd < 0)
		return -1;

	if (listen(fd, 128) < 0) {
		int e = errno;
		(void)close(fd);
		errno = e;
		return -1;
	}
	return fd;
}
