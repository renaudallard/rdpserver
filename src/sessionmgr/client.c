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
 * client.c -- worker-side helpers for talking to rdp-sessionmgr.
 *
 * A worker keeps a connection open across AUTH and SPAWN so the
 * sessmgr can bind the spawn to the prior auth without re-checking
 * credentials.  Closing the connection forgets the auth.
 */

#include "sessionmgr.h"
#include "protocol.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
connect_unix(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	if (path == NULL || path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	if (strlen(path) >= sizeof sun.sun_path) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return -1;
	memset(&sun, 0, sizeof sun);
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof sun.sun_path - 1);
	if (connect(fd, (struct sockaddr *)&sun, sizeof sun) < 0) {
		int e = errno;
		(void)close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

int
rdp_sessmgr_open_auth(struct rdp_sessmgr *out,
		const char *sock_path,
		const char *user, const char *pass,
		const char *client_ip)
{
	uint8_t  frame[RDP_SESSMGR_FRAME_MAX];
	uint8_t  resp[8];
	size_t   user_len, pass_len, ip_len, off;
	ssize_t  n;
	int      fd;

	if (out == NULL || user == NULL || pass == NULL) {
		errno = EINVAL;
		return -1;
	}
	user_len = strlen(user);
	pass_len = strlen(pass);
	ip_len = client_ip != NULL ? strlen(client_ip) : 0;
	if (user_len > RDP_SESSMGR_USER_MAX
	    || pass_len > RDP_SESSMGR_PASS_MAX
	    || ip_len > RDP_SESSMGR_IP_MAX) {
		errno = E2BIG;
		return -1;
	}

	fd = connect_unix(sock_path);
	if (fd < 0)
		return -1;

	memset(frame, 0, 8);
	frame[0] = RDP_SESSMGR_OP_AUTH;
	frame[2] = (uint8_t)(user_len & 0xff);
	frame[3] = (uint8_t)((user_len >> 8) & 0xff);
	frame[4] = (uint8_t)(pass_len & 0xff);
	frame[5] = (uint8_t)((pass_len >> 8) & 0xff);
	frame[6] = (uint8_t)(ip_len & 0xff);
	frame[7] = (uint8_t)((ip_len >> 8) & 0xff);
	off = 8;
	memcpy(frame + off, user, user_len); off += user_len;
	memcpy(frame + off, pass, pass_len); off += pass_len;
	if (ip_len > 0) {
		memcpy(frame + off, client_ip, ip_len);
		off += ip_len;
	}

	n = send(fd, frame, off, 0);
	explicit_bzero(frame, off);
	if (n != (ssize_t)off) {
		(void)close(fd);
		return -1;
	}
	n = recv(fd, resp, sizeof resp, 0);
	if (n < 4 || resp[0] != RDP_SESSMGR_OK) {
		(void)close(fd);
		errno = EACCES;
		return -1;
	}

	out->fd = fd;
	(void)strncpy(out->auth_user, user, sizeof out->auth_user - 1);
	out->auth_user[sizeof out->auth_user - 1] = '\0';
	return 0;
}

int
rdp_sessmgr_open_nla(struct rdp_sessmgr *out,
		const char *sock_path, const char *user,
		const uint8_t nonce[16])
{
	uint8_t  frame[RDP_SESSMGR_FRAME_MAX];
	uint8_t  resp[8];
	size_t   user_len, off;
	ssize_t  n;
	int      fd;

	if (out == NULL || user == NULL || nonce == NULL) {
		errno = EINVAL;
		return -1;
	}
	user_len = strlen(user);
	if (user_len > RDP_SESSMGR_USER_MAX) { errno = E2BIG; return -1; }

	fd = connect_unix(sock_path);
	if (fd < 0) return -1;

	memset(frame, 0, 8);
	frame[0] = RDP_SESSMGR_OP_NLA_AUTH;
	frame[2] = (uint8_t)(user_len & 0xff);
	frame[3] = (uint8_t)((user_len >> 8) & 0xff);
	off = 8;
	memcpy(frame + off, user, user_len); off += user_len;
	memcpy(frame + off, nonce, RDP_SESSMGR_NLA_NONCE_LEN);
	off += RDP_SESSMGR_NLA_NONCE_LEN;

	n = send(fd, frame, off, 0);
	if (n != (ssize_t)off) { (void)close(fd); return -1; }
	n = recv(fd, resp, sizeof resp, 0);
	if (n < 1 || resp[0] != RDP_SESSMGR_OK) {
		(void)close(fd);
		errno = EACCES;
		return -1;
	}
	out->fd = fd;
	(void)strncpy(out->auth_user, user, sizeof out->auth_user - 1);
	out->auth_user[sizeof out->auth_user - 1] = '\0';
	return 0;
}

int
rdp_sessmgr_nla_store(const char *sock_path,
		const char *user, const uint8_t nonce[16])
{
	uint8_t  frame[RDP_SESSMGR_FRAME_MAX];
	uint8_t  resp[8];
	size_t   user_len, off;
	ssize_t  n;
	int      fd;

	if (user == NULL || nonce == NULL) { errno = EINVAL; return -1; }
	user_len = strlen(user);
	if (user_len > RDP_SESSMGR_USER_MAX) { errno = E2BIG; return -1; }

	fd = connect_unix(sock_path);
	if (fd < 0) return -1;

	memset(frame, 0, 8);
	frame[0] = RDP_SESSMGR_OP_NLA_STORE;
	frame[2] = (uint8_t)(user_len & 0xff);
	frame[3] = (uint8_t)((user_len >> 8) & 0xff);
	off = 8;
	memcpy(frame + off, user, user_len); off += user_len;
	memcpy(frame + off, nonce, RDP_SESSMGR_NLA_NONCE_LEN);
	off += RDP_SESSMGR_NLA_NONCE_LEN;

	n = send(fd, frame, off, 0);
	if (n != (ssize_t)off) { (void)close(fd); return -1; }
	n = recv(fd, resp, sizeof resp, 0);
	(void)close(fd);
	if (n < 1 || resp[0] != RDP_SESSMGR_OK) return -1;
	return 0;
}

int
rdp_sessmgr_spawn(struct rdp_sessmgr *s, uint16_t w, uint16_t h,
		uint32_t lcid, const char *tz, int *fd_out)
{
	uint8_t req[12 + RDP_SESSMGR_TZ_MAX];
	uint8_t resp[8];
	struct msghdr msg;
	struct iovec iov;
	char   cbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t n;
	int recvd_fd = -1;
	size_t tz_len = 0;
	size_t req_len;

	if (s == NULL || s->fd < 0 || fd_out == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (tz != NULL) {
		tz_len = strlen(tz);
		if (tz_len > RDP_SESSMGR_TZ_MAX)
			tz_len = RDP_SESSMGR_TZ_MAX;
	}
	memset(req, 0, 12);
	req[0] = RDP_SESSMGR_OP_SPAWN;
	req[2] = (uint8_t)(w & 0xff);
	req[3] = (uint8_t)((w >> 8) & 0xff);
	req[4] = (uint8_t)(h & 0xff);
	req[5] = (uint8_t)((h >> 8) & 0xff);
	req[6] = (uint8_t)(tz_len & 0xff);
	req[7] = (uint8_t)((tz_len >> 8) & 0xff);
	req[8]  = (uint8_t)(lcid & 0xff);
	req[9]  = (uint8_t)((lcid >> 8) & 0xff);
	req[10] = (uint8_t)((lcid >> 16) & 0xff);
	req[11] = (uint8_t)((lcid >> 24) & 0xff);
	if (tz_len > 0)
		memcpy(req + 12, tz, tz_len);
	req_len = 12 + tz_len;
	{
		ssize_t sn;
		do { sn = send(s->fd, req, req_len, 0); }
		while (sn < 0 && errno == EINTR);
		if (sn != (ssize_t)req_len) return -1;
	}

	memset(&msg, 0, sizeof msg);
	iov.iov_base = resp;
	iov.iov_len  = sizeof resp;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;
	memset(cbuf, 0, sizeof cbuf);
	do { n = recvmsg(s->fd, &msg, 0); } while (n < 0 && errno == EINTR);
	if (n < 4) {
		rdp_warn("sessmgr SPAWN: recvmsg returned %zd errno=%d",
			n, errno);
		return -1;
	}
	if (resp[0] != RDP_SESSMGR_OK) {
		rdp_warn("sessmgr SPAWN: status=%u", (unsigned)resp[0]);
		errno = EACCES;
		return -1;
	}
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS
		    && cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
			memcpy(&recvd_fd, CMSG_DATA(cmsg), sizeof(int));
			break;
		}
	}
	if (recvd_fd < 0) {
		rdp_warn("sessmgr SPAWN: no fd in reply");
		errno = EBADF;
		return -1;
	}
	*fd_out = recvd_fd;
	return 0;
}

void
rdp_sessmgr_close(struct rdp_sessmgr *s)
{
	if (s == NULL) return;
	if (s->fd >= 0) (void)close(s->fd);
	s->fd = -1;
	explicit_bzero(s->auth_user, sizeof s->auth_user);
}

int
rdp_sessmgr_suspend(const char *sock_path,
		uint32_t logon_id, const uint8_t arc_random[16],
		int be_fd)
{
	int fd;
	uint8_t req[24];
	struct msghdr msg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	uint8_t resp[8];
	ssize_t n;

	fd = connect_unix(sock_path);
	if (fd < 0) return -1;
	memset(req, 0, sizeof req);
	req[0] = RDP_SESSMGR_OP_SUSPEND;
	req[4] = (uint8_t)(logon_id & 0xff);
	req[5] = (uint8_t)((logon_id >> 8) & 0xff);
	req[6] = (uint8_t)((logon_id >> 16) & 0xff);
	req[7] = (uint8_t)((logon_id >> 24) & 0xff);
	memcpy(req + 8, arc_random, 16);

	memset(&msg, 0, sizeof msg);
	iov.iov_base = req;
	iov.iov_len = sizeof req;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &be_fd, sizeof(int));
	if (sendmsg(fd, &msg, 0) < 0) {
		(void)close(fd);
		return -1;
	}
	n = recv(fd, resp, sizeof resp, 0);
	(void)close(fd);
	if (n < 1 || resp[0] != RDP_SESSMGR_OK) return -1;
	return 0;
}

int
rdp_sessmgr_resume(const char *sock_path,
		uint32_t logon_id, int *fd_out,
		uint8_t arc_random_out[16])
{
	int fd;
	uint8_t req[8];
	uint8_t resp[24];
	struct msghdr msg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t n;
	int recvd_fd = -1;

	fd = connect_unix(sock_path);
	if (fd < 0) return -1;
	memset(req, 0, sizeof req);
	req[0] = RDP_SESSMGR_OP_RESUME;
	req[4] = (uint8_t)(logon_id & 0xff);
	req[5] = (uint8_t)((logon_id >> 8) & 0xff);
	req[6] = (uint8_t)((logon_id >> 16) & 0xff);
	req[7] = (uint8_t)((logon_id >> 24) & 0xff);
	if (send(fd, req, sizeof req, 0) != (ssize_t)sizeof req) {
		(void)close(fd);
		return -1;
	}
	memset(&msg, 0, sizeof msg);
	iov.iov_base = resp;
	iov.iov_len = sizeof resp;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;
	n = recvmsg(fd, &msg, 0);
	(void)close(fd);
	if (n < 1 || resp[0] != RDP_SESSMGR_OK) return -1;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS
		    && cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
			memcpy(&recvd_fd, CMSG_DATA(cmsg), sizeof(int));
	}
	if (recvd_fd < 0) return -1;
	if (n >= 24 && arc_random_out != NULL)
		memcpy(arc_random_out, resp + 8, 16);
	*fd_out = recvd_fd;
	return 0;
}
