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
 * sessionmgr.h -- client-side helper for talking to rdp-sessionmgr.
 *
 * The privileged session broker is its own binary.  rdpd workers
 * connect to its AF_UNIX socket for each authentication.  This
 * header exposes only the worker-side helpers; the daemon main is
 * in src/sessionmgr/sessionmgr.c and is compiled into the
 * rdp-sessionmgr binary, not linked into rdpd.
 */

#ifndef RDP_SESSIONMGR_H
#define RDP_SESSIONMGR_H

#include "../include/compat.h"
#include "protocol.h"

#include <stddef.h>
#include <sys/types.h>

/* Worker handle: connect once, do AUTH, then SPAWN.  Caller owns the
 * struct.  The auth_user buffer remembers which name authenticated
 * so subsequent SPAWN doesn't need to re-quote it. */
struct rdp_sessmgr {
	int  fd;
	char auth_user[RDP_SESSMGR_USER_MAX + 1];
};

/* Open a connection to `sock_path` and run AUTH.  Returns 0 on
 * success and fills *out so the caller can chain SPAWN.  Returns
 * -1 on transport or auth failure.  The caller `explicit_bzero`s
 * the password buffer after this returns. */
int rdp_sessmgr_open_auth(struct rdp_sessmgr *out,
		const char *sock_path,
		const char *user, const char *pass,
		const char *client_ip);

int rdp_sessmgr_open_nla(struct rdp_sessmgr *out,
		const char *sock_path, const char *user,
		const uint8_t nonce[16]);

/* Register a nonce for a future NLA_AUTH request.  Called by the
 * worker that performed NLA authentication via password. */
int rdp_sessmgr_nla_store(const char *sock_path,
		const char *user, const uint8_t nonce[16]);

/* SPAWN: ask sessmgr to fork+setuid+exec rdp-session as the
 * authenticated user.  Returns the backend socket fd (one end of
 * a SOCK_STREAM socketpair) via *fd_out.  Caller closes when
 * done. */
int rdp_sessmgr_spawn(struct rdp_sessmgr *s,
		uint16_t w, uint16_t h, uint32_t lcid, int *fd_out);

void rdp_sessmgr_close(struct rdp_sessmgr *s);

/* SUSPEND: worker hands its backend fd + logonId to sessmgr so the
 * session stays alive across a reconnect. */
int rdp_sessmgr_suspend(const char *sock_path,
		uint32_t logon_id, const uint8_t arc_random[16],
		int be_fd);

/* RESUME: new worker presents a logonId; sessmgr returns the
 * matching backend fd if the session is still alive. */
int rdp_sessmgr_resume(const char *sock_path,
		uint32_t logon_id, int *fd_out,
		uint8_t arc_random_out[16]);

#endif /* RDP_SESSIONMGR_H */
