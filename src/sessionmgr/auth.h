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
 * auth.h -- pluggable authentication backend interface.
 *
 * Exactly one of auth_pam.c (PAM, used on Linux/FreeBSD/NetBSD) or
 * auth_bsdauth.c (bsd_auth, used on OpenBSD) is built and linked
 * into rdp-sessionmgr.  The configure script picks which based on
 * what the host provides.
 *
 * A successful rdp_auth_user returns a handle that carries the login
 * through to the session, so the backend can run its session stack
 * around the user's processes:
 *
 *   sessmgr:  rdp_auth_user, then fork the per-session monitor and
 *             rdp_auth_free its own copy of the handle
 *   monitor:  rdp_auth_session_open (root), fork the user process,
 *             wait for it, rdp_auth_session_close
 *   user:     rdp_auth_session_env, rdp_auth_become_user, exec
 *
 * Backends never keep the password past rdp_auth_user and
 * explicit_bzero any local copy on the way out.
 *
 * Service name affects which PAM stack is consulted.  When NULL,
 * "login" is used (universally present, allows password auth out of
 * the box).  Production deployments install contrib/pam.d/rdpd and
 * pass "rdpd" here.
 */

#ifndef RDP_AUTH_H
#define RDP_AUTH_H

struct passwd;
struct rdp_auth;

/* Authenticate user/pass; rhost is the client address for the auth
 * stack (may be NULL).  Returns 0 and a handle in *out on success. */
int rdp_auth_user(const char *service, const char *user, const char *pass,
		const char *rhost, struct rdp_auth **out);

/* Login name the backend settled on, which a PAM module may have mapped
 * from the name the client typed. */
const char *rdp_auth_username(const struct rdp_auth *a);

/* Monitor, as root: set the user's groups, establish credentials and
 * open the session.  Returns 0 on success. */
int rdp_auth_session_open(struct rdp_auth *a, const struct passwd *pw);

/* NULL-terminated NAME=value list the session stack exported, or NULL.
 * The strings stay valid until exec. */
char **rdp_auth_session_env(struct rdp_auth *a);

/* User process: drop to the user for good.  Returns 0 on success. */
int rdp_auth_become_user(struct rdp_auth *a, struct passwd *pw);

/* Close whatever rdp_auth_session_open set up, then free the handle.
 * The monitor calls it once the user process has exited; the session
 * manager also uses it for a handle that never reached a spawn. */
void rdp_auth_session_close(struct rdp_auth *a);

/* Free the session manager's copy of a handle once the monitor has
 * forked with it, without disturbing the monitor's session state. */
void rdp_auth_free(struct rdp_auth *a);

#endif /* RDP_AUTH_H */
