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
 * The same `rdp_auth_user` signature is exposed regardless.  All
 * backends must:
 *   - return 0 on success, -1 on failure
 *   - never store the password beyond the call
 *   - explicit_bzero any local copy on the way out
 *
 * Service name affects which PAM stack is consulted on Linux.  When
 * NULL, "login" is used (universally present, allows password auth
 * out of the box).  Production deployments install a tailored
 * `/etc/pam.d/rdpd` and pass "rdpd" here.
 */

#ifndef RDP_AUTH_H
#define RDP_AUTH_H

int rdp_auth_user(const char *service, const char *user, const char *pass);

#endif /* RDP_AUTH_H */
