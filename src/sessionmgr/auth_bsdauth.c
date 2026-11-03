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
 * auth_bsdauth.c -- bsd_auth backend for rdp-sessionmgr.
 *
 * OpenBSD uses this file.  `auth_userokay(3)` performs the full
 * challenge/response against the user's login class default style
 * (typically passwd in /etc/master.passwd).  The function takes
 * non-const char pointers; we duplicate into scratch buffers to
 * stay strictly conforming and so we can `explicit_bzero` them on
 * the way out.
 *
 * The `service` argument is unused here; bsd_auth picks the style
 * from login.conf based on the user's class.
 */

#include "auth.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include <sys/types.h>
#include <login_cap.h>
#include <bsd_auth.h>

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct rdp_auth {
	char *user;
};

int
rdp_auth_user(const char *service, const char *user, const char *pass,
		const char *rhost, struct rdp_auth **out)
{
	struct rdp_auth *a;
	char *u = NULL, *p = NULL;
	int ok;

	(void)service;
	(void)rhost;
	*out = NULL;
	if (user == NULL || pass == NULL || user[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	u = strdup(user);
	p = strdup(pass);
	if (u == NULL || p == NULL) {
		if (u) free(u);
		if (p) { explicit_bzero(p, strlen(p)); free(p); }
		errno = ENOMEM;
		return -1;
	}

	rdp_info("bsd_auth: trying user='%s'", u);
	ok = auth_userokay(u, NULL, NULL, p);
	rdp_info("bsd_auth: auth_userokay returned %d", ok);

	explicit_bzero(p, strlen(p));
	free(p);

	if (!ok) {
		rdp_info("bsd_auth: %s rejected", user);
		free(u);
		return -1;
	}
	a = calloc(1, sizeof *a);
	if (a == NULL) {
		free(u);
		return -1;
	}
	a->user = u;
	rdp_info("bsd_auth: %s authenticated", user);
	*out = a;
	return 0;
}

const char *
rdp_auth_username(const struct rdp_auth *a)
{
	return a->user;
}

int
rdp_auth_session_open(struct rdp_auth *a, const struct passwd *pw)
{
	/* bsd_auth has no session stack; the login class is applied by
	 * rdp_auth_become_user. */
	(void)a;
	(void)pw;
	return 0;
}

char **
rdp_auth_session_env(struct rdp_auth *a)
{
	(void)a;
	return NULL;
}

int
rdp_auth_become_user(struct rdp_auth *a, struct passwd *pw)
{
	(void)a;
	/* Groups, resource limits, priority, umask, login name and uid from
	 * the user's login class. PATH and the environment stay as the
	 * session manager set them. */
	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETALL & ~(LOGIN_SETPATH | LOGIN_SETENV)) != 0)
		return -1;
	return 0;
}

void
rdp_auth_session_close(struct rdp_auth *a)
{
	rdp_auth_free(a);
}

void
rdp_auth_free(struct rdp_auth *a)
{
	if (a == NULL)
		return;
	free(a->user);
	free(a);
}
