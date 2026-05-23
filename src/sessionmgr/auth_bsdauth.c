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
#include <stdlib.h>
#include <string.h>

int
rdp_auth_user(const char *service, const char *user, const char *pass)
{
	char *u = NULL, *p = NULL;
	int ok;

	(void)service;
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

	rdp_info("bsd_auth: trying user='%s' (ulen=%zu, plen=%zu)",
		u, strlen(u), strlen(p));
	ok = auth_userokay(u, NULL, NULL, p);
	rdp_info("bsd_auth: auth_userokay returned %d", ok);

	free(u);
	explicit_bzero(p, strlen(p));
	free(p);

	if (ok) {
		rdp_info("bsd_auth: %s authenticated", user);
		return 0;
	}
	rdp_info("bsd_auth: %s rejected", user);
	return -1;
}
