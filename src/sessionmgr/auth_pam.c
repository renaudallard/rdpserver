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
 * auth_pam.c -- PAM backend for rdp-sessionmgr.
 *
 * Linux/FreeBSD/NetBSD use this file.  Selected by ./configure when
 * the PAM headers and libpam are present.
 *
 * The conversation callback only services PAM_PROMPT_ECHO_OFF
 * (password) and PAM_PROMPT_ECHO_ON (username variant); everything
 * else (text, error) is acknowledged with an empty response.  Real
 * PAM stacks like pam_unix on Debian work fine with this minimal
 * conversation.
 */

#define _GNU_SOURCE   /* setresuid/setresgid on glibc */

#include "auth.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#ifdef __APPLE__
#include <pam/pam_appl.h>
#else
#include <security/pam_appl.h>
#endif

#include <sys/types.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct rdp_auth {
	pam_handle_t   *pamh;
	struct pam_conv conv;
	const char     *password;   /* only during pam_authenticate */
	char           *user;       /* PAM_USER after account checks */
	int             cred;       /* pam_setcred(ESTABLISH) done */
	int             session;    /* pam_open_session done */
};

static int
conv_cb(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *appdata)
{
	struct rdp_auth *a = appdata;
	struct pam_response *r;
	int i;

	if (num_msg <= 0)
		return PAM_CONV_ERR;
	r = calloc((size_t)num_msg, sizeof *r);
	if (r == NULL)
		return PAM_BUF_ERR;
	for (i = 0; i < num_msg; i++) {
		r[i].resp = NULL;
		r[i].resp_retcode = 0;
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			/* Only pam_authenticate gets the password; prompts
			 * from the session stack are answered empty. */
			if (a->password != NULL)
				r[i].resp = strdup(a->password);
			break;
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
		default:
			break;
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

int
rdp_auth_user(const char *service, const char *user, const char *pass,
		const char *rhost, struct rdp_auth **out)
{
	struct rdp_auth *a;
	const void *item = NULL;
	const char *svc = (service != NULL && service[0]) ? service : "login";
	int rc;

	*out = NULL;
	if (user == NULL || pass == NULL || user[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	a = calloc(1, sizeof *a);
	if (a == NULL)
		return -1;
	a->conv.conv = conv_cb;
	a->conv.appdata_ptr = a;

	rc = pam_start(svc, user, &a->conv, &a->pamh);
	if (rc != PAM_SUCCESS) {
		rdp_warn("pam_start(%s, %s): %s", svc, user,
			pam_strerror(a->pamh, rc));
		free(a);
		return -1;
	}
	if (rhost != NULL && rhost[0] != '\0')
		(void)pam_set_item(a->pamh, PAM_RHOST, rhost);

	a->password = pass;
	rc = pam_authenticate(a->pamh, PAM_DISALLOW_NULL_AUTHTOK);
	a->password = NULL;
	if (rc == PAM_SUCCESS)
		rc = pam_acct_mgmt(a->pamh, PAM_DISALLOW_NULL_AUTHTOK);
	if (rc == PAM_SUCCESS
	    && pam_get_item(a->pamh, PAM_USER, &item) == PAM_SUCCESS
	    && item != NULL)
		a->user = strdup(item);
	if (rc == PAM_SUCCESS && a->user == NULL)
		rc = PAM_BUF_ERR;
	if (rc != PAM_SUCCESS) {
		rdp_info("pam: %s -> %s", user, pam_strerror(a->pamh, rc));
		(void)pam_end(a->pamh, rc);
		free(a->user);
		free(a);
		return -1;
	}
	rdp_info("pam: %s authenticated", a->user);
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
	int rc;

	/* Groups first so pam_group can add to them, then credentials,
	 * then the session, the order Linux-PAM documents. */
	if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
		rdp_err("initgroups %s: %s", pw->pw_name, strerror(errno));
		return -1;
	}
	rc = pam_setcred(a->pamh, PAM_ESTABLISH_CRED);
	if (rc != PAM_SUCCESS) {
		rdp_err("pam_setcred %s: %s", a->user,
			pam_strerror(a->pamh, rc));
		return -1;
	}
	a->cred = 1;
	/* An interactive desktop login, so pam_systemd registers it as a
	 * user session rather than a background one. */
	(void)pam_putenv(a->pamh, "XDG_SESSION_CLASS=user");
	rc = pam_open_session(a->pamh, 0);
	if (rc != PAM_SUCCESS) {
		rdp_err("pam_open_session %s: %s", a->user,
			pam_strerror(a->pamh, rc));
		return -1;
	}
	a->session = 1;
	return 0;
}

char **
rdp_auth_session_env(struct rdp_auth *a)
{
	return pam_getenvlist(a->pamh);
}

int
rdp_auth_become_user(struct rdp_auth *a, struct passwd *pw)
{
	(void)a;
	/* The monitor already set the supplementary groups. */
#if HAVE_SETRESUID
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0
	    || setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0)
		return -1;
#else
	if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
		return -1;
#endif
	return 0;
}

void
rdp_auth_session_close(struct rdp_auth *a)
{
	int rc = PAM_SUCCESS;

	if (a == NULL)
		return;
	if (a->session && (rc = pam_close_session(a->pamh, 0)) != PAM_SUCCESS)
		rdp_warn("pam_close_session %s: %s", a->user,
			pam_strerror(a->pamh, rc));
	if (a->cred)
		(void)pam_setcred(a->pamh, PAM_DELETE_CRED);
	(void)pam_end(a->pamh, rc);
	free(a->user);
	free(a);
}

void
rdp_auth_free(struct rdp_auth *a)
{
	if (a == NULL)
		return;
#ifdef PAM_DATA_SILENT
	/* The monitor owns any module state now; do not let pam_end
	 * clean it up from here. */
	(void)pam_end(a->pamh, PAM_SUCCESS | PAM_DATA_SILENT);
#else
	(void)pam_end(a->pamh, PAM_SUCCESS);
#endif
	free(a->user);
	free(a);
}
