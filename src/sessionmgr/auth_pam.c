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

#include "auth.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include <security/pam_appl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct conv_state {
	const char *password;
};

static int
conv_cb(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *appdata)
{
	struct conv_state *st = appdata;
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
			if (st->password != NULL)
				r[i].resp = strdup(st->password);
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
rdp_auth_user(const char *service, const char *user, const char *pass)
{
	pam_handle_t *pamh = NULL;
	struct conv_state st;
	struct pam_conv conv;
	const char *svc = (service != NULL && service[0]) ? service : "login";
	int rc;

	if (user == NULL || pass == NULL || user[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	st.password = pass;
	conv.conv = conv_cb;
	conv.appdata_ptr = &st;

	rc = pam_start(svc, user, &conv, &pamh);
	if (rc != PAM_SUCCESS) {
		rdp_warn("pam_start(%s, %s): %s", svc, user,
			pam_strerror(pamh, rc));
		return -1;
	}

	rc = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
	if (rc == PAM_SUCCESS)
		rc = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK);

	(void)pam_end(pamh, rc);
	if (rc != PAM_SUCCESS) {
		rdp_info("pam: %s -> %s", user, pam_strerror(NULL, rc));
		return -1;
	}
	rdp_info("pam: %s authenticated", user);
	return 0;
}
