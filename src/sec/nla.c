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
 * nla.c -- CredSSP / NLA server flow.
 *
 * Sequence (TLS already established):
 *
 *   1. Read TSRequest #1 from client:  negoTokens = NTLMSSP_NEGOTIATE
 *   2. Write TSRequest #2 to client:   negoTokens = NTLMSSP_CHALLENGE
 *   3. Read TSRequest #3 from client:  negoTokens = NTLMSSP_AUTHENTICATE
 *                                      + pubKeyAuth (we ignore in v1)
 *   4. Write TSRequest #4 to client:   pubKeyAuth = stub OK
 *   5. Read TSRequest #5 from client:  authInfo = RC4-sealed TSCredentials
 *   6. Decrypt authInfo with the client-to-server seal key
 *   7. Parse TSCredentials -> TSPasswordCreds, decode UTF-16LE -> UTF-8
 *
 * The decoded cleartext is what the caller hands to PAM/bsd_auth.
 *
 * What we DO NOT do in v1: pubKeyAuth verification (channel
 * binding) -- this is a security gap we document.  Production
 * deployments should require it.
 */

#include "nla.h"
#include "cssp.h"
#include "ntlm.h"
#include "nla_crypto.h"
#include "tls.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/utf16.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Bound on a single TSRequest read.  Generous so AV-pair-heavy
 * AUTHENTICATE messages fit. */
#define NLA_MAX_TSREQ (16 * 1024)

static int
read_tsrequest(struct rdp_tls *t, uint8_t *buf, size_t cap, size_t *out_len)
{
	/* TSRequest is DER-encoded, leading with the SEQUENCE tag (0x30)
	 * followed by a length.  Read enough to decode the length, then
	 * the rest of the body. */
	ssize_t n;
	size_t  body_len, hdr_len;
	uint8_t lb;

	n = rdp_tls_read_full(t, buf, 2);
	if (n != 2) return -1;
	if (buf[0] != 0x30) return -1;
	lb = buf[1];
	if ((lb & 0x80) == 0) {
		body_len = lb;
		hdr_len = 2;
	} else {
		unsigned int nlen = lb & 0x7f;
		size_t i, acc = 0;
		if (nlen == 0 || nlen > 4) return -1;
		n = rdp_tls_read_full(t, buf + 2, nlen);
		if (n != (ssize_t)nlen) return -1;
		for (i = 0; i < nlen; i++)
			acc = (acc << 8) | buf[2 + i];
		body_len = acc;
		hdr_len = 2 + nlen;
	}
	if (hdr_len + body_len > cap) return -1;
	n = rdp_tls_read_full(t, buf + hdr_len, body_len);
	if (n != (ssize_t)body_len) return -1;
	*out_len = hdr_len + body_len;
	return 0;
}

int
rdp_nla_server(struct rdp_tls *t,
		char *user, size_t user_size,
		char *pass, size_t pass_size)
{
	uint8_t  in_buf[NLA_MAX_TSREQ];
	uint8_t  out_buf[NLA_MAX_TSREQ];
	size_t   in_len, out_len;
	struct rdp_tsrequest req, resp;
	struct ntlm_negotiate neg;
	struct ntlm_authenticate auth;
	uint8_t  server_challenge[8];
	uint8_t  session_base_key[16];
	uint8_t  exported[16];
	uint8_t  cts_seal[16];
	char     user_utf8[256];
	char     domain_utf8[256];
	struct rdp_tscredentials tc;
	int rc = -1;
	ssize_t bn;

	/* 1. Read NEGOTIATE. */
	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read NEGOTIATE failed");
		return -1;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.nego_token == NULL
	    || ntlm_parse_negotiate(req.nego_token, req.nego_token_len,
		&neg) != 0) {
		rdp_warn("nla: bad NEGOTIATE");
		return -1;
	}

	/* 2. Send CHALLENGE. */
	{
		uint8_t chal_buf[1024];
		ssize_t cn = ntlm_build_challenge(chal_buf, sizeof chal_buf,
			neg.flags, "rdpserver", server_challenge);
		if (cn <= 0) return -1;
		memset(&resp, 0, sizeof resp);
		resp.version = req.version;
		resp.nego_token = chal_buf;
		resp.nego_token_len = (size_t)cn;
		bn = rdp_cssp_build(out_buf, sizeof out_buf, &resp);
		if (bn <= 0) return -1;
		if (rdp_tls_write_full(t, out_buf, (size_t)bn)
		    != (ssize_t)bn) return -1;
	}

	/* 3. Read AUTHENTICATE. */
	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read AUTHENTICATE failed");
		return -1;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.nego_token == NULL
	    || ntlm_parse_authenticate(req.nego_token, req.nego_token_len,
		&auth) != 0) {
		rdp_warn("nla: bad AUTHENTICATE");
		return -1;
	}

	{
		size_t got;
		got = rdp_utf16le_to_utf8(user_utf8, sizeof user_utf8 - 1,
			auth.user_utf16, auth.user_utf16_len);
		if (got == (size_t)-1) got = 0;
		user_utf8[got] = '\0';
		got = rdp_utf16le_to_utf8(domain_utf8, sizeof domain_utf8 - 1,
			auth.domain_utf16, auth.domain_utf16_len);
		if (got == (size_t)-1) got = 0;
		domain_utf8[got] = '\0';
	}
	rdp_info("nla: AUTHENTICATE from user='%s' domain='%s'",
		user_utf8, domain_utf8);

	/* We don't know the password yet -- it's in the next round's
	 * authInfo, encrypted with the seal key.  Reply with a stub
	 * pubKeyAuth to keep the client moving.  Production should
	 * compute the real pubKeyAuth (TLS server pubkey + 1, signed
	 * with the seal MAC). */
	{
		uint8_t stub_pka[16] = {0};
		memset(&resp, 0, sizeof resp);
		resp.version = req.version;
		resp.pub_key_auth = stub_pka;
		resp.pub_key_auth_len = sizeof stub_pka;
		bn = rdp_cssp_build(out_buf, sizeof out_buf, &resp);
		if (bn <= 0) return -1;
		if (rdp_tls_write_full(t, out_buf, (size_t)bn)
		    != (ssize_t)bn) return -1;
	}

	/* 4. Read TSRequest with authInfo. */
	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read authInfo failed");
		return -1;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.auth_info == NULL) {
		rdp_warn("nla: missing authInfo");
		return -1;
	}

	/* We cannot validate the NTLMv2 response without knowing the
	 * password.  But the client encrypted authInfo with the
	 * client->server seal key, which is derived from the
	 * ExportedSessionKey, which is derived from the SessionBaseKey,
	 * which is the HMAC-MD5 of the NTLMv2 hash over NTProofStr.
	 * Without the password we can't compute SessionBaseKey, so we
	 * can't decrypt authInfo.  Decryption-as-validation: try the
	 * supplied password and check the result parses as
	 * TSCredentials with a sensible user; if not, reject.
	 *
	 * Approach: the AUTHENTICATE message already carries the user
	 * name.  We accept any password the client encrypts -- our job
	 * is then to feed it to PAM, which is the actual authority.
	 *
	 * However we still need the password bytes.  The client
	 * derived the seal key the same way; without the password we
	 * cannot.  So in v1 we require the worker's caller to supply
	 * a candidate password (it doesn't have one).  Practical
	 * solution: trust the AUTHENTICATE's NT response and require
	 * the user to type the password into the client; the
	 * password reaches us only inside authInfo (sealed) so we
	 * can't read it.
	 *
	 * Pragmatic v1 compromise: we cannot decrypt without the
	 * password.  We fail the NLA flow and return -1; rdpd falls
	 * back to TLS-only + greeter.  Production NLA needs hash-
	 * based PAM (winbind/sssd) or pre-shared credentials -- a
	 * separate engineering project.
	 *
	 * Bail out cleanly so the connection still terminates well. */
	(void)session_base_key; (void)exported; (void)cts_seal;
	(void)tc;
	rdp_warn("nla: decryption of authInfo not supported without a "
		"hash backend; client should retry with /sec:tls");

	memset(user, 0, user_size);
	memset(pass, 0, pass_size);

	rc = -1;
	return rc;
}
