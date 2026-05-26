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
 *   1. Read NTLMSSP_NEGOTIATE
 *   2. Send NTLMSSP_CHALLENGE
 *   3. Read NTLMSSP_AUTHENTICATE + pubKeyAuth
 *   4. Look up NT hash, verify NTLMv2, derive session key
 *   5. Send pubKeyAuth response (stub - not channel-bound)
 *   6. Read authInfo, decrypt with seal key
 *   7. Parse TSCredentials, extract plaintext user + password
 *
 * NT hashes are read from /etc/rdpserver/nthashes (format:
 * user:hex_hash, one per line). Create entries with rdp-passwd.
 */

#include "nla.h"
#include "cssp.h"
#include "ntlm.h"
#include "nla_crypto.h"
#include "tls.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/utf16.h"

#include <openssl/evp.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NLA_MAX_TSREQ (16 * 1024)
#define NTHASH_PATH   "/etc/rdpserver/nthashes"

static int
read_tsrequest(struct rdp_tls *t, uint8_t *buf, size_t cap, size_t *out_len)
{
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

static int
hex2byte(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + c - 'a';
	if (c >= 'A' && c <= 'F') return 10 + c - 'A';
	return -1;
}

static int
lookup_nthash(const char *user, uint8_t nthash[16])
{
	FILE *fp;
	char line[512];

	fp = fopen(NTHASH_PATH, "r");
	if (fp == NULL) return -1;
	while (fgets(line, sizeof line, fp) != NULL) {
		char *colon = strchr(line, ':');
		size_t ulen;
		int i;
		if (colon == NULL) continue;
		ulen = (size_t)(colon - line);
		if (ulen != strlen(user)) continue;
		if (strncmp(line, user, ulen) != 0) continue;
		colon++;
		while (*colon == ' ') colon++;
		for (i = 0; i < 16; i++) {
			int hi = hex2byte(colon[i * 2]);
			int lo = hex2byte(colon[i * 2 + 1]);
			if (hi < 0 || lo < 0) { fclose(fp); return -1; }
			nthash[i] = (uint8_t)((hi << 4) | lo);
		}
		fclose(fp);
		return 0;
	}
	fclose(fp);
	return -1;
}

int
rdp_nla_server(struct rdp_tls *t,
		char *user, size_t user_size,
		char *pass, size_t pass_size)
{
	uint8_t  in_buf[NLA_MAX_TSREQ];
	uint8_t  out_buf[NLA_MAX_TSREQ];
	size_t   in_len;
	struct rdp_tsrequest req, resp;
	struct ntlm_negotiate neg;
	struct ntlm_authenticate auth;
	uint8_t  server_challenge[8];
	uint8_t  session_base_key[16];
	uint8_t  exported[16];
	uint8_t  cts_seal[16];
	uint8_t  nthash[16];
	char     user_utf8[256];
	char     domain_utf8[256];
	ssize_t  bn;

	memset(user, 0, user_size);
	memset(pass, 0, pass_size);

	/* 1. Read NEGOTIATE. */
	uint8_t saved_nonce[32];
	size_t saved_nonce_len = 0;

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
	if (req.client_nonce != NULL && req.client_nonce_len >= 32) {
		memcpy(saved_nonce, req.client_nonce, 32);
		saved_nonce_len = 32;
		rdp_debug("nla: saved nonce from NEGOTIATE");
	} else {
		rdp_debug("nla: no nonce in NEGOTIATE");
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
		if (got == (size_t)-1 || got >= sizeof user_utf8) got = 0;
		user_utf8[got] = '\0';
		got = rdp_utf16le_to_utf8(domain_utf8, sizeof domain_utf8 - 1,
			auth.domain_utf16, auth.domain_utf16_len);
		if (got == (size_t)-1 || got >= sizeof domain_utf8) got = 0;
		domain_utf8[got] = '\0';
	}
	rdp_info("nla: user='%s' domain='%s'", user_utf8, domain_utf8);

	/* Fall back to AUTHENTICATE nonce if NEGOTIATE had none. */
	if (saved_nonce_len == 0 && req.client_nonce != NULL
	    && req.client_nonce_len >= 32) {
		memcpy(saved_nonce, req.client_nonce, 32);
		saved_nonce_len = 32;
		rdp_debug("nla: saved nonce from AUTHENTICATE");
	}

	/* 4. Look up NT hash and verify NTLMv2. */
	if (lookup_nthash(user_utf8, nthash) != 0) {
		rdp_warn("nla: no NT hash for user '%s' in %s",
			user_utf8, NTHASH_PATH);
		return -1;
	}

	if (ntlm_verify_ntlmv2_hash(server_challenge, &auth,
		nthash, session_base_key) != 0) {
		rdp_warn("nla: NTLMv2 verification failed for '%s'",
			user_utf8);
		return -1;
	}
	rdp_info("nla: NTLMv2 verified for '%s'", user_utf8);

	if (ntlm_derive_exported_key(&auth, session_base_key, exported) != 0) {
		rdp_warn("nla: derive exported key failed");
		return -1;
	}
	ntlm_seal_key(1, exported, cts_seal);

	/* Initialize the client-to-server RC4 state. The client's RC4
	 * handle persists across messages, so we must advance ours past
	 * the client's pubKeyAuth before we can decrypt authInfo. */
	struct rdp_rc4 *cts_rc4 = rdp_rc4_new(cts_seal, 16);
	if (cts_rc4 == NULL) return -1;
	if (req.pub_key_auth != NULL && req.pub_key_auth_len > 16) {
		uint8_t junk[2048];
		size_t pka_msg_len = req.pub_key_auth_len - 16;
		rdp_rc4_process(cts_rc4, req.pub_key_auth + 16, junk,
		    pka_msg_len > sizeof junk ? sizeof junk : pka_msg_len);
		rdp_rc4_process(cts_rc4, req.pub_key_auth + 4, junk, 8);
	}

	/* 5. Send pubKeyAuth -- NTLM-seal the server cert public key
	 * to prove we own the TLS certificate. */
	{
		uint8_t pubkey[2048];
		ssize_t pklen;
		uint8_t stsc_seal[16], stsc_sign[16];
		uint8_t sealed[2048 + 16];
		ssize_t sealed_len;
		uint8_t msg_to_seal[2048];
		size_t msg_len;

		ntlm_seal_key(0, exported, stsc_seal);
		ntlm_sign_key(0, exported, stsc_sign);
		pklen = rdp_tls_get_server_pubkey(t, pubkey, sizeof pubkey);
		if (pklen <= 0) {
			rdp_warn("nla: cannot get server pubkey");
			return -1;
		}
		rdp_debug("nla: pubkey len=%zd first=%02x%02x%02x%02x ver=%u",
			pklen, pubkey[0], pubkey[1], pubkey[2], pubkey[3],
			req.version);
		if (req.version >= 5 && saved_nonce_len >= 32) {
			/* CredSSP v5+: seal SHA-256(magic + nonce + pubkey) */
			static const uint8_t magic[] =
				"CredSSP Server-To-Client Binding Hash";
			EVP_MD_CTX *sha = EVP_MD_CTX_new();
			unsigned int hlen = 32;
			uint8_t hash[32];
			if (sha == NULL) return -1;
			EVP_DigestInit_ex(sha, EVP_sha256(), NULL);
			EVP_DigestUpdate(sha, magic, sizeof magic);
			EVP_DigestUpdate(sha, saved_nonce, 32);
			EVP_DigestUpdate(sha, pubkey, (size_t)pklen);
			EVP_DigestFinal_ex(sha, hash, &hlen);
			EVP_MD_CTX_free(sha);
			memcpy(msg_to_seal, hash, 32);
			msg_len = 32;
		} else {
			/* CredSSP v2-4: seal pubkey with first byte + 1 */
			memcpy(msg_to_seal, pubkey, (size_t)pklen);
			msg_to_seal[0]++;
			msg_len = (size_t)pklen;
		}
		rdp_debug("nla: seal input len=%zu hash=%02x%02x%02x%02x "
			"skey=%02x%02x%02x%02x",
			msg_len,
			msg_to_seal[0], msg_to_seal[1],
			msg_to_seal[2], msg_to_seal[3],
			stsc_seal[0], stsc_seal[1],
			stsc_seal[2], stsc_seal[3]);
		sealed_len = ntlm_seal_message(stsc_seal, stsc_sign, 0,
			msg_to_seal, msg_len, sealed, sizeof sealed);
		if (sealed_len <= 0) {
			rdp_warn("nla: seal pubKeyAuth failed (%zd)", sealed_len);
			return -1;
		}
		rdp_debug("nla: sealed len=%zd first=%02x%02x%02x%02x",
			sealed_len, sealed[0], sealed[1],
			sealed[2], sealed[3]);

		memset(&resp, 0, sizeof resp);
		resp.version = req.version;
		resp.pub_key_auth = sealed;
		resp.pub_key_auth_len = (size_t)sealed_len;
		bn = rdp_cssp_build(out_buf, sizeof out_buf, &resp);
		if (bn <= 0) return -1;
		rdp_debug("nla: TSReq %zd: %02x%02x%02x%02x %02x%02x%02x%02x",
			bn, out_buf[0], out_buf[1], out_buf[2], out_buf[3],
			out_buf[4], out_buf[5], out_buf[6], out_buf[7]);
		if (rdp_tls_write_full(t, out_buf, (size_t)bn)
		    != (ssize_t)bn) return -1;
		explicit_bzero(stsc_seal, sizeof stsc_seal);
		explicit_bzero(stsc_sign, sizeof stsc_sign);
	}

	/* 6. Read authInfo and decrypt. */
	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read authInfo failed");
		return -1;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.auth_info == NULL || req.auth_info_len == 0) {
		rdp_warn("nla: missing authInfo");
		return -1;
	}

	{
		uint8_t *decrypted;
		size_t dec_len;
		struct rdp_rc4 *rc4;
		struct rdp_tscredentials tc;

		if (req.auth_info_len < 16) {
			rdp_warn("nla: authInfo too short");
			return -1;
		}
		dec_len = req.auth_info_len - 16;
		decrypted = malloc(dec_len);
		if (decrypted == NULL) {
			rdp_rc4_free(cts_rc4);
			return -1;
		}

		/* Decrypt using the persisted RC4 state (message first) */
		rdp_rc4_process(cts_rc4, req.auth_info + 16, decrypted, dec_len);
		{
			uint8_t skip[8];
			rdp_rc4_process(cts_rc4, req.auth_info + 4, skip, 8);
		}
		rdp_rc4_free(cts_rc4);

		if (rdp_cssp_parse_tscredentials(decrypted, dec_len, &tc) != 0) {
			rdp_warn("nla: TSCredentials parse failed");
			explicit_bzero(decrypted, dec_len);
			free(decrypted);
			return -1;
		}

		{
			size_t got;
			got = rdp_utf16le_to_utf8(user, user_size - 1,
				tc.user_utf16, tc.user_utf16_len);
			if (got == (size_t)-1 || got >= user_size) got = 0;
			user[got] = '\0';
			got = rdp_utf16le_to_utf8(pass, pass_size - 1,
				tc.password_utf16, tc.password_utf16_len);
			if (got == (size_t)-1 || got >= pass_size) got = 0;
			pass[got] = '\0';
		}

		explicit_bzero(decrypted, dec_len);
		free(decrypted);
	}

	rdp_info("nla: credentials extracted for '%s'", user);
	explicit_bzero(nthash, sizeof nthash);
	explicit_bzero(session_base_key, sizeof session_base_key);
	explicit_bzero(exported, sizeof exported);
	explicit_bzero(cts_seal, sizeof cts_seal);
	return 0;
}
