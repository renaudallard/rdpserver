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
 *   5. Verify the AUTHENTICATE MIC and the client's pubKeyAuth
 *      channel binding, send our pubKeyAuth
 *   6. Read authInfo, unseal and verify its signature
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
#include "../common/str.h"
#include "../common/utf16.h"

#include <openssl/evp.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NLA_MAX_TSREQ (16 * 1024)
#define NLA_MAX_NEGOTIATE 1024
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
	/* Subtraction form: a 4-byte length can wrap the sum where size_t
	 * is 32 bits. */
	if (body_len > cap - hdr_len) return -1;
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

/* CredSSP v5+ binding hash: SHA-256(magic incl. NUL || nonce || pubkey). */
static int
binding_hash(const char *magic, size_t magic_len, const uint8_t nonce[32],
		const uint8_t *pubkey, size_t pklen, uint8_t out[32])
{
	EVP_MD_CTX *sha;
	unsigned int hlen = 32;
	int rc = -1;

	sha = EVP_MD_CTX_new();
	if (sha == NULL)
		return -1;
	if (EVP_DigestInit_ex(sha, EVP_sha256(), NULL) == 1
	    && EVP_DigestUpdate(sha, magic, magic_len) == 1
	    && EVP_DigestUpdate(sha, nonce, 32) == 1
	    && EVP_DigestUpdate(sha, pubkey, pklen) == 1
	    && EVP_DigestFinal_ex(sha, out, &hlen) == 1 && hlen == 32)
		rc = 0;
	EVP_MD_CTX_free(sha);
	return rc;
}

/* Check the client's pubKeyAuth (MS-CSSP 3.1.5): it must unseal, with
 * sequence number 0, to SHA-256(client-to-server magic || nonce ||
 * pubkey) for v5+, or to our public key itself for v2-4. A mismatch
 * means the client's TLS channel ends at someone other than us. */
static int
verify_client_binding(struct rdp_rc4 *rc4, const uint8_t sign_key[16],
		uint32_t version, const uint8_t *pka, size_t pka_len,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *pubkey, size_t pklen)
{
	static const char magic[] = "CredSSP Client-To-Server Binding Hash";
	uint8_t got[2048], hash[32];
	const uint8_t *want = pubkey;
	size_t want_len = pklen;
	ssize_t n;

	if (pka == NULL)
		return -1;
	n = ntlm_unseal_message(rc4, sign_key, 0, pka, pka_len, got,
		sizeof got);
	if (n < 0)
		return -1;
	if (version >= 5 && nonce_len >= 32) {
		if (binding_hash(magic, sizeof magic, nonce, pubkey, pklen,
		    hash) != 0)
			return -1;
		want = hash;
		want_len = sizeof hash;
	}
	if ((size_t)n != want_len || rdp_consttime_eq(got, want, want_len) != 0)
		return -1;
	return 0;
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
	uint8_t  cts_sign[16];
	uint8_t  nthash[16];
	uint8_t  neg_msg[NLA_MAX_NEGOTIATE];
	size_t   neg_len = 0;
	uint8_t  chal_buf[1024];
	size_t   chal_len = 0;
	uint8_t  pubkey[2048];
	ssize_t  pklen;
	char     user_utf8[256];
	char     domain_utf8[256];
	ssize_t  bn;
	struct rdp_rc4 *cts_rc4 = NULL;
	int      rc = -1;

	memset(user, 0, user_size);
	memset(pass, 0, pass_size);

	/* 1. Read NEGOTIATE. */
	uint8_t saved_nonce[32];
	size_t saved_nonce_len = 0;

	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read NEGOTIATE failed");
		goto out;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.nego_token == NULL
	    || ntlm_parse_negotiate(req.nego_token, req.nego_token_len,
		&neg) != 0) {
		rdp_warn("nla: bad NEGOTIATE");
		goto out;
	}
	/* Keep the NEGOTIATE message for the AUTHENTICATE MIC; in_buf is
	 * reused for the next TSRequest. */
	if (req.nego_token_len > sizeof neg_msg) {
		rdp_warn("nla: NEGOTIATE too large");
		goto out;
	}
	memcpy(neg_msg, req.nego_token, req.nego_token_len);
	neg_len = req.nego_token_len;
	if (req.client_nonce != NULL && req.client_nonce_len >= 32) {
		memcpy(saved_nonce, req.client_nonce, 32);
		saved_nonce_len = 32;
		rdp_debug("nla: saved nonce from NEGOTIATE");
	} else {
		rdp_debug("nla: no nonce in NEGOTIATE");
	}

	/* 2. Send CHALLENGE. */
	{
		ssize_t cn = ntlm_build_challenge(chal_buf, sizeof chal_buf,
			neg.flags, "rdpserver", server_challenge);
		if (cn <= 0) goto out;
		chal_len = (size_t)cn;
		memset(&resp, 0, sizeof resp);
		resp.version = req.version;
		resp.nego_token = chal_buf;
		resp.nego_token_len = (size_t)cn;
		bn = rdp_cssp_build(out_buf, sizeof out_buf, &resp);
		if (bn <= 0) goto out;
		if (rdp_tls_write_full(t, out_buf, (size_t)bn)
		    != (ssize_t)bn) goto out;
	}

	/* 3. Read AUTHENTICATE. */
	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read AUTHENTICATE failed");
		goto out;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.nego_token == NULL
	    || ntlm_parse_authenticate(req.nego_token, req.nego_token_len,
		&auth) != 0) {
		rdp_warn("nla: bad AUTHENTICATE");
		goto out;
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
		goto out;
	}

	if (ntlm_verify_ntlmv2_hash(server_challenge, &auth,
		nthash, session_base_key) != 0) {
		rdp_warn("nla: NTLMv2 verification failed for '%s'",
			user_utf8);
		goto out;
	}
	rdp_info("nla: NTLMv2 verified for '%s'", user_utf8);

	if (ntlm_derive_exported_key(&auth, session_base_key, exported) != 0) {
		rdp_warn("nla: derive exported key failed");
		goto out;
	}
	/* MS-NLMP 3.3.2: a client that flags a MIC in its AV pairs (they
	 * are covered by the NTProofStr we just checked) must have it
	 * verified, or the NEGOTIATE and CHALLENGE flags it saw could have
	 * been altered in transit. */
	if (!ntlm_auth_has_mic(&auth)) {
		rdp_debug("nla: client sent no MIC");
	} else if (ntlm_verify_mic(exported, neg_msg, neg_len, chal_buf,
	    chal_len, req.nego_token, req.nego_token_len) != 0) {
		rdp_warn("nla: AUTHENTICATE MIC mismatch for '%s'", user_utf8);
		goto out;
	} else {
		rdp_debug("nla: AUTHENTICATE MIC verified");
	}
	ntlm_seal_key(1, exported, cts_seal);
	ntlm_sign_key(1, exported, cts_sign);

	pklen = rdp_tls_get_server_pubkey(t, pubkey, sizeof pubkey);
	if (pklen <= 0) {
		rdp_warn("nla: cannot get server pubkey");
		goto out;
	}

	/* The client-to-server RC4 stream runs across messages: pubKeyAuth
	 * first, authInfo after it. */
	cts_rc4 = rdp_rc4_new(cts_seal, 16);
	if (cts_rc4 == NULL) goto out;
	if (verify_client_binding(cts_rc4, cts_sign, req.version,
	    req.pub_key_auth, req.pub_key_auth_len, saved_nonce,
	    saved_nonce_len, pubkey, (size_t)pklen) != 0) {
		rdp_warn("nla: client pubKeyAuth does not match our TLS key");
		goto out;
	}
	rdp_debug("nla: client pubKeyAuth verified (CredSSP v%u)",
		(unsigned)req.version);

	/* 5. Send pubKeyAuth -- NTLM-seal the server cert public key
	 * to prove we own the TLS certificate. */
	{
		uint8_t stsc_seal[16], stsc_sign[16];
		uint8_t sealed[2048 + 16];
		ssize_t sealed_len;
		uint8_t msg_to_seal[2048];
		size_t msg_len;

		ntlm_seal_key(0, exported, stsc_seal);
		ntlm_sign_key(0, exported, stsc_sign);
		rdp_debug("nla: pubkey len=%zd first=%02x%02x%02x%02x ver=%u",
			pklen, pubkey[0], pubkey[1], pubkey[2], pubkey[3],
			req.version);
		if (req.version >= 5 && saved_nonce_len >= 32) {
			/* CredSSP v5+: seal SHA-256(magic + nonce + pubkey) */
			static const char magic[] =
				"CredSSP Server-To-Client Binding Hash";
			if (binding_hash(magic, sizeof magic, saved_nonce,
			    pubkey, (size_t)pklen, msg_to_seal) != 0)
				goto out;
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
			goto out;
		}
		rdp_debug("nla: sealed len=%zd first=%02x%02x%02x%02x",
			sealed_len, sealed[0], sealed[1],
			sealed[2], sealed[3]);

		memset(&resp, 0, sizeof resp);
		resp.version = req.version;
		resp.pub_key_auth = sealed;
		resp.pub_key_auth_len = (size_t)sealed_len;
		bn = rdp_cssp_build(out_buf, sizeof out_buf, &resp);
		if (bn <= 0) goto out;
		rdp_debug("nla: TSReq %zd: %02x%02x%02x%02x %02x%02x%02x%02x",
			bn, out_buf[0], out_buf[1], out_buf[2], out_buf[3],
			out_buf[4], out_buf[5], out_buf[6], out_buf[7]);
		if (rdp_tls_write_full(t, out_buf, (size_t)bn)
		    != (ssize_t)bn) goto out;
		explicit_bzero(stsc_seal, sizeof stsc_seal);
		explicit_bzero(stsc_sign, sizeof stsc_sign);
	}

	/* 6. Read authInfo and decrypt. */
	if (read_tsrequest(t, in_buf, sizeof in_buf, &in_len) != 0) {
		rdp_warn("nla: read authInfo failed");
		goto out;
	}
	if (rdp_cssp_parse(in_buf, in_len, &req) != 0
	    || req.auth_info == NULL || req.auth_info_len == 0) {
		rdp_warn("nla: missing authInfo");
		goto out;
	}

	{
		uint8_t *decrypted;
		size_t dec_len;
		struct rdp_tscredentials tc;

		if (req.auth_info_len < 16) {
			rdp_warn("nla: authInfo too short");
			goto out;
		}
		dec_len = req.auth_info_len - 16;
		decrypted = malloc(dec_len);
		if (decrypted == NULL)
			goto out;

		/* The client's second sealed message: sequence number 1. */
		if (ntlm_unseal_message(cts_rc4, cts_sign, 1, req.auth_info,
		    req.auth_info_len, decrypted, dec_len) < 0) {
			rdp_warn("nla: authInfo signature does not verify");
			explicit_bzero(decrypted, dec_len);
			free(decrypted);
			goto out;
		}
		rdp_rc4_free(cts_rc4);
		cts_rc4 = NULL;

		if (rdp_cssp_parse_tscredentials(decrypted, dec_len, &tc) != 0) {
			rdp_warn("nla: TSCredentials parse failed");
			explicit_bzero(decrypted, dec_len);
			free(decrypted);
			goto out;
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
	rc = 0;
out:
	rdp_rc4_free(cts_rc4);
	explicit_bzero(nthash, sizeof nthash);
	explicit_bzero(session_base_key, sizeof session_base_key);
	explicit_bzero(exported, sizeof exported);
	explicit_bzero(cts_seal, sizeof cts_seal);
	explicit_bzero(cts_sign, sizeof cts_sign);
	return rc;
}
