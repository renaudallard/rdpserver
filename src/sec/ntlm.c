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
 * ntlm.c -- NTLMSSP message parsing and NTLMv2 verification.
 */

#include "ntlm.h"
#include "nla_crypto.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/buf.h"
#include "../common/utf16.h"
#include "../common/rand.h"

#include <openssl/evp.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NTLM_SIG "NTLMSSP\0"
#define NTLM_SIG_LEN 8

static uint16_t
ld_u16le(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t
ld_u32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
st_u16le(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static void
st_u32le(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static int
parse_field(const uint8_t *buf, size_t len, size_t off,
		struct ntlm_field *out)
{
	uint16_t flen, fmax;
	uint32_t foff;
	if (off + 8 > len) return -1;
	flen = ld_u16le(buf + off);
	fmax = ld_u16le(buf + off + 2);
	foff = ld_u32le(buf + off + 4);
	(void)fmax;
	if (flen == 0) {
		out->data = NULL;
		out->len = 0;
		return 0;
	}
	if ((size_t)foff + (size_t)flen > len) return -1;
	out->data = buf + foff;
	out->len = flen;
	return 0;
}

int
ntlm_parse_negotiate(const uint8_t *buf, size_t len,
		struct ntlm_negotiate *out)
{
	if (len < 16) return -1;
	if (memcmp(buf, NTLM_SIG, NTLM_SIG_LEN) != 0) return -1;
	if (ld_u32le(buf + 8) != NTLM_MSG_NEGOTIATE) return -1;
	out->flags = ld_u32le(buf + 12);
	return 0;
}

ssize_t
ntlm_build_challenge(uint8_t *out, size_t cap,
		uint32_t client_flags,
		const char *target_name,
		uint8_t challenge[8])
{
	uint32_t flags;
	uint8_t  target_utf16[256];
	size_t   target_utf16_len;
	uint8_t  av_block[256];
	size_t   av_len = 0;
	uint64_t timestamp;
	size_t   total, payload_off;

	/* Echo the client's protocol preferences but force the bits we
	 * need: Unicode + NTLMv2 (extended session security) + target
	 * info + always sign. */
	flags = (client_flags
		& (NTLMSSP_NEGOTIATE_UNICODE
		   | NTLMSSP_NEGOTIATE_OEM
		   | NTLMSSP_NEGOTIATE_SIGN
		   | NTLMSSP_NEGOTIATE_SEAL
		   | NTLMSSP_NEGOTIATE_NTLM
		   | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		   | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		   | NTLMSSP_NEGOTIATE_128
		   | NTLMSSP_NEGOTIATE_KEY_EXCH
		   | NTLMSSP_NEGOTIATE_56));
	flags |= NTLMSSP_NEGOTIATE_UNICODE
		| NTLMSSP_REQUEST_TARGET
		| NTLMSSP_NEGOTIATE_NTLM
		| NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		| NTLMSSP_NEGOTIATE_TARGET_INFO
		| NTLMSSP_NEGOTIATE_128;
	flags &= ~NTLMSSP_NEGOTIATE_OEM;
	flags &= ~NTLMSSP_NEGOTIATE_VERSION;

	target_utf16_len = rdp_utf8_to_utf16le(target_utf16,
		sizeof target_utf16, target_name, strlen(target_name));
	if (target_utf16_len == (size_t)-1) target_utf16_len = 0;

	/* AV pairs: NB computer name (target), NB domain name (empty),
	 * timestamp, EOL. */
	timestamp = ((uint64_t)time(NULL) + 11644473600ULL) * 10000000ULL;

	st_u16le(av_block + av_len, MSV_AV_NB_COMPUTER_NAME); av_len += 2;
	st_u16le(av_block + av_len, (uint16_t)target_utf16_len); av_len += 2;
	memcpy(av_block + av_len, target_utf16, target_utf16_len);
	av_len += target_utf16_len;

	st_u16le(av_block + av_len, MSV_AV_NB_DOMAIN_NAME); av_len += 2;
	st_u16le(av_block + av_len, (uint16_t)target_utf16_len); av_len += 2;
	memcpy(av_block + av_len, target_utf16, target_utf16_len);
	av_len += target_utf16_len;

	st_u16le(av_block + av_len, MSV_AV_TIMESTAMP); av_len += 2;
	st_u16le(av_block + av_len, 8); av_len += 2;
	memcpy(av_block + av_len, &timestamp, 8);
	av_len += 8;

	st_u16le(av_block + av_len, MSV_AV_EOL); av_len += 2;
	st_u16le(av_block + av_len, 0); av_len += 2;

	payload_off = 56;
	total = payload_off + target_utf16_len + av_len;
	if (total > cap) return -1;

	rdp_rand_bytes(challenge, 8);

	memset(out, 0, total);
	memcpy(out, NTLM_SIG, NTLM_SIG_LEN);
	st_u32le(out + 8, NTLM_MSG_CHALLENGE);
	/* TargetNameFields: len, maxlen, offset */
	st_u16le(out + 12, (uint16_t)target_utf16_len);
	st_u16le(out + 14, (uint16_t)target_utf16_len);
	st_u32le(out + 16, (uint32_t)payload_off);
	st_u32le(out + 20, flags);
	memcpy(out + 24, challenge, 8);   /* ServerChallenge */
	/* Reserved 8 bytes at offset 32 are zero. */
	/* TargetInfoFields */
	st_u16le(out + 40, (uint16_t)av_len);
	st_u16le(out + 42, (uint16_t)av_len);
	st_u32le(out + 44, (uint32_t)(payload_off + target_utf16_len));
	/* Version (8 bytes at offset 48) -- zero. */

	memcpy(out + payload_off, target_utf16, target_utf16_len);
	memcpy(out + payload_off + target_utf16_len, av_block, av_len);
	return (ssize_t)total;
}

int
ntlm_parse_authenticate(const uint8_t *buf, size_t len,
		struct ntlm_authenticate *out)
{
	struct ntlm_field lm, nt, domain, user, ws, enc;
	memset(out, 0, sizeof *out);
	if (len < 64) return -1;
	if (memcmp(buf, NTLM_SIG, NTLM_SIG_LEN) != 0) return -1;
	if (ld_u32le(buf + 8) != NTLM_MSG_AUTHENTICATE) return -1;
	if (parse_field(buf, len, 12, &lm) != 0) return -1;
	if (parse_field(buf, len, 20, &nt) != 0) return -1;
	if (parse_field(buf, len, 28, &domain) != 0) return -1;
	if (parse_field(buf, len, 36, &user) != 0) return -1;
	if (parse_field(buf, len, 44, &ws) != 0) return -1;
	if (parse_field(buf, len, 52, &enc) != 0) return -1;
	out->flags = ld_u32le(buf + 60);

	out->lm_response = lm.data;       out->lm_response_len = lm.len;
	out->nt_response = nt.data;       out->nt_response_len = nt.len;
	out->domain_utf16 = domain.data;  out->domain_utf16_len = domain.len;
	out->user_utf16   = user.data;    out->user_utf16_len   = user.len;
	out->workstation_utf16 = ws.data; out->workstation_utf16_len = ws.len;
	out->enc_random_skey = enc.data;  out->enc_random_skey_len = enc.len;

	/* Optional 16-byte MIC at offset 72 if flags advertise it.  We
	 * don't validate it in v1. */
	if (len >= 72 + 16) out->mic = buf + 72;
	return 0;
}

static void
to_utf16_upper(const char *s, uint8_t *out, size_t *out_len)
{
	uint8_t tmp[256];
	size_t i, n = strlen(s);
	for (i = 0; i < n && i < sizeof tmp - 1; i++) {
		unsigned char c = (unsigned char)s[i];
		tmp[i] = (uint8_t)toupper(c);
	}
	tmp[i] = '\0';
	*out_len = rdp_utf8_to_utf16le(out, 512, (const char *)tmp, i);
	if (*out_len == (size_t)-1) *out_len = 0;
}

static void
to_utf16_plain(const char *s, uint8_t *out, size_t *out_len)
{
	*out_len = rdp_utf8_to_utf16le(out, 512, s, strlen(s));
	if (*out_len == (size_t)-1) *out_len = 0;
}

int
ntlm_verify_ntlmv2(const uint8_t server_challenge[8],
		const struct ntlm_authenticate *auth,
		const char *user_utf8, const char *domain_utf8,
		const char *password_utf8,
		uint8_t session_base_key[16])
{
	uint8_t pw_utf16[1024];
	uint8_t nt_hash[16];
	uint8_t ntlmv2_hash[16];
	uint8_t user_up[512], dom_le[512];
	size_t  pw_len, user_len, dom_len;
	const uint8_t *temp;
	size_t temp_len;
	uint8_t nt_proof[16];

	if (auth->nt_response_len < 16 + 8) return -1;
	temp = auth->nt_response + 16;
	temp_len = auth->nt_response_len - 16;

	pw_len = rdp_utf8_to_utf16le(pw_utf16, sizeof pw_utf16,
		password_utf8, strlen(password_utf8));
	if (pw_len == (size_t)-1) return -1;
	if (rdp_md4(pw_utf16, pw_len, nt_hash) != 0) return -1;

	to_utf16_upper(user_utf8, user_up, &user_len);
	to_utf16_plain(domain_utf8 ? domain_utf8 : "", dom_le, &dom_len);
	if (rdp_hmac_md5_2(nt_hash, 16, user_up, user_len,
		dom_le, dom_len, ntlmv2_hash) != 0) return -1;

	if (rdp_hmac_md5_2(ntlmv2_hash, 16,
		server_challenge, 8, temp, temp_len, nt_proof) != 0)
		return -1;

	if (memcmp(nt_proof, auth->nt_response, 16) != 0)
		return -1;

	if (rdp_hmac_md5(ntlmv2_hash, 16, nt_proof, 16,
		session_base_key) != 0)
		return -1;
	return 0;
}

int
ntlm_verify_ntlmv2_hash(const uint8_t server_challenge[8],
		const struct ntlm_authenticate *auth,
		const uint8_t nt_hash[16],
		uint8_t session_base_key[16])
{
	uint8_t ntlmv2_hash[16];
	uint8_t user_up[512], dom_le[512];
	size_t  user_len, dom_len;
	const uint8_t *temp;
	size_t temp_len;
	uint8_t nt_proof[16];
	char user_utf8[256], domain_utf8[256];
	size_t got;

	if (auth->nt_response_len < 16 + 8) return -1;
	temp = auth->nt_response + 16;
	temp_len = auth->nt_response_len - 16;

	got = rdp_utf16le_to_utf8(user_utf8, sizeof user_utf8 - 1,
		auth->user_utf16, auth->user_utf16_len);
	if (got == (size_t)-1) got = 0;
	user_utf8[got] = '\0';
	got = rdp_utf16le_to_utf8(domain_utf8, sizeof domain_utf8 - 1,
		auth->domain_utf16, auth->domain_utf16_len);
	if (got == (size_t)-1) got = 0;
	domain_utf8[got] = '\0';

	to_utf16_upper(user_utf8, user_up, &user_len);
	to_utf16_plain(domain_utf8, dom_le, &dom_len);
	if (rdp_hmac_md5_2(nt_hash, 16, user_up, user_len,
		dom_le, dom_len, ntlmv2_hash) != 0) return -1;

	if (rdp_hmac_md5_2(ntlmv2_hash, 16,
		server_challenge, 8, temp, temp_len, nt_proof) != 0)
		return -1;

	if (memcmp(nt_proof, auth->nt_response, 16) != 0)
		return -1;

	if (rdp_hmac_md5(ntlmv2_hash, 16, nt_proof, 16,
		session_base_key) != 0)
		return -1;
	return 0;
}

int
ntlm_derive_exported_key(const struct ntlm_authenticate *auth,
		const uint8_t session_base_key[16],
		uint8_t exported_session_key[16])
{
	if (auth->flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		struct rdp_rc4 *rc4;
		if (auth->enc_random_skey_len != 16) return -1;
		rc4 = rdp_rc4_new(session_base_key, 16);
		if (rc4 == NULL) return -1;
		rdp_rc4_process(rc4, auth->enc_random_skey,
			exported_session_key, 16);
		rdp_rc4_free(rc4);
	} else {
		memcpy(exported_session_key, session_base_key, 16);
	}
	return 0;
}

void
ntlm_seal_key(int from_client_to_server,
		const uint8_t exported_session_key[16],
		uint8_t out_key[16])
{
	static const char client_to_server[] =
		"session key to client-to-server sealing key magic constant";
	static const char server_to_client[] =
		"session key to server-to-client sealing key magic constant";
	const char *magic = from_client_to_server
		? client_to_server : server_to_client;
	uint8_t buf[16 + 64];
	memcpy(buf, exported_session_key, 16);
	memcpy(buf + 16, magic, strlen(magic) + 1);
	{
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		unsigned int outlen = 16;
		EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
		EVP_DigestUpdate(ctx, buf, 16 + strlen(magic) + 1);
		EVP_DigestFinal_ex(ctx, out_key, &outlen);
		EVP_MD_CTX_free(ctx);
	}
}
