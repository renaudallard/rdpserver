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
 * ntlm_test.c -- NTLM unseal signature check, MIC presence and MIC check.
 */

#include "../../src/sec/ntlm.h"
#include "../../src/sec/nla_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

/* OpenSSL keeps the legacy provider and its fetched HMAC method for the
 * life of the process; they are its allocations, not leaks of ours.  The
 * suppressions match frames inside OpenSSL, so ask for full stacks. */
const char *__asan_default_options(void);
const char *__lsan_default_suppressions(void);
const char *
__asan_default_options(void)
{
	return "fast_unwind_on_malloc=0";
}
const char *
__lsan_default_suppressions(void)
{
	return "leak:OSSL_PROVIDER_try_load_ex\nleak:HMAC\n";
}

static ssize_t
unseal(const uint8_t key[16], const uint8_t sign[16], uint32_t seq,
		const uint8_t *in, size_t in_len, uint8_t *out, size_t cap)
{
	struct rdp_rc4 *rc4 = rdp_rc4_new(key, 16);
	ssize_t n;

	if (rc4 == NULL) FAIL("rc4");
	n = ntlm_unseal_message(rc4, sign, seq, in, in_len, out, cap);
	rdp_rc4_free(rc4);
	return n;
}

static void
test_unseal(void)
{
	uint8_t seal[16], sign[16], msg[48], sealed[64], out[64];
	ssize_t n;
	size_t i;

	for (i = 0; i < 16; i++) {
		seal[i] = (uint8_t)i;
		sign[i] = (uint8_t)(0x80 + i);
	}
	for (i = 0; i < sizeof msg; i++)
		msg[i] = (uint8_t)(i * 7);
	n = ntlm_seal_message(seal, sign, 1, msg, sizeof msg, sealed,
	    sizeof sealed);
	if (n != 16 + (ssize_t)sizeof msg) FAIL("seal len");
	if (unseal(seal, sign, 1, sealed, (size_t)n, out, sizeof out)
	    != (ssize_t)sizeof msg || memcmp(out, msg, sizeof msg) != 0)
		FAIL("unseal roundtrip");
	if (unseal(seal, sign, 0, sealed, (size_t)n, out, sizeof out) >= 0)
		FAIL("wrong sequence number accepted");
	sealed[20] ^= 1;
	if (unseal(seal, sign, 1, sealed, (size_t)n, out, sizeof out) >= 0)
		FAIL("tampered ciphertext accepted");
	sealed[20] ^= 1;
	sign[0] ^= 1;
	if (unseal(seal, sign, 1, sealed, (size_t)n, out, sizeof out) >= 0)
		FAIL("wrong signing key accepted");
	if (unseal(seal, sign, 1, sealed, 15, out, sizeof out) >= 0)
		FAIL("short message accepted");
}

/* NTProofStr(16) + client challenge header(28) + AV pairs. */
static size_t
nt_response(uint8_t *p, int with_flags, uint32_t flags)
{
	size_t off = 16 + 28;

	memset(p, 0, off);
	p[off++] = 7; p[off++] = 0; p[off++] = 8; p[off++] = 0;  /* timestamp */
	memset(p + off, 0x11, 8); off += 8;
	if (with_flags) {
		p[off++] = 6; p[off++] = 0; p[off++] = 4; p[off++] = 0;
		p[off++] = (uint8_t)flags; p[off++] = 0;
		p[off++] = 0; p[off++] = 0;
	}
	p[off++] = 0; p[off++] = 0; p[off++] = 0; p[off++] = 0;  /* EOL */
	return off;
}

static void
test_has_mic(void)
{
	uint8_t nt[128];
	struct ntlm_authenticate a;

	memset(&a, 0, sizeof a);
	a.nt_response = nt;
	a.nt_response_len = nt_response(nt, 1, 2);
	if (!ntlm_auth_has_mic(&a)) FAIL("MIC flag not seen");
	a.nt_response_len = nt_response(nt, 1, 0);
	if (ntlm_auth_has_mic(&a)) FAIL("MIC seen without flag");
	a.nt_response_len = nt_response(nt, 0, 0);
	if (ntlm_auth_has_mic(&a)) FAIL("MIC seen without MsvAvFlags");
	/* An AV pair claiming more bytes than remain stops the walk. */
	a.nt_response_len = nt_response(nt, 1, 2);
	nt[16 + 28 + 2] = 0xff;
	if (ntlm_auth_has_mic(&a)) FAIL("overlong AV pair walked");
}

static void
test_mic(void)
{
	uint8_t key[16], neg[40], chal[56], auth[120], all[216], mic[16];
	size_t i;

	for (i = 0; i < sizeof key; i++) key[i] = (uint8_t)(i + 3);
	for (i = 0; i < sizeof neg; i++) neg[i] = (uint8_t)i;
	for (i = 0; i < sizeof chal; i++) chal[i] = (uint8_t)(0x40 + i);
	for (i = 0; i < sizeof auth; i++) auth[i] = (uint8_t)(0x90 + i);
	memset(auth + 72, 0, 16);
	memcpy(all, neg, sizeof neg);
	memcpy(all + sizeof neg, chal, sizeof chal);
	memcpy(all + sizeof neg + sizeof chal, auth, sizeof auth);
	if (rdp_hmac_md5(key, 16, all, sizeof all, mic) != 0) FAIL("hmac");
	memcpy(auth + 72, mic, 16);
	if (ntlm_verify_mic(key, neg, sizeof neg, chal, sizeof chal, auth,
	    sizeof auth) != 0)
		FAIL("good MIC rejected");
	chal[30] ^= 1;
	if (ntlm_verify_mic(key, neg, sizeof neg, chal, sizeof chal, auth,
	    sizeof auth) == 0)
		FAIL("MIC over a tampered CHALLENGE accepted");
	chal[30] ^= 1;
	auth[100] ^= 1;
	if (ntlm_verify_mic(key, neg, sizeof neg, chal, sizeof chal, auth,
	    sizeof auth) == 0)
		FAIL("MIC over a tampered AUTHENTICATE accepted");
	if (ntlm_verify_mic(key, neg, sizeof neg, chal, sizeof chal, auth,
	    80) == 0)
		FAIL("AUTHENTICATE too short for a MIC accepted");
}

int
main(void)
{
	test_unseal();
	test_has_mic();
	test_mic();
	(void)printf("ntlm_test: all ok\n");
	return 0;
}
