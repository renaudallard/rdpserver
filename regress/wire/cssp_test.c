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
 * cssp_test.c -- MS-CSSP TSRequest / TSCredentials parse bounds.
 *
 * A context tag whose declared length runs past the received bytes must be
 * rejected, not handed on as a token length that later readers trust.
 */

#include "../../src/sec/cssp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

/* Copy into an exactly sized heap buffer so a sanitizer sees any over-read. */
static int
parse_exact(const uint8_t *m, size_t n, struct rdp_tsrequest *req)
{
	uint8_t *b = malloc(n);
	int rc;

	if (b == NULL) FAIL("malloc");
	memcpy(b, m, n);
	rc = rdp_cssp_parse(b, n, req);
	free(b);
	return rc;
}

static void
test_roundtrip(void)
{
	static const uint8_t tok[] = "NTLMSSP\0token";
	struct rdp_tsrequest in, out;
	uint8_t buf[256];
	ssize_t n;

	memset(&in, 0, sizeof in);
	in.version = 6;
	in.nego_token = tok;
	in.nego_token_len = sizeof tok;
	n = rdp_cssp_build(buf, sizeof buf, &in);
	if (n <= 0) FAIL("build");
	if (rdp_cssp_parse(buf, (size_t)n, &out) != 0) FAIL("parse built");
	if (out.version != 6 || out.nego_token_len != sizeof tok
	    || memcmp(out.nego_token, tok, sizeof tok) != 0)
		FAIL("roundtrip mismatch");
}

static void
test_lying_nego_length(void)
{
	/* negoTokens [1] and its nested SEQUENCEs claim about 1 MiB while
	 * the message carries a few bytes. */
	static const uint8_t m[] = {
		0x30, 0x20,
		0xa0, 0x03, 0x02, 0x01, 0x06,
		0xa1, 0x83, 0x10, 0x00, 0x40,
		0x30, 0x83, 0x10, 0x00, 0x30,
		0x30, 0x83, 0x10, 0x00, 0x20,
		0xa0, 0x83, 0x10, 0x00, 0x10,
		0x04, 0x83, 0x10, 0x00, 0x00,
		'N', 'T',
	};
	struct rdp_tsrequest req;

	if (parse_exact(m, sizeof m, &req) == 0)
		FAIL("lying negoTokens length accepted (token len %zu)",
		    req.nego_token_len);
}

static void
test_lying_field_lengths(void)
{
	/* pubKeyAuth [3] and an unknown [7] each claiming more than is left. */
	static const uint8_t pka[] = {
		0x30, 0x0a, 0xa3, 0x82, 0x01, 0x00, 0x04, 0x82, 0x00, 0xfc,
		0x00, 0x00,
	};
	static const uint8_t unk[] = {
		0x30, 0x06, 0xa7, 0x84, 0x7f, 0xff, 0xff, 0xff,
	};
	struct rdp_tsrequest req;

	if (parse_exact(pka, sizeof pka, &req) == 0)
		FAIL("lying pubKeyAuth length accepted");
	if (parse_exact(unk, sizeof unk, &req) == 0)
		FAIL("lying unknown element length accepted");
}

static void
test_tscredentials(void)
{
	/* TSCredentials whose credentials [1] claims 0x100 bytes of 6. */
	static const uint8_t m[] = {
		0x30, 0x0e,
		0xa0, 0x03, 0x02, 0x01, 0x01,
		0xa1, 0x82, 0x01, 0x00, 0x04, 0x82, 0x00, 0xfc, 0x30,
	};
	struct rdp_tscredentials tc;
	uint8_t *b = malloc(sizeof m);

	if (b == NULL) FAIL("malloc");
	memcpy(b, m, sizeof m);
	if (rdp_cssp_parse_tscredentials(b, sizeof m, &tc) == 0)
		FAIL("lying TSCredentials length accepted");
	free(b);
}

int
main(void)
{
	test_roundtrip();
	test_lying_nego_length();
	test_lying_field_lengths();
	test_tscredentials();
	(void)printf("cssp_test: all ok\n");
	return 0;
}
