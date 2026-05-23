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
 * x224_test.c -- unit tests for src/wire/x224.c.
 *
 * Covers: CR with no negotiate PDU, CR with cookie + NEG_REQ, CR
 * with CORRELATION_INFO_PRESENT, CC build (success and failure),
 * malformed inputs.
 */

#include "../../src/wire/x224.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static void
test_cr_minimal(void)
{
	/* LI=6, CR code, dst-ref, src-ref, class. */
	uint8_t cr[] = { 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct rdp_x224_cr out;

	if (rdp_x224_parse_cr(&out, cr, sizeof cr) != 0)
		FAIL("minimal CR");
	if (out.have_neg_req) FAIL("neg_req should be absent");
}

static void
test_cr_with_neg_req(void)
{
	uint8_t cr[] = {
		0x0e, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* RDP_NEG_REQ: type=1, flags=0, len=8, proto=PROTOCOL_SSL */
		0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
	};
	struct rdp_x224_cr out;

	if (rdp_x224_parse_cr(&out, cr, sizeof cr) != 0)
		FAIL("CR with NEG_REQ");
	if (!out.have_neg_req) FAIL("missed NEG_REQ");
	if (out.requested_protocols != RDP_PROTO_SSL)
		FAIL("requested = 0x%x", out.requested_protocols);
}

static void
test_cr_with_cookie(void)
{
	const char *cookie = "Cookie: mstshash=ALICE\r\n";
	uint8_t cr[256];
	struct rdp_x224_cr out;
	size_t off = 7;
	size_t cookie_len = strlen(cookie);

	/* Fixed X.224 header (LI placeholder, code, dst-ref, src-ref, class). */
	memset(cr, 0, 7);
	cr[1] = 0xE0;
	memcpy(cr + off, cookie, cookie_len);
	off += cookie_len;
	/* RDP_NEG_REQ */
	cr[off + 0] = 0x01; cr[off + 1] = 0x00;
	cr[off + 2] = 0x08; cr[off + 3] = 0x00;
	cr[off + 4] = 0x01; cr[off + 5] = 0x00;
	cr[off + 6] = 0x00; cr[off + 7] = 0x00;
	off += 8;
	cr[0] = (uint8_t)(off - 1);

	if (rdp_x224_parse_cr(&out, cr, off) != 0)
		FAIL("CR with cookie");
	if (!out.have_neg_req) FAIL("missed neg_req after cookie");
	if (out.cookie == NULL) FAIL("cookie not captured");
	if (out.cookie_len != cookie_len)
		FAIL("cookie_len = %zu, want %zu", out.cookie_len, cookie_len);
}

static void
test_cr_correlation_info(void)
{
	uint8_t cr[7 + 8 + 36];
	struct rdp_x224_cr out;

	memset(cr, 0, sizeof cr);
	cr[1] = 0xE0;                     /* CR */
	cr[0] = (uint8_t)(sizeof cr - 1); /* LI */
	cr[7] = 0x01;                     /* type = NEG_REQ */
	cr[8] = RDP_NEG_CORRELATION_INFO_PRESENT;
	cr[9] = 0x08;
	cr[10] = 0x00;
	cr[11] = 0x01;                    /* PROTOCOL_SSL */
	/* 36 bytes follow at offset 15, value irrelevant. */

	if (rdp_x224_parse_cr(&out, cr, sizeof cr) != 0)
		FAIL("CR with correlation info");
	if (out.requested_protocols != RDP_PROTO_SSL)
		FAIL("after correlation info, proto = 0x%x",
			out.requested_protocols);
}

static void
test_cr_malformed(void)
{
	struct rdp_x224_cr out;

	/* Too short. */
	uint8_t empty = 0;
	if (rdp_x224_parse_cr(&out, &empty, 0) == 0) FAIL("zero len");
	/* Wrong code (DT instead of CR). */
	uint8_t a[] = { 6, 0xF0, 0, 0, 0, 0, 0 };
	if (rdp_x224_parse_cr(&out, a, sizeof a) == 0) FAIL("wrong code");
	/* LI past buffer end. */
	uint8_t b[] = { 0xff, 0xE0, 0, 0, 0, 0, 0 };
	if (rdp_x224_parse_cr(&out, b, sizeof b) == 0) FAIL("li overrun");
	/* NEG_REQ length not 8. */
	uint8_t c[] = { 14, 0xE0, 0, 0, 0, 0, 0,
		0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00 };
	if (rdp_x224_parse_cr(&out, c, sizeof c) == 0) FAIL("bad neg_len");
}

static void
test_cc_success(void)
{
	uint8_t cc[32];
	ssize_t n;

	n = rdp_x224_build_cc(cc, sizeof cc, 0, RDP_PROTO_SSL, 0);
	if (n != 15)
		FAIL("cc success len = %lld", (long long)n);
	/* LI=14, code=0xD0, dst,src=0,0, class=0, neg_rsp=02 00 0800 01000000 */
	if (cc[0] != 14 || cc[1] != 0xD0 || cc[7] != 0x02 ||
	    cc[8] != 0 || cc[9] != 8 || cc[10] != 0 ||
	    cc[11] != 1 || cc[12] != 0 || cc[13] != 0 || cc[14] != 0)
		FAIL("cc wire bytes: %02x..", cc[0]);
}

static void
test_cc_failure(void)
{
	uint8_t cc[32];
	ssize_t n;

	n = rdp_x224_build_cc(cc, sizeof cc, 1, 0,
		RDP_NEG_FAIL_SSL_REQUIRED_BY_SERVER);
	if (n != 15) FAIL("cc fail len = %lld", (long long)n);
	if (cc[7] != RDP_NEG_TYPE_FAILURE) FAIL("not failure type");
	if (cc[11] != RDP_NEG_FAIL_SSL_REQUIRED_BY_SERVER)
		FAIL("wrong fail code");
}

static void
test_dt(void)
{
	uint8_t dt[8];
	ssize_t n;

	n = rdp_x224_build_dt(dt, sizeof dt);
	if (n != 3) FAIL("dt build len = %lld", (long long)n);
	if (dt[0] != 0x02 || dt[1] != 0xF0 || dt[2] != 0x80)
		FAIL("dt bytes %02x %02x %02x", dt[0], dt[1], dt[2]);
	if (rdp_x224_parse_dt(dt, 3) != 3) FAIL("dt parse");
	dt[1] = 0xE0;
	if (rdp_x224_parse_dt(dt, 3) == 3) FAIL("wrong dt code accepted");
}

int
main(void)
{
	test_cr_minimal();
	test_cr_with_neg_req();
	test_cr_with_cookie();
	test_cr_correlation_info();
	test_cr_malformed();
	test_cc_success();
	test_cc_failure();
	test_dt();
	return 0;
}
