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
 * ber_test.c -- unit tests for src/common/ber.c.
 */

#include "../../src/common/ber.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static void
test_length(void)
{
	uint8_t s[8];
	struct rdp_buf b;
	size_t v;
	ssize_t r;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_length(&b, 0x7f) != 0) FAIL("len 0x7f");
	if (s[0] != 0x7f) FAIL("len 0x7f byte = %02x", s[0]);
	r = rdp_ber_read_length(s, 1, &v);
	if (r != 1 || v != 0x7f) FAIL("read 0x7f = %zu", v);

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_length(&b, 0x80) != 0) FAIL("len 0x80");
	if (s[0] != 0x81 || s[1] != 0x80) FAIL("len 0x80 wrong");
	r = rdp_ber_read_length(s, 2, &v);
	if (r != 2 || v != 0x80) FAIL("read 0x80 = %zu", v);

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_length(&b, 0x1234) != 0) FAIL("len 0x1234");
	if (s[0] != 0x82 || s[1] != 0x12 || s[2] != 0x34) FAIL("len 0x1234");
	r = rdp_ber_read_length(s, 3, &v);
	if (r != 3 || v != 0x1234) FAIL("read 0x1234 = %zu", v);
}

static void
test_integer(void)
{
	uint8_t s[16];
	struct rdp_buf b;
	uint32_t v;
	ssize_t r;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_integer(&b, 0) != 0) FAIL("int 0");
	if (s[0] != 0x02 || s[1] != 0x01 || s[2] != 0x00) FAIL("int 0 bytes");
	r = rdp_ber_read_integer(s, 3, &v);
	if (r != 3 || v != 0) FAIL("read int 0 = %u", v);

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_integer(&b, 0x12345) != 0) FAIL("int 0x12345");
	r = rdp_ber_read_integer(s, rdp_buf_used(&b), &v);
	if (r < 0 || v != 0x12345) FAIL("read int 0x12345 = %u", v);

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_integer(&b, 0xffffffffu) != 0) FAIL("int max");
	r = rdp_ber_read_integer(s, rdp_buf_used(&b), &v);
	if (r < 0 || v != 0xffffffffu) FAIL("read int max = %u", v);
}

static void
test_app_tag(void)
{
	uint8_t s[16];
	struct rdp_buf b;
	size_t vlen;
	ssize_t r;

	/* Application 101 (MCS ConnectInitial) -- needs multi-byte tag.
	 * The value body (5 bytes) must fit within the buffer. */
	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_app_tag(&b, RDP_BER_CONSTRUCTED, 101) != 0)
		FAIL("write app tag 101");
	if (rdp_ber_write_length(&b, 5) != 0) FAIL("write length");
	memset(s + rdp_buf_used(&b), 0, 5);
	if (s[0] != 0x7f || s[1] != 0x65 || s[2] != 0x05)
		FAIL("app tag bytes %02x %02x %02x", s[0], s[1], s[2]);

	r = rdp_ber_read_app_tag(s, rdp_buf_used(&b) + 5,
		RDP_BER_CONSTRUCTED, 101, &vlen);
	if (r != 3 || vlen != 5) FAIL("read app 101: r=%ld vlen=%zu",
		(long)r, vlen);
}

static void
test_octet_string(void)
{
	uint8_t s[32];
	struct rdp_buf b;
	const uint8_t *d;
	size_t dl;
	ssize_t r;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_ber_write_octet_string(&b, "abc", 3) != 0) FAIL("write os");
	r = rdp_ber_read_octet_string(s, rdp_buf_used(&b), &d, &dl);
	if (r < 0 || dl != 3 || memcmp(d, "abc", 3) != 0) FAIL("read os");
}

int
main(void)
{
	test_length();
	test_integer();
	test_app_tag();
	test_octet_string();
	return 0;
}
