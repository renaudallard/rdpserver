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
 * per_test.c -- unit tests for src/common/per.c.
 */

#include "../../src/common/per.h"

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
	if (rdp_per_write_length(&b, 5) != 0) FAIL("len 5");
	if (s[0] != 5) FAIL("len 5 byte = %02x", s[0]);
	r = rdp_per_read_length(s, 1, &v);
	if (r != 1 || v != 5) FAIL("read 5");

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_per_write_length(&b, 0x123) != 0) FAIL("len 0x123");
	if (s[0] != 0x81 || s[1] != 0x23) FAIL("len 0x123 bytes %02x %02x",
		s[0], s[1]);
	r = rdp_per_read_length(s, 2, &v);
	if (r != 2 || v != 0x123) FAIL("read 0x123 = %zu", v);

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_per_write_length(&b, 0x4000) == 0) FAIL("len too large accepted");
}

static void
test_oid(void)
{
	uint8_t s[16];
	struct rdp_buf b;
	ssize_t r;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_per_write_object_identifier_gcc(&b) != 0) FAIL("write oid");
	r = rdp_per_read_object_identifier_gcc(s, rdp_buf_used(&b));
	if (r < 0) FAIL("read oid");
	/* Reject a wrong OID. */
	s[2] = 0xff;
	r = rdp_per_read_object_identifier_gcc(s, rdp_buf_used(&b));
	if (r >= 0) FAIL("bogus oid accepted");
}

static void
test_u16_u32(void)
{
	uint8_t s[8];
	struct rdp_buf b;
	uint16_t v16;
	uint32_t v32;
	ssize_t r;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_per_write_u16(&b, 0xbeef) != 0) FAIL("write u16");
	if (s[0] != 0xbe || s[1] != 0xef) FAIL("u16 bytes");
	r = rdp_per_read_u16(s, 2, &v16);
	if (r != 2 || v16 != 0xbeef) FAIL("read u16");

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_per_write_u32(&b, 0xdeadbeefu) != 0) FAIL("write u32");
	r = rdp_per_read_u32(s, 4, &v32);
	if (r != 4 || v32 != 0xdeadbeefu) FAIL("read u32");
}

static void
test_h221_key(void)
{
	uint8_t s[8];
	struct rdp_buf b;
	char key[4];

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_per_write_h221_key(&b, "Duca") != 0) FAIL("write key");
	if (rdp_per_read_h221_key(s, 4, key) != 4) FAIL("read key");
	if (memcmp(key, "Duca", 4) != 0) FAIL("key mismatch");
}

int
main(void)
{
	test_length();
	test_oid();
	test_u16_u32();
	test_h221_key();
	return 0;
}
