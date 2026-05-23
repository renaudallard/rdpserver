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
 * buf_test.c -- unit tests for src/common/buf.c.
 *
 * Exit 0 on success, non-zero on first failure.  Each test prints
 * its own failure context to stderr so make(1)'s indented-output
 * mode is readable.
 */

#include "../../src/common/buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                          \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                \
	exit(1);                                  \
} while (0)

static void
test_put_get_u16le(void)
{
	uint8_t s[4];
	struct rdp_buf b;
	uint16_t v;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_buf_put_u16le(&b, 0x1234) != 0)
		FAIL("put_u16le 1");
	if (rdp_buf_put_u16le(&b, 0xabcd) != 0)
		FAIL("put_u16le 2");
	if (rdp_buf_put_u16le(&b, 0x0001) == 0)
		FAIL("overflow not detected");
	if (s[0] != 0x34 || s[1] != 0x12 || s[2] != 0xcd || s[3] != 0xab)
		FAIL("wire bytes wrong: %02x %02x %02x %02x",
			s[0], s[1], s[2], s[3]);

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_buf_get_u16le(&b, &v) != 0 || v != 0x1234)
		FAIL("get_u16le 1 = 0x%04x", v);
	if (rdp_buf_get_u16le(&b, &v) != 0 || v != 0xabcd)
		FAIL("get_u16le 2 = 0x%04x", v);
	if (rdp_buf_get_u16le(&b, &v) == 0)
		FAIL("underflow not detected");
}

static void
test_put_get_u32be(void)
{
	uint8_t s[4];
	struct rdp_buf b;
	uint32_t v;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_buf_put_u32be(&b, 0xdeadbeefu) != 0)
		FAIL("put_u32be");
	if (s[0] != 0xde || s[1] != 0xad || s[2] != 0xbe || s[3] != 0xef)
		FAIL("u32be wire bytes wrong");

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_buf_get_u32be(&b, &v) != 0 || v != 0xdeadbeefu)
		FAIL("get_u32be = 0x%08x", v);
}

static void
test_reserve(void)
{
	uint8_t s[8];
	struct rdp_buf b;
	void *p1, *p2;

	rdp_buf_init(&b, s, sizeof s);
	p1 = rdp_buf_reserve(&b, 5);
	if (p1 != s)
		FAIL("reserve 1 returned %p, want %p", p1, (void *)s);
	p2 = rdp_buf_reserve(&b, 3);
	if (p2 != s + 5)
		FAIL("reserve 2 returned %p, want %p", p2, (void *)(s + 5));
	if (rdp_buf_reserve(&b, 1) != NULL)
		FAIL("reserve overflow not detected");
	if (rdp_buf_used(&b) != 8)
		FAIL("used = %zu", rdp_buf_used(&b));
	if (rdp_buf_space(&b) != 0)
		FAIL("space = %zu", rdp_buf_space(&b));
}

static void
test_skip(void)
{
	uint8_t s[8] = "ABCDEFGH";
	struct rdp_buf b;
	uint8_t v;

	rdp_buf_init(&b, s, sizeof s);
	if (rdp_buf_skip(&b, 3) != 0) FAIL("skip 3");
	if (rdp_buf_get_u8(&b, &v) != 0 || v != 'D')
		FAIL("after skip, got %c", v);
	if (rdp_buf_skip(&b, 5) == 0) FAIL("skip past end not detected");
}

int
main(void)
{
	test_put_get_u16le();
	test_put_get_u32be();
	test_reserve();
	test_skip();
	return 0;
}
