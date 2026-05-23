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
 * str_test.c -- unit tests for src/common/str.c.
 */

#include "../../src/common/str.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                          \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                \
	exit(1);                                  \
} while (0)

static void
test_consttime_eq(void)
{
	if (rdp_consttime_eq("abc", "abc", 3) != 0)
		FAIL("equal not detected");
	if (rdp_consttime_eq("abc", "abd", 3) == 0)
		FAIL("inequal not detected");
	if (rdp_consttime_eq("", "", 0) != 0)
		FAIL("zero-length not equal");
}

static void
test_hex(void)
{
	char out[16];
	size_t n;

	n = rdp_hex(out, sizeof out, "\x01\x02\xff", 3);
	if (n != 6)
		FAIL("hex needs = %zu, want 6", n);
	if (strcmp(out, "0102ff") != 0)
		FAIL("hex got %s, want 0102ff", out);

	/* Truncation: dsize too small. */
	n = rdp_hex(out, 3, "\xab\xcd", 2);
	if (n != 4)
		FAIL("hex truncate needs = %zu, want 4", n);
	if (strcmp(out, "ab") != 0)
		FAIL("hex truncated got %s, want ab", out);
}

int
main(void)
{
	test_consttime_eq();
	test_hex();
	return 0;
}
