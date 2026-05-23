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
 * utf16_test.c -- unit tests for src/common/utf16.c.
 */

#include "../../src/common/utf16.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                          \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                \
	exit(1);                                  \
} while (0)

static void
test_ascii_roundtrip(void)
{
	const char *s = "hello";
	uint8_t u[16];
	char back[16];
	size_t n;

	n = rdp_utf8_to_utf16le(u, sizeof u, s, 5);
	if (n != 10) FAIL("ascii encode len = %zu, want 10", n);
	if (u[0] != 'h' || u[1] != 0 || u[8] != 'o' || u[9] != 0)
		FAIL("ascii wire bytes wrong");
	n = rdp_utf16le_to_utf8(back, sizeof back, u, 10);
	if (n != 5) FAIL("ascii decode len = %zu, want 5", n);
	back[5] = '\0';
	if (strcmp(back, "hello") != 0)
		FAIL("ascii decoded got %s", back);
}

static void
test_bmp(void)
{
	/* U+00E9 (é) is two UTF-8 bytes (c3 a9), two UTF-16LE bytes
	 * (e9 00).  U+00DC (Ü) is c3 9c / dc 00.  Together: "éÜ". */
	const char *s = "\xc3\xa9\xc3\x9c";
	uint8_t u[8];
	char back[8];
	size_t n;

	n = rdp_utf8_to_utf16le(u, sizeof u, s, 4);
	if (n != 4) FAIL("bmp encode len = %zu", n);
	if (u[0] != 0xe9 || u[1] != 0x00 || u[2] != 0xdc || u[3] != 0x00)
		FAIL("bmp wire wrong %02x %02x %02x %02x",
			u[0], u[1], u[2], u[3]);
	n = rdp_utf16le_to_utf8(back, sizeof back, u, 4);
	if (n != 4) FAIL("bmp decode len = %zu", n);
	back[4] = '\0';
	if (memcmp(back, s, 4) != 0)
		FAIL("bmp decoded mismatch");
}

static void
test_surrogate_pair(void)
{
	/* U+1F600 (grinning face) -- 4 bytes UTF-8 (f0 9f 98 80),
	 * 4 bytes UTF-16LE (3d d8 00 de). */
	const char *s = "\xf0\x9f\x98\x80";
	uint8_t u[8];
	char back[8];
	size_t n;

	n = rdp_utf8_to_utf16le(u, sizeof u, s, 4);
	if (n != 4) FAIL("smp encode len = %zu", n);
	if (u[0] != 0x3d || u[1] != 0xd8 || u[2] != 0x00 || u[3] != 0xde)
		FAIL("smp wire wrong %02x %02x %02x %02x",
			u[0], u[1], u[2], u[3]);
	n = rdp_utf16le_to_utf8(back, sizeof back, u, 4);
	if (n != 4) FAIL("smp decode len = %zu", n);
	back[4] = '\0';
	if (memcmp(back, s, 4) != 0)
		FAIL("smp decoded mismatch");
}

static void
test_invalid(void)
{
	uint8_t u[4];
	char back[4];
	size_t n;

	/* Lone continuation byte. */
	n = rdp_utf8_to_utf16le(u, sizeof u, "\x80", 1);
	if (n != (size_t)-1) FAIL("lone cont accepted");
	/* Overlong encoding of '/' (0x2f). */
	n = rdp_utf8_to_utf16le(u, sizeof u, "\xc0\xaf", 2);
	if (n != (size_t)-1) FAIL("overlong accepted");
	/* Unpaired high surrogate on the way back. */
	u[0] = 0x00; u[1] = 0xd8; u[2] = 0x00; u[3] = 0x00;
	n = rdp_utf16le_to_utf8(back, sizeof back, u, 4);
	if (n != (size_t)-1) FAIL("unpaired high surrogate accepted");
	/* Odd byte count on the way back. */
	n = rdp_utf16le_to_utf8(back, sizeof back, u, 3);
	if (n != (size_t)-1) FAIL("odd utf16 byte count accepted");
}

int
main(void)
{
	test_ascii_roundtrip();
	test_bmp();
	test_surrogate_pair();
	test_invalid();
	return 0;
}
