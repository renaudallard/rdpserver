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
 * mic_test.c -- unit tests for the session microphone module.
 *
 * Covers the one dependency free piece the live PulseAudio path relies on
 * being correct: parsing the integer module index pactl prints on stdout
 * after a successful "load-module".  A wrong parse here would leak a loaded
 * module (we could never unload it), so the bounds and rejection rules are
 * exercised directly.
 */

#include "../../src/session/mic.h"

#include <stdio.h>
#include <string.h>

static int fails;

#define CHECK(cond, msg) do {						\
	if (!(cond)) {							\
		fprintf(stderr, "FAIL: %s (%s:%d)\n", msg,		\
		    __FILE__, __LINE__);				\
		fails++;						\
	}								\
} while (0)

/* Parse a NUL terminated literal (pactl always writes printable text). */
static long
parse(const char *s)
{
	return rdp_mic_parse_index(s, strlen(s));
}

static void
test_parse_index(void)
{
	/* A plain index with the trailing newline pactl writes. */
	CHECK(parse("7\n") == 7, "simple index with newline");

	/* No newline (some pactl builds omit it). */
	CHECK(parse("7") == 7, "simple index without newline");

	/* Zero is a valid module index. */
	CHECK(parse("0\n") == 0, "zero index");

	/* A multi-digit index. */
	CHECK(parse("123456\n") == 123456, "multi digit index");

	/* Leading and trailing whitespace around the number is tolerated. */
	CHECK(parse("  42  \n") == 42, "surrounding whitespace");
	CHECK(parse("\t9\r\n") == 9, "tabs and crlf");

	/* An empty or whitespace only line has no index. */
	CHECK(parse("") == -1, "empty line rejected");
	CHECK(parse("\n") == -1, "newline only rejected");
	CHECK(parse("   ") == -1, "spaces only rejected");

	/* An error message (pactl prints these on failure) is not an index. */
	CHECK(parse("Failure: Module initialization failed\n") == -1,
	    "error text rejected");

	/* Trailing junk after the number is rejected, so we never unload the
	 * wrong module from a partially numeric line. */
	CHECK(parse("12abc\n") == -1, "trailing junk rejected");
	CHECK(parse("12 34\n") == -1, "two numbers rejected");

	/* A leading sign is not accepted (indices are non-negative). */
	CHECK(parse("-1\n") == -1, "negative rejected");
	CHECK(parse("+3\n") == -1, "leading plus rejected");

	/* An absurdly long digit run overflows and is rejected cleanly
	 * rather than wrapping to a bogus small index. */
	CHECK(parse("999999999999999999999999999999") == -1,
	    "overflow rejected");

	/* A NULL buffer is handled. */
	CHECK(rdp_mic_parse_index(NULL, 0) == -1, "null buffer");

	/* The length bound is honoured: only the first byte is in range, so
	 * the trailing 'x' is invisible and the lone digit parses. */
	CHECK(rdp_mic_parse_index("5x", 1) == 5, "length bound honoured");
}

int
main(void)
{
	test_parse_index();
	if (fails == 0)
		printf("mic_test: all ok\n");
	return fails == 0 ? 0 : 1;
}
