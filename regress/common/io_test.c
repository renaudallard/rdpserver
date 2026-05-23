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
 * io_test.c -- unit tests for src/common/io.c.
 *
 * Tests read_full / write_full over a socketpair, including
 * partial-write recovery, EOF semantics, and the cloexec/nonblock
 * helpers.
 */

#include "../../src/common/io.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FAIL(...) do {                          \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                \
	exit(1);                                  \
} while (0)

static void
test_full_roundtrip(void)
{
	int sv[2];
	uint8_t want[256], got[256];
	size_t i;

	for (i = 0; i < sizeof want; i++)
		want[i] = (uint8_t)i;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		FAIL("socketpair: %s", strerror(errno));
	if (rdp_write_full(sv[0], want, sizeof want) != (ssize_t)sizeof want)
		FAIL("write_full short: %s", strerror(errno));
	if (rdp_read_full(sv[1], got, sizeof got) != (ssize_t)sizeof got)
		FAIL("read_full short: %s", strerror(errno));
	if (memcmp(want, got, sizeof want) != 0)
		FAIL("roundtrip data mismatch");
	(void)close(sv[0]);
	(void)close(sv[1]);
}

static void
test_eof(void)
{
	int sv[2];
	uint8_t buf[8];
	ssize_t r;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		FAIL("socketpair: %s", strerror(errno));
	(void)close(sv[0]);
	r = rdp_read_full(sv[1], buf, sizeof buf);
	if (r != 0) FAIL("eof returned %lld, want 0", (long long)r);
	(void)close(sv[1]);
}

static void
test_flags(void)
{
	int p[2];
	int f;

	if (pipe(p) < 0)
		FAIL("pipe: %s", strerror(errno));
	if (rdp_set_cloexec(p[0]) != 0)
		FAIL("set_cloexec: %s", strerror(errno));
	f = fcntl(p[0], F_GETFD);
	if (f < 0 || (f & FD_CLOEXEC) == 0)
		FAIL("cloexec not set: %d", f);
	if (rdp_set_nonblock(p[0]) != 0)
		FAIL("set_nonblock: %s", strerror(errno));
	f = fcntl(p[0], F_GETFL);
	if (f < 0 || (f & O_NONBLOCK) == 0)
		FAIL("nonblock not set: %d", f);
	(void)close(p[0]);
	(void)close(p[1]);
}

int
main(void)
{
	test_full_roundtrip();
	test_eof();
	test_flags();
	return 0;
}
