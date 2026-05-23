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
 * tpkt_test.c -- unit tests for src/wire/tpkt.c.
 */

#include "../../src/wire/tpkt.h"
#include "../../src/common/io.h"

#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static void
test_encode_decode(void)
{
	uint8_t h[4];
	struct rdp_tpkt t;

	if (rdp_tpkt_encode_hdr(h, 11) != 0) FAIL("encode 11");
	if (h[0] != 3 || h[1] != 0 || h[2] != 0 || h[3] != 11)
		FAIL("bytes %02x %02x %02x %02x", h[0], h[1], h[2], h[3]);
	if (rdp_tpkt_parse_hdr(&t, h) != 0) FAIL("parse roundtrip");
	if (t.length != 11) FAIL("length %u", t.length);

	if (rdp_tpkt_encode_hdr(h, 6) == 0) FAIL("encode below min accepted");
	h[0] = 4;
	if (rdp_tpkt_parse_hdr(&t, h) == 0) FAIL("bad version accepted");
	h[0] = 3; h[1] = 1;
	if (rdp_tpkt_parse_hdr(&t, h) == 0) FAIL("reserved nonzero accepted");
	h[1] = 0; h[2] = 0; h[3] = 6;
	if (rdp_tpkt_parse_hdr(&t, h) == 0) FAIL("length 6 accepted");
}

static void
test_read_frame(void)
{
	int sv[2];
	uint8_t frame[] = { 3, 0, 0, 11, 0xE0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t buf[32];
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		FAIL("socketpair: %s", strerror(errno));
	if (rdp_write_full(sv[0], frame, sizeof frame) != (ssize_t)sizeof frame)
		FAIL("write");
	(void)close(sv[0]);
	n = rdp_tpkt_read(sv[1], buf, sizeof buf);
	if (n != (ssize_t)sizeof frame)
		FAIL("read returned %lld, want %zu", (long long)n, sizeof frame);
	if (memcmp(buf, frame, sizeof frame) != 0)
		FAIL("frame bytes wrong");
	(void)close(sv[1]);
}

static void
test_read_eof(void)
{
	int sv[2];
	uint8_t buf[8];
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		FAIL("socketpair: %s", strerror(errno));
	(void)close(sv[0]);
	n = rdp_tpkt_read(sv[1], buf, sizeof buf);
	if (n != 0) FAIL("eof returned %lld", (long long)n);
	(void)close(sv[1]);
}

int
main(void)
{
	test_encode_decode();
	test_read_frame();
	test_read_eof();
	return 0;
}
