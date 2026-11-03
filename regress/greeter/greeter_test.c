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
 * greeter_test.c -- greeter repaint stays inside the framebuffer.
 *
 * The login panel has a fixed size, so on a desktop narrower than the panel
 * its rects start left of the framebuffer. Drive a narrow desktop through
 * Enter, Enter (submit) and check every bitmap tile the greeter emits lies
 * inside the desktop; an unclipped dirty rect would emit a tile at a
 * wrapped negative x and read pixels from before the framebuffer.
 */

#include "../../src/greeter/greeter.h"
#include "../../src/sec/tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

struct rdp_tls { int unused; };

/* One fast-path PDU carrying two scancode presses of Enter (0x1c). */
static const uint8_t input[] = { 0x08, 0x06, 0x00, 0x1c, 0x00, 0x1c };
static size_t ipos;
static unsigned cur_w;
static unsigned tiles;

ssize_t
rdp_tls_read(struct rdp_tls *t, void *buf, size_t n)
{
	(void)t;
	if (ipos >= sizeof input)
		return 0;
	if (n > sizeof input - ipos)
		n = sizeof input - ipos;
	memcpy(buf, input + ipos, n);
	ipos += n;
	return (ssize_t)n;
}

ssize_t
rdp_tls_read_full(struct rdp_tls *t, void *buf, size_t n)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = rdp_tls_read(t, (uint8_t *)buf + got, n - got);
		if (r <= 0)
			break;
		got += (size_t)r;
	}
	return (ssize_t)got;
}

/* Each write is one fast-path bitmap update: action, 1 or 2 length bytes,
 * updateHeader + size (3), updateType + numberRectangles (4), destLeft. */
ssize_t
rdp_tls_write_full(struct rdp_tls *t, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	size_t hdr_n, off;
	unsigned x;

	(void)t;
	if (n < 2)
		FAIL("short write");
	hdr_n = (p[1] & 0x80) ? 3 : 2;
	off = hdr_n + 3 + 4;
	if (n < off + 2)
		FAIL("short bitmap update");
	x = (unsigned)p[off] | ((unsigned)p[off + 1] << 8);
	if (x >= cur_w)
		FAIL("tile at x=%u outside a %u wide desktop", x, cur_w);
	tiles++;
	return (ssize_t)n;
}

int
rdp_tls_send(struct rdp_tls *t, const void *buf, size_t n)
{
	return rdp_tls_write_full(t, buf, n) == (ssize_t)n ? 0 : -1;
}

static void
run(unsigned w, unsigned h)
{
	struct rdp_tls t;
	struct rdp_greeter_result gr;

	ipos = 0;
	tiles = 0;
	cur_w = w;
	memset(&gr, 0, sizeof gr);
	(void)rdp_greeter_run(&t, (uint16_t)w, (uint16_t)h, 0x409,
	    NULL, NULL, &gr);
	if (tiles == 0)
		FAIL("%ux%u: nothing painted", w, h);
}

int
main(void)
{
	run(1024, 768);
	run(300, 600);
	run(64, 64);
	run(1, 1);
	(void)printf("greeter_test: all ok\n");
	return 0;
}
