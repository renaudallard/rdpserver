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
 * bitmap_planar_test.c -- round-trip of the RDP6 planar 32bpp codec.
 *
 * The encoder's planar stream (top-down R,G,B planes, scanline-delta + RLE) is
 * validated by decoding it and checking the pixels are identical across
 * patterns that exercise long runs, zero-delta rows, gradients (every run
 * escape length) and incompressible noise.
 */

#include "../../src/wire/bitmap_planar.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
roundtrip(const uint8_t *pix, uint32_t w, uint32_t h, const char *name)
{
	uint8_t comp[64 * 64 * 6 + 64];
	uint8_t decomp[64 * 64 * 3];
	size_t clen = 0;

	if (rdp_bitmap_planar_compress_24(comp, sizeof comp, &clen, pix, w, h) != 0)
		FAIL("%s %ux%u: compress failed", name, w, h);
	if (clen == 0 || clen > sizeof comp)
		FAIL("%s %ux%u: bad clen %zu", name, w, h, clen);
	if (rdp_bitmap_planar_decompress_24(decomp, sizeof decomp, comp, clen,
	    w, h) != 0)
		FAIL("%s %ux%u: decompress failed", name, w, h);
	if (memcmp(pix, decomp, (size_t)w * h * 3) != 0)
		FAIL("%s %ux%u: round-trip mismatch", name, w, h);
}

static void
fill_pix(uint8_t *p, uint32_t w, uint32_t h, int kind)
{
	uint32_t x, y;
	uint32_t lcg = 0x2468aceu;

	for (y = 0; y < h; y++) {
		for (x = 0; x < w; x++) {
			uint8_t *q = p + ((size_t)y * w + x) * 3;
			uint8_t r, g, b;
			switch (kind) {
			case 0:                  /* solid */
				r = 0x40; g = 0x80; b = 0xc0; break;
			case 1:                  /* all black */
				r = g = b = 0x00; break;
			case 2:                  /* all white */
				r = g = b = 0xff; break;
			case 3:                  /* horizontal gradient */
				r = (uint8_t)x; g = (uint8_t)(x * 2);
				b = (uint8_t)(x * 3); break;
			case 4:                  /* identical rows (zero deltas) */
				r = (uint8_t)((x / 7) * 9); g = (uint8_t)(x & 0xf0);
				b = (uint8_t)(x | 0x03); break;
			case 5:                  /* vertical gradient (delta runs) */
				r = (uint8_t)y; g = (uint8_t)(y + 1);
				b = (uint8_t)(255 - y); break;
			case 6:                  /* long horizontal runs */
				r = (uint8_t)(x < w / 2 ? 0x10 : 0xf0);
				g = (uint8_t)(x < w / 3 ? 0x20 : 0xa0);
				b = 0x55; break;
			default:                 /* pseudo-random (incompressible) */
				lcg = lcg * 1103515245u + 12345u;
				r = (uint8_t)(lcg >> 16);
				g = (uint8_t)(lcg >> 8);
				b = (uint8_t)lcg;
				break;
			}
			q[0] = b; q[1] = g; q[2] = r;
		}
	}
}

int
main(void)
{
	static uint8_t pix[64 * 64 * 3];
	const uint32_t dims[][2] = {
		{64, 64}, {32, 32}, {16, 16}, {1, 1}, {1, 64}, {64, 1},
		{17, 13}, {63, 64}, {4, 4}, {48, 33}
	};
	int kind;
	size_t d;

	for (kind = 0; kind <= 7; kind++) {
		for (d = 0; d < sizeof dims / sizeof dims[0]; d++) {
			uint32_t w = dims[d][0], h = dims[d][1];
			char name[32];
			fill_pix(pix, w, h, kind);
			(void)snprintf(name, sizeof name, "kind%d", kind);
			roundtrip(pix, w, h, name);
		}
	}

	/* A too-small output buffer is rejected, not overrun. */
	{
		uint8_t tiny[4];
		size_t clen = 0;
		fill_pix(pix, 64, 64, 7);          /* random: incompressible */
		if (rdp_bitmap_planar_compress_24(tiny, sizeof tiny, &clen, pix,
		    64, 64) != -1)
			FAIL("tiny buffer not rejected");
	}
	/* Bad dimensions are rejected. */
	{
		uint8_t out[64];
		size_t clen = 0;
		if (rdp_bitmap_planar_compress_24(out, sizeof out, &clen, pix,
		    0, 10) != -1) FAIL("zero width accepted");
		if (rdp_bitmap_planar_compress_24(out, sizeof out, &clen, pix,
		    65, 10) != -1) FAIL("oversize width accepted");
	}
	/* A truncated planar stream must be rejected without an over-read. */
	{
		uint8_t decomp[64 * 64 * 3];
		const uint8_t in[] = { 0x30, 0x01 };   /* header + 1 byte */
		if (rdp_bitmap_planar_decompress_24(decomp, sizeof decomp, in,
		    sizeof in, 16, 16) != -1)
			FAIL("truncated stream not rejected");
	}

	(void)printf("bitmap_planar_test: all ok\n");
	return 0;
}
