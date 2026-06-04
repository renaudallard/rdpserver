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
 * bitmap_rle_test.c -- round-trip of the interleaved RLE 24-bpp codec.
 *
 * The encoder's output is validated by decompressing it (with an independent
 * decoder) and checking the pixels are identical, across patterns that exercise
 * every run class: fill/background, mix/foreground, fom, color, color image,
 * and bicolor.
 */

#include "../../src/wire/bitmap_rle.h"

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
	uint8_t comp[64 * 64 * 3 + 1024];
	uint8_t decomp[64 * 64 * 3];
	uint8_t flip[64 * 64 * 3];
	size_t clen = 0;
	uint32_t y;

	if (rdp_bitmap_rle_compress_24(comp, sizeof comp, &clen, pix, w, h) != 0)
		FAIL("%s %ux%u: compress failed", name, w, h);
	if (clen == 0 || clen > sizeof comp)
		FAIL("%s %ux%u: bad clen %zu", name, w, h, clen);
	if (rdp_bitmap_rle_decompress_24(decomp, sizeof decomp, comp, clen,
	    w, h) != 0)
		FAIL("%s %ux%u: decompress failed", name, w, h);
	/* The RLE stream is bottom-up, so the decoded image is the input
	 * flipped vertically; flip it back to compare against the original. */
	for (y = 0; y < h; y++)
		memcpy(flip + (size_t)y * w * 3,
		    decomp + (size_t)(h - 1 - y) * w * 3, (size_t)w * 3);
	if (memcmp(pix, flip, (size_t)w * h * 3) != 0)
		FAIL("%s %ux%u: round-trip mismatch", name, w, h);
}

static void
fill_pix(uint8_t *p, uint32_t w, uint32_t h, int kind)
{
	uint32_t x, y;
	uint32_t lcg = 0x12345678u;

	for (y = 0; y < h; y++) {
		for (x = 0; x < w; x++) {
			uint8_t *q = p + ((size_t)y * w + x) * 3;
			uint8_t r, g, b;
			switch (kind) {
			case 0:                  /* solid */
				r = 0x40; g = 0x80; b = 0xc0; break;
			case 1:                  /* all black (background) */
				r = g = b = 0x00; break;
			case 2:                  /* all white (foreground) */
				r = g = b = 0xff; break;
			case 3:                  /* gradient (all distinct) */
				r = (uint8_t)x; g = (uint8_t)y;
				b = (uint8_t)(x + y); break;
			case 4:                  /* rows identical (fill runs) */
				r = (uint8_t)(x * 3); g = (uint8_t)(x * 5);
				b = (uint8_t)(x * 7); break;
			case 5:                  /* vertical 2-colour (bicolor) */
				if (x & 1) { r = 0x11; g = 0x22; b = 0x33; }
				else { r = 0xaa; g = 0xbb; b = 0xcc; }
				break;
			case 6:                  /* horizontal stripes */
				if (y & 1) { r = 0x10; g = 0x20; b = 0x30; }
				else { r = 0x90; g = 0xa0; b = 0xb0; }
				break;
			default:                 /* pseudo-random */
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
		{17, 13}, {63, 64}, {5, 1}, {2, 2}
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
		if (rdp_bitmap_rle_compress_24(tiny, sizeof tiny, &clen, pix,
		    64, 64) != -1)
			FAIL("tiny buffer not rejected");
	}
	/* Bad dimensions are rejected. */
	{
		uint8_t out[16];
		size_t clen = 0;
		if (rdp_bitmap_rle_compress_24(out, sizeof out, &clen, pix,
		    0, 10) != -1) FAIL("zero width accepted");
		if (rdp_bitmap_rle_compress_24(out, sizeof out, &clen, pix,
		    65, 10) != -1) FAIL("oversize width accepted");
	}
	/* Pathological decode dimensions (width*height*3 would overflow) must
	 * be rejected without any out-of-bounds write. */
	{
		uint8_t small[26];
		const uint8_t in[] = { 0x60, 0xff, 0x11, 0x22, 0x33 };
		if (rdp_bitmap_rle_decompress_24(small, sizeof small, in,
		    sizeof in, 3062868337u, 2007567422u) != -1)
			FAIL("overflow dims not rejected");
	}

	(void)printf("bitmap_rle_test: all ok\n");
	return 0;
}
