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
 * fastpath_test.c -- TS_UPDATE_BITMAP builder, including the interleaved-RLE
 * compressed path.  A compressible tile is built, parsed back, and the RLE is
 * decompressed and compared against the source pixels; an incompressible and
 * an oversized tile must fall back to the uncompressed form.
 */

#include "../../src/wire/fastpath.h"
#include "../../src/wire/bitmap_rle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static uint16_t
rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static void
fill_tile(uint8_t *p, uint32_t w, uint32_t h, int random)
{
	uint32_t i;
	uint32_t lcg = 0x1234abcdu;

	for (i = 0; i < w * h * 3; i++) {
		if (random) {
			lcg = lcg * 1103515245u + 12345u;
			p[i] = (uint8_t)(lcg >> 16);
		} else {
			p[i] = (uint8_t)(0x40 + ((i % 3) * 0x40));  /* solid */
		}
	}
}

/* Build a bare TS_UPDATE_BITMAP body and check the bitmap survives a round
 * trip.  want_compressed asserts which encoding the builder chose. */
static void
roundtrip(uint32_t w, uint32_t h, int random, int want_compressed,
    const char *name)
{
	uint8_t src[64 * 64 * 3];
	uint8_t body[64 * 64 * 3 + 512];
	uint8_t decomp[128 * 128 * 3];
	uint8_t flip[128 * 128 * 3];
	const uint8_t *bd;
	ssize_t n;
	uint16_t flags, blen, bw, bh;
	uint32_t y;

	if (w * h * 3 > sizeof src)
		FAIL("%s: src too small", name);
	fill_tile(src, w, h, random);

	n = rdp_fp_build_bitmap_body(body, sizeof body, 100, 50,
	    (uint16_t)w, (uint16_t)h, src, (size_t)w * 3);
	if (n < 22) FAIL("%s: build returned %lld", name, (long long)n);

	/* TS_UPDATE_BITMAP header. */
	if (body[0] != 0x01 || body[1] != 0x00 || body[2] != 0x01
	    || body[3] != 0x00) FAIL("%s: update header", name);
	bd = body + 4;                         /* TS_BITMAP_DATA */
	if (rd16(bd + 0) != 100 || rd16(bd + 2) != 50)
		FAIL("%s: dest origin", name);
	if (rd16(bd + 4) != 100 + w - 1 || rd16(bd + 6) != 50 + h - 1)
		FAIL("%s: dest extent", name);
	bw = rd16(bd + 8);
	bh = rd16(bd + 10);
	if (rd16(bd + 12) != 24) FAIL("%s: bpp", name);
	flags = rd16(bd + 14);
	blen = rd16(bd + 16);
	if (bh != h) FAIL("%s: height %u != %u", name, bh, (unsigned)h);

	if (want_compressed) {
		uint8_t rle[64 * 64 * 3 + 512];
		if (!(flags & 0x0001))
			FAIL("%s: expected compressed, flags=0x%04x", name, flags);
		if (bw != w) FAIL("%s: compressed width %u != %u", name, bw,
		    (unsigned)w);
		/* 8-byte comp header then blen RLE bytes. */
		if (rd16(bd + 20) != blen) FAIL("%s: cbCompMainBodySize", name);
		if ((size_t)(22 + blen) > (size_t)n) FAIL("%s: rle overruns", name);
		memcpy(rle, bd + 26, blen);
		if (rdp_bitmap_rle_decompress_24(decomp, sizeof decomp, rle,
		    blen, w, h) != 0) FAIL("%s: decompress", name);
		/* The RLE stream is bottom-up; flip to compare. */
		for (y = 0; y < h; y++)
			memcpy(flip + (size_t)y * w * 3,
			    decomp + (size_t)(h - 1 - y) * w * 3,
			    (size_t)w * 3);
		if (memcmp(src, flip, (size_t)w * h * 3) != 0)
			FAIL("%s: compressed round-trip mismatch", name);
	} else {
		uint16_t wpad = (uint16_t)((w + 3) & ~3u);
		if (flags & 0x0001)
			FAIL("%s: expected uncompressed, flags=0x%04x", name, flags);
		if (bw != wpad) FAIL("%s: uncompressed width %u != wpad %u",
		    name, bw, wpad);
		if (blen != (uint16_t)((size_t)wpad * 3 * h))
			FAIL("%s: uncompressed bitmapLength", name);
		/* Raw bottom-up rows padded to wpad; compare the w columns. */
		for (y = 0; y < h; y++) {
			const uint8_t *row = bd + 18 + (size_t)(h - 1 - y) * wpad * 3;
			if (memcmp(row, src + (size_t)y * w * 3, (size_t)w * 3) != 0)
				FAIL("%s: uncompressed row %u", name, y);
		}
	}
}

int
main(void)
{
	/* Solid tiles compress; the builder must choose the compressed form. */
	roundtrip(64, 64, 0, 1, "solid64");
	roundtrip(8, 8, 0, 1, "solid8");
	roundtrip(17, 13, 0, 1, "solid17x13");   /* unaligned width */
	/* A 1x1 tile cannot beat the raw rows once the 8-byte compression
	 * header is counted, so the builder keeps it uncompressed. */
	roundtrip(1, 1, 0, 0, "solid1");

	/* Random tiles do not shrink below the raw rows -> uncompressed. */
	roundtrip(64, 64, 1, 0, "rand64");

	/* Tiles beyond the 64x64 RLE limit always fall back to uncompressed. */
	{
		uint8_t big[100 * 100 * 3];
		uint8_t body[100 * 100 * 3 + 512];
		ssize_t n;
		fill_tile(big, 64, 64, 0);             /* reuse: fill 64x64 worth */
		memset(big, 0x55, sizeof big);
		n = rdp_fp_build_bitmap_body(body, sizeof body, 0, 0, 100, 100,
		    big, 100 * 3);
		if (n < 0) FAIL("big build failed");
		if (rd16(body + 4 + 14) & 0x0001) FAIL("100x100 was compressed");
	}

	/* The fast-path-wrapped builder produces a non-empty PDU. */
	{
		uint8_t src[64 * 64 * 3];
		uint8_t pkt[64 * 64 * 3 + 512];
		ssize_t n;
		fill_tile(src, 64, 64, 0);
		n = rdp_fp_build_bitmap_update(pkt, sizeof pkt, 0, 0, 64, 64,
		    src, 64 * 3);
		if (n <= 0) FAIL("wrapped build failed");
		if ((pkt[0] & 0x03) != 0) FAIL("not a fast-path action");
	}

	(void)printf("fastpath_test: all ok\n");
	return 0;
}
