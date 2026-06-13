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
 * bitmap_planar.c -- MS-RDPEGDI RDP6.0 planar bitmap compression (the RGB,
 * no-alpha, no-colour-loss form), a faithful port of the FreeRDP encoder
 * (libfreerdp/codec/planar.c) limited to what a 32bpp server emits.
 *
 * Stream layout produced here:
 *   FormatHeader (1 byte) = 0x30 (NA | RLE; CLL=0, CS=0)
 *   RLE-compressed Red plane
 *   RLE-compressed Green plane
 *   RLE-compressed Blue plane
 * Each plane is first scanline-delta-encoded (row 0 verbatim, later rows the
 * signed zig-zag delta against the row above) then run-length compressed one
 * scanline at a time.
 */

#include "bitmap_planar.h"

#include <string.h>

#define PLANAR_DIM_MAX 64
#define PLANAR_PIX_MAX (PLANAR_DIM_MAX * PLANAR_DIM_MAX)

/* FormatHeader bits (MS-RDPEGDI 2.2.2.5.1). */
#define PLANAR_FMT_RLE 0x10
#define PLANAR_FMT_NA  0x20

/* controlByte: low nibble = run length, high nibble = raw-byte count. */
#define PLANAR_CB(run, raw) ((uint8_t)(((run) & 0x0f) | (((raw) & 0x0f) << 4)))

/* ---- encoder ---------------------------------------------------------- */

/* Scanline delta-encode one plane: row 0 copied verbatim, later rows hold the
 * signed delta against the row above, sign-folded to a byte (d>=0 -> 2d,
 * d<0 -> 2|d|-1).  in and out are width*height bytes. */
static void
delta_encode_plane(const uint8_t *in, uint32_t width, uint32_t height,
		uint8_t *out)
{
	uint32_t x, y;

	memcpy(out, in, width);
	for (y = 1; y < height; y++) {
		const uint8_t *src = in + (size_t)y * width;
		const uint8_t *prev = in + (size_t)(y - 1) * width;
		uint8_t *dst = out + (size_t)y * width;
		for (x = 0; x < width; x++) {
			/* Low-byte signed delta in [-128,127] (mod 256). */
			uint8_t ud = (uint8_t)(src[x] - prev[x]);
			if (ud < 128)
				dst[x] = (uint8_t)(ud << 1);
			else
				dst[x] = (uint8_t)(((256u - ud) << 1) - 1u);
		}
	}
}

/* Emit one (cRawBytes literals + nRunLength run) chunk into out (cap bytes).
 * Returns the bytes written, or -1 on overflow.  Port of FreeRDP's
 * freerdp_bitmap_planar_write_rle_bytes. */
static ssize_t
write_rle_bytes(const uint8_t *in, uint32_t cRawBytes, uint32_t nRunLength,
		uint8_t *out, size_t cap)
{
	size_t pos = 0;
	uint8_t cb;
	uint8_t nraw;

	if (cRawBytes == 0 && nRunLength == 0)
		return 0;
	/* Runs shorter than 3 are cheaper stored as literals (and 1/2 collide
	 * with the extended-run escapes). */
	if (nRunLength < 3) {
		cRawBytes += nRunLength;
		nRunLength = 0;
	}

	while (cRawBytes) {
		if (cRawBytes < 16) {
			if (nRunLength > 15) {
				if (nRunLength < 18) {
					cb = PLANAR_CB(13, cRawBytes);
					nRunLength -= 13;
					cRawBytes = 0;
				} else {
					cb = PLANAR_CB(15, cRawBytes);
					nRunLength -= 15;
					cRawBytes = 0;
				}
			} else {
				cb = PLANAR_CB(nRunLength, cRawBytes);
				nRunLength = 0;
				cRawBytes = 0;
			}
		} else {
			cb = PLANAR_CB(0, 15);
			cRawBytes -= 15;
		}
		if (pos + 1 > cap) return -1;
		out[pos++] = cb;
		nraw = (uint8_t)(cb >> 4);
		if (nraw) {
			if (pos + nraw > cap) return -1;
			memcpy(out + pos, in, nraw);
			pos += nraw;
			in += nraw;
		}
	}

	while (nRunLength) {
		if (nRunLength > 47) {
			if (nRunLength < 50) {
				cb = PLANAR_CB(2, 13);
				nRunLength -= 45;
			} else {
				cb = PLANAR_CB(2, 15);
				nRunLength -= 47;
			}
		} else if (nRunLength > 31) {
			cb = PLANAR_CB(2, nRunLength - 32);
			nRunLength = 0;
		} else if (nRunLength > 15) {
			cb = PLANAR_CB(1, nRunLength - 16);
			nRunLength = 0;
		} else {
			cb = PLANAR_CB(nRunLength, 0);
			nRunLength = 0;
		}
		if (pos + 1 > cap) return -1;
		out[pos++] = cb;
	}
	return (ssize_t)pos;
}

/* RLE-compress one scanline (inlen bytes) into out (cap bytes).  Returns the
 * bytes written, or -1 on overflow.  Port of FreeRDP's
 * freerdp_bitmap_planar_encode_rle_bytes. */
static ssize_t
encode_rle_scanline(const uint8_t *in, uint32_t inlen, uint8_t *out, size_t cap)
{
	uint8_t symbol = 0;
	const uint8_t *p = in;
	uint32_t remaining = inlen;
	uint32_t cRawBytes = 0, nRunLength = 0;
	size_t pos = 0;

	while (remaining > 0) {
		uint32_t match = (symbol == *p) ? 1u : 0u;
		symbol = *p;
		p++;
		remaining--;
		if (nRunLength && !match) {
			if (nRunLength < 3) {
				cRawBytes += nRunLength;
				nRunLength = 0;
			} else {
				const uint8_t *bytes =
					p - (cRawBytes + nRunLength + 1);
				ssize_t n = write_rle_bytes(bytes, cRawBytes,
					nRunLength, out + pos, cap - pos);
				if (n < 0) return -1;
				pos += (size_t)n;
				nRunLength = 0;
				cRawBytes = 0;
			}
		}
		nRunLength += match;
		cRawBytes += match ? 0u : 1u;
	}
	if (cRawBytes || nRunLength) {
		const uint8_t *bytes = p - (cRawBytes + nRunLength);
		ssize_t n = write_rle_bytes(bytes, cRawBytes, nRunLength,
			out + pos, cap - pos);
		if (n < 0) return -1;
		pos += (size_t)n;
	}
	return (ssize_t)pos;
}

/* RLE-compress a whole delta plane scanline by scanline into out.  Returns the
 * bytes written, or -1 on overflow. */
static ssize_t
compress_plane(const uint8_t *delta, uint32_t width, uint32_t height,
		uint8_t *out, size_t cap)
{
	size_t pos = 0;
	uint32_t y;

	for (y = 0; y < height; y++) {
		ssize_t n = encode_rle_scanline(delta + (size_t)y * width, width,
			out + pos, cap - pos);
		if (n < 0) return -1;
		pos += (size_t)n;
	}
	return (ssize_t)pos;
}

int
rdp_bitmap_planar_compress_24(uint8_t *dst, size_t cap, size_t *out_len,
		const uint8_t *src, uint32_t width, uint32_t height)
{
	uint8_t plane[PLANAR_PIX_MAX];
	uint8_t delta[PLANAR_PIX_MAX];
	/* Per-plane RLE worst case stays well under twice the plane. */
	uint8_t rle[3][PLANAR_PIX_MAX * 2];
	size_t rlen[3];
	size_t npix, total, i;
	int c;

	if (width == 0 || height == 0 || width > PLANAR_DIM_MAX ||
	    height > PLANAR_DIM_MAX)
		return -1;
	npix = (size_t)width * height;

	/* Channels in wire order R, G, B; source pixel is packed B,G,R. */
	for (c = 0; c < 3; c++) {
		size_t off = (size_t)(2 - c);   /* R=src[2], G=src[1], B=src[0] */
		ssize_t n;
		for (i = 0; i < npix; i++)
			plane[i] = src[i * 3 + off];
		delta_encode_plane(plane, width, height, delta);
		n = compress_plane(delta, width, height, rle[c], sizeof rle[c]);
		if (n < 0)
			return -1;
		rlen[c] = (size_t)n;
	}

	total = 1 + rlen[0] + rlen[1] + rlen[2];
	if (total > cap)
		return -1;
	dst[0] = PLANAR_FMT_NA | PLANAR_FMT_RLE;
	total = 1;
	for (c = 0; c < 3; c++) {
		memcpy(dst + total, rle[c], rlen[c]);
		total += rlen[c];
	}
	*out_len = total;
	return 0;
}

/* ---- decoder (round-trip test) ---------------------------------------- */

/* Decode one RLE plane (width*height delta bytes) from *pp (with *prem bytes
 * left), advancing the pointer.  Returns 0 on success, -1 on malformed input.
 * Each scanline is decoded independently to exactly width bytes; the run-only
 * escapes (run nibble 1 -> +16, 2 -> +32) match the encoder. */
static int
decode_plane_rle(const uint8_t **pp, size_t *prem, uint32_t width,
		uint32_t height, uint8_t *delta)
{
	const uint8_t *p = *pp;
	size_t rem = *prem;
	uint32_t y;

	for (y = 0; y < height; y++) {
		uint8_t *row = delta + (size_t)y * width;
		uint32_t x = 0;
		uint8_t last = 0;       /* encoder symbol starts at 0 each row */
		while (x < width) {
			uint8_t cb, run, raw;
			uint32_t k;
			if (rem < 1) return -1;
			cb = *p++; rem--;
			run = (uint8_t)(cb & 0x0f);
			raw = (uint8_t)((cb >> 4) & 0x0f);
			if (run == 1) { run = (uint8_t)(raw + 16); raw = 0; }
			else if (run == 2) { run = (uint8_t)(raw + 32); raw = 0; }
			if ((size_t)raw > rem) return -1;
			for (k = 0; k < raw; k++) {
				if (x >= width) return -1;
				last = *p++;
				row[x++] = last;
			}
			rem -= raw;
			for (k = 0; k < run; k++) {
				if (x >= width) return -1;
				row[x++] = last;
			}
		}
	}
	*pp = p;
	*prem = rem;
	return 0;
}

int
rdp_bitmap_planar_decompress_24(uint8_t *dst, size_t dst_len,
		const uint8_t *src, size_t src_len, uint32_t width, uint32_t height)
{
	uint8_t delta[PLANAR_PIX_MAX];
	uint8_t plane[3][PLANAR_PIX_MAX];
	const uint8_t *p;
	size_t rem, npix, i;
	uint8_t fmt;
	int rle, na, c;
	uint32_t x, y;

	if (width == 0 || height == 0 || width > PLANAR_DIM_MAX ||
	    height > PLANAR_DIM_MAX || src_len < 1)
		return -1;
	npix = (size_t)width * height;
	if (dst_len < npix * 3)
		return -1;

	p = src;
	rem = src_len;
	fmt = *p++; rem--;
	rle = (fmt & PLANAR_FMT_RLE) != 0;
	na = (fmt & PLANAR_FMT_NA) != 0;
	/* This codec only emits the RGB no-loss no-alpha form. */
	if ((fmt & 0x0f) != 0 || (fmt & 0x08) != 0 || !na)
		return -1;

	for (c = 0; c < 3; c++) {
		if (rle) {
			if (decode_plane_rle(&p, &rem, width, height, delta) != 0)
				return -1;
			/* Undo the scanline delta encoding. */
			memcpy(plane[c], delta, width);
			for (y = 1; y < height; y++) {
				uint8_t *row = plane[c] + (size_t)y * width;
				const uint8_t *prev = plane[c] + (size_t)(y - 1) * width;
				const uint8_t *d = delta + (size_t)y * width;
				for (x = 0; x < width; x++) {
					int dv = (d[x] & 1) ? -((d[x] >> 1) + 1)
							    : (d[x] >> 1);
					row[x] = (uint8_t)(prev[x] + dv);
				}
			}
		} else {
			if (rem < npix) return -1;
			memcpy(plane[c], p, npix);
			p += npix; rem -= npix;
		}
	}

	/* Reassemble packed B,G,R from the R,G,B planes. */
	for (i = 0; i < npix; i++) {
		dst[i * 3 + 0] = plane[2][i];   /* B */
		dst[i * 3 + 1] = plane[1][i];   /* G */
		dst[i * 3 + 2] = plane[0][i];   /* R */
	}
	return 0;
}
