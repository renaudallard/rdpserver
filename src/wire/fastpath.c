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
 * fastpath.c -- Fast-Path output encoder and input decoder.
 */

#include "fastpath.h"

#include "bitmap_rle.h"
#include "../common/buf.h"
#include "../include/rdp_log.h"

#include <stdlib.h>
#include <string.h>

/* Encode the fast-path header: 1 byte (action=0, numEvents=0,
 * security flags=0) plus the variable length determinant. */
static int
fp_write_header(struct rdp_buf *b, size_t total_len)
{
	if (rdp_buf_put_u8(b, 0) != 0) return -1;
	if (total_len <= 0x7f) {
		if (rdp_buf_put_u8(b, (uint8_t)total_len) != 0) return -1;
	} else {
		if (rdp_buf_put_u8(b,
			(uint8_t)(0x80 | ((total_len >> 8) & 0x7f))) != 0)
			return -1;
		if (rdp_buf_put_u8(b, (uint8_t)(total_len & 0xff)) != 0)
			return -1;
	}
	return 0;
}

ssize_t
rdp_fp_build_update_frag(uint8_t *out, size_t cap,
		uint8_t update_type, uint8_t fragment,
		const void *body, size_t body_len)
{
	size_t inner = 3 + body_len;        /* 1 (updateHeader) + 2 (size) + body */
	size_t total_min = 1 + 1 + inner;    /* assume 1-byte length */
	size_t total = total_min < 0x80 ? total_min : 1 + 2 + inner;
	struct rdp_buf b;

	if (total > cap || body_len > 0xffff) return -1;
	if (total > RDP_FP_MAX_PACKET_SIZE) return -1;
	rdp_buf_init(&b, out, cap);
	if (fp_write_header(&b, total) != 0) return -1;
	if (rdp_buf_put_u8(&b,
		(uint8_t)((update_type & 0x0f)
		| (fragment << 4))) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)body_len) != 0) return -1;
	if (body_len > 0 && rdp_buf_put(&b, body, body_len) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_fp_build_update(uint8_t *out, size_t cap,
		uint8_t update_type, const void *body, size_t body_len)
{
	return rdp_fp_build_update_frag(out, cap, update_type,
		RDP_FP_FRAGMENT_SINGLE, body, body_len);
}

ssize_t
rdp_fp_build_synchronize(uint8_t *out, size_t cap)
{
	return rdp_fp_build_update(out, cap, RDP_FP_UPDATE_SYNCHRONIZE, NULL, 0);
}

ssize_t
rdp_fp_build_pointer_default(uint8_t *out, size_t cap)
{
	return rdp_fp_build_update(out, cap, RDP_FP_UPDATE_PTR_DEFAULT, NULL, 0);
}

ssize_t
rdp_fp_build_pointer_new(uint8_t *out, size_t cap,
		uint16_t cache_index, uint16_t hot_x, uint16_t hot_y,
		uint16_t w, uint16_t h, const uint8_t *argb, size_t stride)
{
	size_t xor_stride = (size_t)w * 4;          /* 32bpp, already even */
	size_t and_stride = ((size_t)w + 15) / 16 * 2; /* 1bpp, WORD-padded */
	size_t len_xor = xor_stride * h;
	size_t len_and = and_stride * h;
	size_t body_len = 16 + len_xor + len_and;
	uint8_t *body;
	uint16_t r;
	ssize_t rc;

	if (w == 0 || h == 0 || argb == NULL) return -1;
	if (len_xor > 0xffff || len_and > 0xffff) return -1;
	/* The hotspot must lie within the cursor; clamp untrusted input. */
	if (hot_x >= w) hot_x = (uint16_t)(w - 1);
	if (hot_y >= h) hot_y = (uint16_t)(h - 1);
	body = malloc(body_len);
	if (body == NULL) return -1;

	/* TS_POINTERATTRIBUTE header (all u16 LE). */
	body[0] = 32; body[1] = 0;                          /* xorBpp = 32 */
	body[2] = (uint8_t)(cache_index & 0xff);
	body[3] = (uint8_t)(cache_index >> 8);
	body[4] = (uint8_t)(hot_x & 0xff);
	body[5] = (uint8_t)(hot_x >> 8);
	body[6] = (uint8_t)(hot_y & 0xff);
	body[7] = (uint8_t)(hot_y >> 8);
	body[8] = (uint8_t)(w & 0xff);
	body[9] = (uint8_t)(w >> 8);
	body[10] = (uint8_t)(h & 0xff);
	body[11] = (uint8_t)(h >> 8);
	body[12] = (uint8_t)(len_and & 0xff);
	body[13] = (uint8_t)(len_and >> 8);
	body[14] = (uint8_t)(len_xor & 0xff);
	body[15] = (uint8_t)(len_xor >> 8);

	/* Rows are bottom-up: output row r maps to source row (h-1-r). */
	for (r = 0; r < h; r++) {
		const uint8_t *src = argb + (size_t)(h - 1 - r) * stride;
		uint8_t *xrow = body + 16 + (size_t)r * xor_stride;
		uint8_t *arow = body + 16 + len_xor + (size_t)r * and_stride;
		uint16_t x;
		memset(arow, 0, and_stride);
		for (x = 0; x < w; x++) {
			uint8_t pr = src[x * 4 + 0];
			uint8_t pg = src[x * 4 + 1];
			uint8_t pb = src[x * 4 + 2];
			uint8_t pa = src[x * 4 + 3];
			/* xorMask pixel as BGRA. */
			xrow[x * 4 + 0] = pb;
			xrow[x * 4 + 1] = pg;
			xrow[x * 4 + 2] = pr;
			xrow[x * 4 + 3] = pa;
			/* AND mask MSB-first: 1 = transparent, 0 = opaque. */
			if (pa < 128)
				arow[x / 8] |= (uint8_t)(0x80 >> (x % 8));
		}
	}

	rc = rdp_fp_build_update(out, cap, RDP_FP_UPDATE_POINTER,
		body, body_len);
	free(body);
	return rc;
}

ssize_t
rdp_fp_build_pointer_cached(uint8_t *out, size_t cap, uint16_t cache_index)
{
	uint8_t body[2];
	body[0] = (uint8_t)(cache_index & 0xff);
	body[1] = (uint8_t)(cache_index >> 8);
	return rdp_fp_build_update(out, cap, RDP_FP_UPDATE_CACHED, body, sizeof body);
}

/* Convert a top-down 24bpp BGR frame slice into a bottom-up rows
 * padded to 4 pixels wide, packed contiguously.  This is what
 * TS_BITMAP_DATA expects when bitsPerPixel = 24 and compression = 0.
 * Returns the size in bytes of the encoded pixel block. */
static size_t
encode_bitmap_pixels(uint8_t *out, const uint8_t *src, size_t src_stride,
		uint16_t w, uint16_t h)
{
	uint16_t wpad = (uint16_t)((w + 3) & ~3u);
	size_t row_bytes = (size_t)wpad * 3;
	uint16_t r;

	for (r = 0; r < h; r++) {
		const uint8_t *src_row = src + (size_t)(h - 1 - r) * src_stride;
		uint8_t *dst_row = out + (size_t)r * row_bytes;
		size_t i;
		for (i = 0; i < w; i++) {
			dst_row[i * 3 + 0] = src_row[i * 3 + 0];
			dst_row[i * 3 + 1] = src_row[i * 3 + 1];
			dst_row[i * 3 + 2] = src_row[i * 3 + 2];
		}
		for (i = w; i < wpad; i++) {
			dst_row[i * 3 + 0] = 0;
			dst_row[i * 3 + 1] = 0;
			dst_row[i * 3 + 2] = 0;
		}
	}
	return row_bytes * h;
}

/* TS_BITMAP_DATA flags (MS-RDPBCGR 2.2.9.1.1.3.1.2.2). */
#define BITMAP_COMPRESSION      0x0001
#define NO_BITMAP_COMPRESSION_HDR 0x0400

/* Write one TS_BITMAP_DATA (the per-rectangle structure: 18 header bytes then
 * the bitmap) for the rectangle [x, y, w, h] from 24bpp top-down BGR pixels
 * into dst (cap bytes).  When the tile is within the RLE codec's 64x64 limit,
 * its rows are packed (stride == w*3) and interleaved RLE shrinks it below the
 * raw 4-pixel-padded rows (counting the 8-byte compression header), the
 * compressed form is written; otherwise the raw bottom-up rows are.  The
 * compression header is always included, so any client decodes it.  Returns
 * the number of bytes written, or -1 on overflow. */
static ssize_t
write_bitmap_data(uint8_t *dst, size_t cap, uint16_t x, uint16_t y,
		uint16_t w, uint16_t h, const uint8_t *pixels, size_t stride)
{
	uint16_t wpad = (uint16_t)((w + 3) & ~3u);
	size_t pixel_bytes = (size_t)wpad * 3 * h;
	uint16_t r2 = (uint16_t)(x + w - 1);
	uint16_t b2 = (uint16_t)(y + h - 1);
	uint8_t rle[64 * 64 * 3 + 256];
	size_t rle_len = 0;

	/* The 18-byte TS_BITMAP_DATA header is written below before either
	 * branch revalidates against the data size, so it must fit first. */
	if (cap < 18) return -1;
	dst[0] = (uint8_t)(x & 0xff);  dst[1] = (uint8_t)(x >> 8);
	dst[2] = (uint8_t)(y & 0xff);  dst[3] = (uint8_t)(y >> 8);
	dst[4] = (uint8_t)(r2 & 0xff); dst[5] = (uint8_t)(r2 >> 8);
	dst[6] = (uint8_t)(b2 & 0xff); dst[7] = (uint8_t)(b2 >> 8);
	dst[12] = 24; dst[13] = 0;                 /* bitsPerPixel = 24 */

	if (w >= 1 && w <= 64 && h >= 1 && h <= 64 && stride == (size_t)w * 3
	    && rdp_bitmap_rle_compress_24(rle, sizeof rle, &rle_len, pixels, w, h)
	       == 0 && rle_len + 8 < pixel_bytes) {
		size_t total = 18 + 8 + rle_len;
		uint16_t scan = (uint16_t)(w * 3);
		uint16_t uncomp = (uint16_t)(w * 3 * h);
		if (cap < total) return -1;
		dst[8] = (uint8_t)(w & 0xff);  dst[9] = (uint8_t)(w >> 8);
		dst[10] = (uint8_t)(h & 0xff); dst[11] = (uint8_t)(h >> 8);
		dst[14] = BITMAP_COMPRESSION; dst[15] = 0;      /* flags */
		dst[16] = (uint8_t)(rle_len & 0xff);            /* bitmapLength */
		dst[17] = (uint8_t)((rle_len >> 8) & 0xff);
		/* bitmapComprHdr (TS_CD_HEADER, 8 bytes). */
		dst[18] = 0; dst[19] = 0;                       /* cbCompFirstRowSize */
		dst[20] = (uint8_t)(rle_len & 0xff);            /* cbCompMainBodySize */
		dst[21] = (uint8_t)((rle_len >> 8) & 0xff);
		dst[22] = (uint8_t)(scan & 0xff);               /* cbScanWidth */
		dst[23] = (uint8_t)(scan >> 8);
		dst[24] = (uint8_t)(uncomp & 0xff);             /* cbUncompressedSize */
		dst[25] = (uint8_t)(uncomp >> 8);
		memcpy(dst + 26, rle, rle_len);
		return (ssize_t)total;
	}

	/* Raw: bottom-up rows padded to a 4-pixel width. */
	if (18 + pixel_bytes > 0xffff || cap < 18 + pixel_bytes) return -1;
	dst[8] = (uint8_t)(wpad & 0xff); dst[9] = (uint8_t)(wpad >> 8);
	dst[10] = (uint8_t)(h & 0xff);   dst[11] = (uint8_t)(h >> 8);
	dst[14] = 0; dst[15] = 0;                  /* flags = 0 (uncompressed) */
	dst[16] = (uint8_t)(pixel_bytes & 0xff);   /* bitmapLength */
	dst[17] = (uint8_t)((pixel_bytes >> 8) & 0xff);
	(void)encode_bitmap_pixels(dst + 18, pixels, stride, w, h);
	return (ssize_t)(18 + pixel_bytes);
}

/* Write a bare TS_UPDATE_BITMAP body (no fast-path wrapper) to out.
 * Returns the body size, or -1 if it would exceed cap or 0xffff. */
ssize_t
rdp_fp_build_bitmap_body(uint8_t *out, size_t cap,
		uint16_t x, uint16_t y, uint16_t w, uint16_t h,
		const uint8_t *pixels, size_t pixels_stride)
{
	ssize_t bd;

	if (cap < 4) return -1;
	out[0] = 0x01; out[1] = 0x00;      /* updateType = UPDATETYPE_BITMAP */
	out[2] = 0x01; out[3] = 0x00;      /* numberRectangles = 1 */
	bd = write_bitmap_data(out + 4, cap - 4, x, y, w, h, pixels, pixels_stride);
	if (bd < 0 || 4 + (size_t)bd > 0xffff) return -1;
	return 4 + bd;
}

ssize_t
rdp_fp_build_bitmap_update(uint8_t *out, size_t cap,
		uint16_t x, uint16_t y, uint16_t w, uint16_t h,
		const uint8_t *pixels, size_t pixels_stride)
{
	ssize_t bd;
	size_t body_size;
	struct rdp_buf b;
	size_t inner, total, hdr_n;
	uint8_t hdr[4];

	/* Build the TS_UPDATE_BITMAP body at out+4, then prefix the fast-path
	 * record headers (which are 1-2 bytes shorter, so the body is shifted
	 * left into place once their length is known). */
	if (cap < 8) return -1;
	out[4] = 0x01; out[5] = 0x00;
	out[6] = 0x01; out[7] = 0x00;
	bd = write_bitmap_data(out + 8, cap - 8, x, y, w, h, pixels, pixels_stride);
	if (bd < 0) return -1;
	body_size = 4 + (size_t)bd;
	if (body_size > 0xffff) return -1;

	inner = 3 + body_size;
	total = inner < 0x80 - 2 ? 1 + 1 + inner : 1 + 2 + inner;
	if (total > RDP_FP_MAX_PACKET_SIZE) return -1;
	rdp_buf_init(&b, hdr, sizeof hdr);
	if (fp_write_header(&b, total) != 0) return -1;
	hdr_n = rdp_buf_used(&b);
	if (hdr_n + 3 + body_size > cap) return -1;
	memmove(out + hdr_n + 3, out + 4, body_size);
	memcpy(out, hdr, hdr_n);
	out[hdr_n + 0] = (uint8_t)((RDP_FP_UPDATE_BITMAP & 0x0f)
		| (RDP_FP_FRAGMENT_SINGLE << 4));
	out[hdr_n + 1] = (uint8_t)(body_size & 0xff);
	out[hdr_n + 2] = (uint8_t)((body_size >> 8) & 0xff);
	return (ssize_t)(hdr_n + 3 + body_size);
}

int
rdp_fp_looks_like(const uint8_t *buf, size_t len)
{
	if (len < 1) return 0;
	if (buf[0] == 0x03) return 0;   /* TPKT */
	if ((buf[0] & 0x03) == 0) return 1; /* fast-path action bits = 0 */
	return 0;
}

int
rdp_fp_parse_input(const uint8_t *buf, size_t len,
		rdp_fp_input_cb cb, void *ctx, unsigned *n_events_out)
{
	uint8_t hdr;
	unsigned n_events;
	size_t off, total;

	if (len < 2) return -1;
	hdr = buf[0];
	if ((hdr & 0x03) != 0) return -1;   /* not fast-path input */
	n_events = (unsigned)((hdr >> 2) & 0x0f);
	if ((buf[1] & 0x80) == 0) {
		total = buf[1];
		off = 2;
	} else {
		if (len < 3) return -1;
		total = ((size_t)(buf[1] & 0x7f) << 8) | buf[2];
		off = 3;
	}
	if (total != len) return -1;
	if (n_events == 0) {
		if (off >= len) return -1;
		n_events = buf[off++];
	}
	if (n_events_out) *n_events_out = n_events;
	while (n_events-- > 0) {
		struct rdp_fp_input_event ev = {0};
		uint8_t eh;
		uint8_t etype;
		if (off >= len) return -1;
		eh = buf[off++];
		etype = (uint8_t)((eh >> 5) & 0x07);
		ev.type = etype;
		ev.flags = (uint16_t)(eh & 0x1f);
		switch (etype) {
		case RDP_FP_INPUT_SCANCODE:
			if (off >= len) return -1;
			ev.keycode = buf[off++];
			break;
		case RDP_FP_INPUT_MOUSE:
		case RDP_FP_INPUT_MOUSEX:
			if (off + 6 > len) return -1;
			ev.flags = (uint16_t)buf[off]
				| ((uint16_t)buf[off + 1] << 8);
			off += 2;
			ev.x = (int32_t)buf[off] | ((int32_t)buf[off + 1] << 8);
			off += 2;
			ev.y = (int32_t)buf[off] | ((int32_t)buf[off + 1] << 8);
			off += 2;
			break;
		case RDP_FP_INPUT_SYNC:
			break;
		case RDP_FP_INPUT_UNICODE:
			if (off + 2 > len) return -1;
			ev.keycode = (uint16_t)buf[off]
				| ((uint16_t)buf[off + 1] << 8);
			off += 2;
			break;
		default:
			return -1;
		}
		if (cb) cb(ctx, &ev);
	}
	return 0;
}
