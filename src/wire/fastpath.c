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

#include "../common/buf.h"
#include "../include/rdp_log.h"

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

/* Write a bare TS_UPDATE_BITMAP body (no fast-path wrapper) to out.
 * Returns the body size, or -1 if it would exceed cap or 0xffff. */
ssize_t
rdp_fp_build_bitmap_body(uint8_t *out, size_t cap,
		uint16_t x, uint16_t y, uint16_t w, uint16_t h,
		const uint8_t *pixels, size_t pixels_stride)
{
	uint16_t wpad = (uint16_t)((w + 3) & ~3u);
	size_t pixel_bytes = (size_t)wpad * 3 * h;
	size_t body_size = 4 + 18 + pixel_bytes;
	uint8_t *body = out;

	if (body_size > 0xffff) return -1;
	if (cap < body_size) return -1;
	body[0] = 0x01; body[1] = 0x00;
	body[2] = 0x01; body[3] = 0x00;
	body[4] = (uint8_t)(x & 0xff); body[5] = (uint8_t)(x >> 8);
	body[6] = (uint8_t)(y & 0xff); body[7] = (uint8_t)(y >> 8);
	{
		uint16_t r2 = (uint16_t)(x + w - 1);
		uint16_t b2 = (uint16_t)(y + h - 1);
		body[8] = (uint8_t)(r2 & 0xff);  body[9] = (uint8_t)(r2 >> 8);
		body[10] = (uint8_t)(b2 & 0xff); body[11] = (uint8_t)(b2 >> 8);
	}
	body[12] = (uint8_t)(wpad & 0xff); body[13] = (uint8_t)(wpad >> 8);
	body[14] = (uint8_t)(h & 0xff);    body[15] = (uint8_t)(h >> 8);
	body[16] = 24; body[17] = 0;       /* bitsPerPixel = 24 */
	body[18] = 0;  body[19] = 0;       /* flags = 0 (uncompressed) */
	body[20] = (uint8_t)(pixel_bytes & 0xff);
	body[21] = (uint8_t)((pixel_bytes >> 8) & 0xff);
	(void)encode_bitmap_pixels(body + 22, pixels, pixels_stride, w, h);
	return (ssize_t)body_size;
}

ssize_t
rdp_fp_build_bitmap_update(uint8_t *out, size_t cap,
		uint16_t x, uint16_t y, uint16_t w, uint16_t h,
		const uint8_t *pixels, size_t pixels_stride)
{
	uint16_t wpad = (uint16_t)((w + 3) & ~3u);
	size_t pixel_bytes = (size_t)wpad * 3 * h;
	/* TS_UPDATE_BITMAP header: updateType(2)=0x0001 + numberRectangles(2)
	 *   then per rect: destLeft/Top/Right/Bottom(2 each), width(2),
	 *   height(2), bitsPerPixel(2), flags(2), bitmapLength(2),
	 *   bitmapData(...). */
	size_t body_size = 4 + 18 + pixel_bytes;
	uint8_t *body;

	if (body_size > 0xffff) return -1;
	if (cap < 4 + body_size) return -1;
	body = out + 4;
	body[0] = 0x01; body[1] = 0x00;
	body[2] = 0x01; body[3] = 0x00;
	body[4] = (uint8_t)(x & 0xff); body[5] = (uint8_t)(x >> 8);
	body[6] = (uint8_t)(y & 0xff); body[7] = (uint8_t)(y >> 8);
	{
		uint16_t r2 = (uint16_t)(x + w - 1);
		uint16_t b2 = (uint16_t)(y + h - 1);
		body[8] = (uint8_t)(r2 & 0xff);  body[9] = (uint8_t)(r2 >> 8);
		body[10] = (uint8_t)(b2 & 0xff); body[11] = (uint8_t)(b2 >> 8);
	}
	body[12] = (uint8_t)(wpad & 0xff); body[13] = (uint8_t)(wpad >> 8);
	body[14] = (uint8_t)(h & 0xff);    body[15] = (uint8_t)(h >> 8);
	body[16] = 24; body[17] = 0;       /* bitsPerPixel = 24 */
	body[18] = 0;  body[19] = 0;       /* flags = 0 (uncompressed) */
	body[20] = (uint8_t)(pixel_bytes & 0xff);
	body[21] = (uint8_t)((pixel_bytes >> 8) & 0xff);
	(void)encode_bitmap_pixels(body + 22, pixels, pixels_stride, w, h);

	/* Now wrap in fast-path Update record header. */
	{
		struct rdp_buf b;
		size_t inner = 3 + body_size;
		size_t total = inner < 0x80 - 2 ? 1 + 1 + inner : 1 + 2 + inner;
		uint8_t hdr[4];
		size_t hdr_n;

		if (total > RDP_FP_MAX_PACKET_SIZE) return -1;
		rdp_buf_init(&b, hdr, sizeof hdr);
		if (fp_write_header(&b, total) != 0) return -1;
		hdr_n = rdp_buf_used(&b);
		if (hdr_n + 3 + body_size > cap) return -1;
		/* Shift body to make room for header. */
		memmove(out + hdr_n + 3, out + 4, body_size);
		memcpy(out, hdr, hdr_n);
		out[hdr_n + 0] = (uint8_t)((RDP_FP_UPDATE_BITMAP & 0x0f)
			| (RDP_FP_FRAGMENT_SINGLE << 4));
		out[hdr_n + 1] = (uint8_t)(body_size & 0xff);
		out[hdr_n + 2] = (uint8_t)((body_size >> 8) & 0xff);
		return (ssize_t)(hdr_n + 3 + body_size);
	}
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
