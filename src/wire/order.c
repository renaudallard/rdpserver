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
 * order.c -- RDP drawing-order encoders (MS-RDPEGDI): MemBlt + Cache Bitmap V2.
 */

#include "order.h"

#include "../common/buf.h"

/* MemBlt field-presence mask: this encoder always emits all nine fields, so the
 * two field-flag bytes are 0x01FF and need no trailing-zero trimming. */
#define MEMBLT_FIELDS 0x01FFu

/* MS-RDPEGDI fixes the secondary-order length as (total bytes) - 13. */
#define SEC_ORDER_LENGTH_BIAS 13

/* Append an absolute primary-order coordinate (2-byte LE, range 0..65535). */
static int
put_coord(struct rdp_buf *b, int32_t v)
{
	if (v < 0 || v > 65535) return -1;
	return rdp_buf_put_u16le(b, (uint16_t)v);
}

/* MS-RDPEGDI 2.2.2.2.1.1.1.1.2  "two-byte unsigned" variable encoding. */
static int
put_2byte_unsigned(struct rdp_buf *b, uint32_t v)
{
	if (v > 0x7FFF) return -1;
	if (v >= 0x7F) {
		if (rdp_buf_put_u8(b, (uint8_t)(((v & 0x7F00) >> 8) | 0x80)) != 0)
			return -1;
		return rdp_buf_put_u8(b, (uint8_t)(v & 0xFF));
	}
	return rdp_buf_put_u8(b, (uint8_t)(v & 0x7F));
}

/* MS-RDPEGDI 2.2.2.2.1.1.1.1.4 "four-byte unsigned" variable encoding. */
static int
put_4byte_unsigned(struct rdp_buf *b, uint32_t v)
{
	if (v <= 0x3F)
		return rdp_buf_put_u8(b, (uint8_t)v);
	if (v <= 0x3FFF) {
		if (rdp_buf_put_u8(b, (uint8_t)(((v >> 8) & 0x3F) | 0x40)) != 0)
			return -1;
		return rdp_buf_put_u8(b, (uint8_t)(v & 0xFF));
	}
	if (v <= 0x3FFFFF) {
		if (rdp_buf_put_u8(b, (uint8_t)(((v >> 16) & 0x3F) | 0x80)) != 0)
			return -1;
		if (rdp_buf_put_u8(b, (uint8_t)((v >> 8) & 0xFF)) != 0)
			return -1;
		return rdp_buf_put_u8(b, (uint8_t)(v & 0xFF));
	}
	if (v <= 0x3FFFFFFF) {
		if (rdp_buf_put_u8(b, (uint8_t)(((v >> 24) & 0x3F) | 0xC0)) != 0)
			return -1;
		if (rdp_buf_put_u8(b, (uint8_t)((v >> 16) & 0xFF)) != 0)
			return -1;
		if (rdp_buf_put_u8(b, (uint8_t)((v >> 8) & 0xFF)) != 0)
			return -1;
		return rdp_buf_put_u8(b, (uint8_t)(v & 0xFF));
	}
	return -1;
}

/* The 4-bit BitmapBpp identifier used by Cache Bitmap Rev2. */
static int
bpp_id(uint8_t bpp)
{
	switch (bpp) {
	case 8:  return 3;
	case 16: return 4;
	case 24: return 5;
	case 32: return 6;
	default: return -1;
	}
}

ssize_t
rdp_order_build_memblt(uint8_t *out, size_t cap, const struct rdp_memblt *m)
{
	struct rdp_buf b;

	if (m == NULL) return -1;
	rdp_buf_init(&b, out, cap);
	/* Standard primary order; always carry the orderType (TYPE_CHANGE) so a
	 * MemBlt is valid regardless of the preceding order, no bounds, absolute
	 * coordinates. */
	if (rdp_buf_put_u8(&b, RDP_ORDER_STANDARD | RDP_ORDER_TYPE_CHANGE) != 0)
		return -1;
	if (rdp_buf_put_u8(&b, RDP_ORDER_TYPE_MEMBLT) != 0) return -1;
	if (rdp_buf_put_u16le(&b, MEMBLT_FIELDS) != 0) return -1;
	/* Body: every field present, in order. */
	if (rdp_buf_put_u16le(&b, (uint16_t)(m->cache_id & 0xFF)) != 0)
		return -1;                       /* cacheId | colorIndex<<8 */
	if (put_coord(&b, m->x) != 0) return -1;
	if (put_coord(&b, m->y) != 0) return -1;
	if (put_coord(&b, m->w) != 0) return -1;
	if (put_coord(&b, m->h) != 0) return -1;
	if (rdp_buf_put_u8(&b, m->rop) != 0) return -1;
	if (put_coord(&b, m->src_x) != 0) return -1;
	if (put_coord(&b, m->src_y) != 0) return -1;
	if (rdp_buf_put_u16le(&b, m->cache_index) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_order_build_cache_bitmap_v2(uint8_t *out, size_t cap,
    const struct rdp_cache_bitmap *cb)
{
	struct rdp_buf body;
	size_t body_len, total;
	uint16_t extra_flags, cbr2_flags;
	uint16_t cache_index;
	int id;

	if (cb == NULL || cb->cache_id > 3) return -1;
	id = bpp_id(cb->bpp);
	if (id < 0) return -1;
	if (cap < 6) return -1;

	/* Persistent key is always attached; the height matches the width only
	 * when equal; the compression header is omitted. */
	cbr2_flags = CBR2_PERSISTENT_KEY_PRESENT;
	if (cb->height == cb->width)
		cbr2_flags |= CBR2_HEIGHT_SAME_AS_WIDTH;
	if (cb->compressed)
		cbr2_flags |= CBR2_NO_BITMAP_COMPRESSION_HDR;
	extra_flags = (uint16_t)((cb->cache_id & 0x0003)
	    | ((uint16_t)id << 3)
	    | ((uint16_t)cbr2_flags << 7));
	cache_index = cb->cache_index;

	/* Write the body after the 6-byte header so the header's orderLength can
	 * be computed from the final body length. */
	rdp_buf_init(&body, out + 6, cap - 6);
	if (rdp_buf_put_u32le(&body, (uint32_t)(cb->key & 0xFFFFFFFFu)) != 0)
		return -1;                                   /* key1 */
	if (rdp_buf_put_u32le(&body, (uint32_t)(cb->key >> 32)) != 0)
		return -1;                                   /* key2 */
	if (put_2byte_unsigned(&body, cb->width) != 0) return -1;
	if (!(cbr2_flags & CBR2_HEIGHT_SAME_AS_WIDTH)) {
		if (put_2byte_unsigned(&body, cb->height) != 0) return -1;
	}
	if (put_4byte_unsigned(&body, (uint32_t)cb->len) != 0) return -1;
	if (put_2byte_unsigned(&body, cache_index) != 0) return -1;
	if (cb->len > 0) {
		if (cb->data == NULL) return -1;
		if (rdp_buf_put(&body, cb->data, cb->len) != 0) return -1;
	}
	body_len = rdp_buf_used(&body);
	total = 6 + body_len;
	if (total - SEC_ORDER_LENGTH_BIAS > 0xFFFF) return -1;

	/* Header (6 bytes), back-filled now that body_len is known. */
	out[0] = RDP_ORDER_STANDARD | RDP_ORDER_SECONDARY;
	{
		uint16_t order_length = (uint16_t)(total - SEC_ORDER_LENGTH_BIAS);
		out[1] = (uint8_t)(order_length & 0xFF);
		out[2] = (uint8_t)((order_length >> 8) & 0xFF);
	}
	out[3] = (uint8_t)(extra_flags & 0xFF);
	out[4] = (uint8_t)((extra_flags >> 8) & 0xFF);
	out[5] = cb->compressed ? RDP_ORDER_TYPE_CACHE_BITMAP_COMPRESSED_V2
	    : RDP_ORDER_TYPE_CACHE_BITMAP_UNCOMPRESSED_V2;
	return (ssize_t)total;
}
