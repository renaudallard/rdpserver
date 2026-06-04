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
 * order_test.c -- MS-RDPEGDI MemBlt and Cache Bitmap Rev2 order encoders.
 *
 * The expected bytes are derived from the FreeRDP encoder (update_write_memblt_
 * order and update_write_cache_bitmap_v2_order): the primary-order header with
 * fieldFlags 0x01FF, the secondary-order header with orderLength = total - 13,
 * the packed extraFlags, and the 2-byte / 4-byte variable-length integers.
 */

#include "../../src/wire/order.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
test_memblt(void)
{
	uint8_t out[64];
	struct rdp_memblt m;
	ssize_t n;
	/* control, orderType, fieldFlags(0x01FF), then the 9 fields. */
	static const uint8_t want[] = {
		0x09, 0x0D, 0xFF, 0x01,
		0x02, 0x00,             /* cacheId 2 | colorIndex 0 */
		0x64, 0x00,             /* x = 100 */
		0x32, 0x00,             /* y = 50 */
		0x40, 0x00,             /* w = 64 */
		0x40, 0x00,             /* h = 64 */
		0xCC,                   /* rop SRCCOPY */
		0x00, 0x00,             /* src_x = 0 */
		0x00, 0x00,             /* src_y = 0 */
		0x05, 0x00              /* cacheIndex 5 */
	};

	memset(&m, 0, sizeof m);
	m.cache_id = 2;
	m.cache_index = 5;
	m.x = 100; m.y = 50; m.w = 64; m.h = 64;
	m.rop = RDP_ROP_SRCCOPY;
	m.src_x = 0; m.src_y = 0;
	n = rdp_order_build_memblt(out, sizeof out, &m);
	if (n != (ssize_t)sizeof want) FAIL("memblt len %zd", (ssize_t)n);
	if (memcmp(out, want, sizeof want) != 0) FAIL("memblt bytes");

	/* An out-of-range coordinate and a too-small buffer are rejected. */
	m.x = 70000;
	if (rdp_order_build_memblt(out, sizeof out, &m) != -1)
		FAIL("memblt oob coord accepted");
	m.x = 100;
	if (rdp_order_build_memblt(out, 10, &m) != -1)
		FAIL("memblt small cap accepted");
}

static void
test_cache_bitmap_square(void)
{
	uint8_t out[64];
	struct rdp_cache_bitmap cb;
	ssize_t n;
	const uint8_t data[] = { 'D', 'A', 'T', 'A' };
	/* header(6) then key1,key2,width(1),length(1),index(1),data(4) = 15. */
	static const uint8_t want[] = {
		0x03, 0x08, 0x00,       /* STANDARD|SECONDARY, orderLength 21-13=8 */
		0xB1, 0x01,             /* extraFlags: id1 | bpp32(6<<3) | flags3<<7 */
		0x04,                   /* orderType UNCOMPRESSED_V2 */
		0x88, 0x77, 0x66, 0x55, /* key1 (low 32) */
		0x44, 0x33, 0x22, 0x11, /* key2 (high 32) */
		0x40,                   /* width 64 (2-byte unsigned, 1-byte form) */
		0x04,                   /* length 4 (4-byte unsigned, 1-byte form) */
		0x0A,                   /* cacheIndex 10 */
		'D', 'A', 'T', 'A'
	};

	memset(&cb, 0, sizeof cb);
	cb.cache_id = 1;
	cb.cache_index = 10;
	cb.bpp = 32;
	cb.width = 64; cb.height = 64;        /* square -> height not emitted */
	cb.key = 0x1122334455667788ULL;
	cb.compressed = 0;
	cb.data = data; cb.len = sizeof data;
	n = rdp_order_build_cache_bitmap_v2(out, sizeof out, &cb);
	if (n != (ssize_t)sizeof want) FAIL("cb len %zd", (ssize_t)n);
	if (memcmp(out, want, sizeof want) != 0) FAIL("cb bytes");
}

static void
test_cache_bitmap_varint(void)
{
	uint8_t out[64];
	struct rdp_cache_bitmap cb;
	uint8_t data[10];
	ssize_t n;

	memset(data, 0xEE, sizeof data);
	memset(&cb, 0, sizeof cb);
	cb.cache_id = 0;
	cb.cache_index = 256;          /* 2-byte form: 0x81 0x00 */
	cb.bpp = 16;                   /* id 4 */
	cb.width = 300;                /* 2-byte form: 0x81 0x2C */
	cb.height = 200;               /* non-square -> 2-byte form 0x80 0xC8 */
	cb.key = 0;
	cb.compressed = 1;             /* COMPRESSED_V2, NO_BITMAP_COMPRESSION_HDR */
	cb.data = data; cb.len = sizeof data;
	n = rdp_order_build_cache_bitmap_v2(out, sizeof out, &cb);
	/* 6 + key(8) + width(2) + height(2) + length(1) + index(2) + data(10) = 31 */
	if (n != 31) FAIL("cb varint len %zd", (ssize_t)n);
	if (out[0] != 0x03) FAIL("cb varint control");
	if (out[1] != 18 || out[2] != 0) FAIL("cb varint orderLength");  /* 31-13 */
	if (out[5] != RDP_ORDER_TYPE_CACHE_BITMAP_COMPRESSED_V2)
		FAIL("cb varint order type");
	/* extraFlags: cacheId 0 | bpp16(4<<3=0x20) | flags(PERSIST|NOHDR=0x0A)<<7 */
	if (out[3] != 0x20 || out[4] != 0x05) FAIL("cb varint extraFlags");
	if (out[14] != 0x81 || out[15] != 0x2C) FAIL("cb varint width");
	if (out[16] != 0x80 || out[17] != 0xC8) FAIL("cb varint height");
	if (out[18] != 0x0A) FAIL("cb varint length");
	if (out[19] != 0x81 || out[20] != 0x00) FAIL("cb varint index");

	/* A bad bpp and a too-small buffer are rejected. */
	cb.bpp = 12;
	if (rdp_order_build_cache_bitmap_v2(out, sizeof out, &cb) != -1)
		FAIL("cb bad bpp accepted");
	cb.bpp = 16;
	if (rdp_order_build_cache_bitmap_v2(out, 8, &cb) != -1)
		FAIL("cb small cap accepted");
}

int
main(void)
{
	test_memblt();
	test_cache_bitmap_square();
	test_cache_bitmap_varint();
	(void)printf("order_test: all ok\n");
	return 0;
}
