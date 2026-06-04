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
 * order.h -- RDP drawing-order encoders (MS-RDPEGDI).
 *
 * The minimal set needed for a bitmap cache: a MemBlt primary order to blit a
 * cached tile to the screen, and a Cache Bitmap Rev2 secondary order to store
 * a tile in a cache slot with a 64-bit persistent key.  Each builder writes
 * one complete order (its own header included); the caller wraps a run of them
 * in a TS_UPDATE_ORDERS / fast-path ORDERS update with a numberOrders count.
 *
 * Layout matches MS-RDPEGDI and is byte-validated against the FreeRDP encoder.
 */
#ifndef RDP_ORDER_H
#define RDP_ORDER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Order control flags (first byte of every drawing order). */
#define RDP_ORDER_STANDARD     0x01
#define RDP_ORDER_SECONDARY    0x02
#define RDP_ORDER_BOUNDS       0x04
#define RDP_ORDER_TYPE_CHANGE  0x08
#define RDP_ORDER_DELTA_COORDS 0x10

/* Primary order types. */
#define RDP_ORDER_TYPE_MEMBLT  0x0D
#define RDP_ORDER_TYPE_MEM3BLT 0x0E

/* Secondary order types. */
#define RDP_ORDER_TYPE_CACHE_BITMAP_UNCOMPRESSED_V2 0x04
#define RDP_ORDER_TYPE_CACHE_BITMAP_COMPRESSED_V2   0x05

/* Cache Bitmap Rev2 flags (packed into the secondary-order extraFlags). */
#define CBR2_HEIGHT_SAME_AS_WIDTH      0x01
#define CBR2_PERSISTENT_KEY_PRESENT    0x02
#define CBR2_NO_BITMAP_COMPRESSION_HDR 0x08
#define CBR2_DO_NOT_CACHE              0x10

/* cacheIndex sentinel that stores into the cache's waiting list. */
#define RDP_BITMAP_CACHE_WAITING_LIST_INDEX 0x7FFF

/* Common raster op. */
#define RDP_ROP_SRCCOPY 0xCC

/* A MemBlt primary order: blit the cached bitmap (cache_id, cache_index) to the
 * destination rect with raster op rop.  Coordinates are absolute, 0..65535. */
struct rdp_memblt {
	uint8_t  cache_id;
	uint16_t cache_index;
	int32_t  x, y, w, h;     /* destination rectangle */
	uint8_t  rop;
	int32_t  src_x, src_y;   /* top-left offset inside the cached bitmap */
};

/* A Cache Bitmap Rev2 secondary order: store len bytes of bitmap data into
 * (cache_id, cache_index) with a 64-bit persistent key.  bpp is 8/16/24/32.
 * When compressed is set the compressed order type is used and the optional
 * 8-byte compression header is omitted (CBR2_NO_BITMAP_COMPRESSION_HDR). */
struct rdp_cache_bitmap {
	uint8_t  cache_id;       /* 0..3 */
	uint16_t cache_index;
	uint8_t  bpp;            /* 8, 16, 24 or 32 */
	uint16_t width, height;
	uint64_t key;            /* persistent key (key1 = low 32, key2 = high 32) */
	int      compressed;
	const uint8_t *data;
	size_t   len;
};

/* Build one MemBlt order into out (cap bytes).  Returns the byte count, or -1
 * on overflow or an out-of-range coordinate. */
ssize_t rdp_order_build_memblt(uint8_t *out, size_t cap,
    const struct rdp_memblt *m);

/* Build one Cache Bitmap Rev2 order into out (cap bytes).  Returns the byte
 * count, or -1 on overflow or an unsupported bpp. */
ssize_t rdp_order_build_cache_bitmap_v2(uint8_t *out, size_t cap,
    const struct rdp_cache_bitmap *cb);

#endif /* RDP_ORDER_H */
