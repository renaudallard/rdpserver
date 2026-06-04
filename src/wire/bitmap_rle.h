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
 * bitmap_rle.h -- MS-RDPBCGR interleaved RLE bitmap compression (24 bpp).
 *
 * Compresses a 24-bpp tile (3 bytes per pixel, the RDP bitmap byte order,
 * stored top to bottom) into the interleaved run-length stream the client
 * decodes for a compressed Bitmap Update or a Cache Bitmap order.  The encoder
 * is a faithful port of the FreeRDP encoder (freerdp_bitmap_compress_24); a
 * round-trip test against an independent decoder validates the output.
 */
#ifndef RDP_BITMAP_RLE_H
#define RDP_BITMAP_RLE_H

#include <stddef.h>
#include <stdint.h>

/* Compress a width x height 24-bpp tile (src is 3*width*height bytes) into the
 * interleaved RLE stream in dst (cap bytes); *out_len receives the length.
 * width and height must be 1..64.  Returns 0 on success, -1 on bad dimensions
 * or if the compressed output would exceed cap. */
int rdp_bitmap_rle_compress_24(uint8_t *dst, size_t cap, size_t *out_len,
    const uint8_t *src, uint32_t width, uint32_t height);

/* Decompress an interleaved RLE 24-bpp stream back to width x height pixels
 * (dst is 3*width*height bytes, top to bottom).  Returns 0 on success, -1 on a
 * malformed stream or a size mismatch.  Used by the round-trip test and as a
 * defensive self-check. */
int rdp_bitmap_rle_decompress_24(uint8_t *dst, size_t dst_len,
    const uint8_t *src, size_t src_len, uint32_t width, uint32_t height);

#endif /* RDP_BITMAP_RLE_H */
