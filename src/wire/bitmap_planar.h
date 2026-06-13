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
 * bitmap_planar.h -- MS-RDPEGDI RDP6.0 planar bitmap compression.
 *
 * The planar codec is the compression a 32bpp RDP client expects for the
 * legacy bitmap path; it splits a tile into separate R, G and B colour
 * planes, scanline-delta-encodes each, and run-length compresses the
 * deltas.  This encoder produces the simple RGB, no-alpha (NA),
 * no-colour-loss form (FormatHeader 0x30), which decodes to opaque 32bpp
 * pixels.
 *
 * It is NOT wired into the output path: rdpd demands 24bpp in its Bitmap
 * capability, so well-behaved clients confirm 24bpp and receive interleaved
 * RLE; the only clients that request 32bpp are GPU-less Microsoft ones,
 * which reject compressed bitmaps once they have fallen back from the GFX
 * channel.  The codec is kept (and round-trip tested) for a future 32bpp
 * output mode, mirroring the unwired RFX progressive encoder.
 */

#ifndef RDP_BITMAP_PLANAR_H
#define RDP_BITMAP_PLANAR_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>

/* Compress a width x height tile of 24bpp packed BGR pixels (top-down,
 * stride width*3) into the RDP6 planar stream (FormatHeader + RLE R, G, B
 * planes, no alpha).  Writes the stream into dst (cap bytes) and the length
 * into *out_len.  Returns 0 on success, -1 on overflow or invalid size
 * (width/height 0 or > 64).  The caller compares *out_len against the raw
 * size and sends the smaller form. */
int rdp_bitmap_planar_compress_24(uint8_t *dst, size_t cap, size_t *out_len,
		const uint8_t *src, uint32_t width, uint32_t height);

/* Decode a planar stream (as produced by the encoder above: RGB, NA, RLE or
 * raw planes) of src_len bytes into width*height*3 packed BGR pixels in dst
 * (dst_len bytes).  Returns 0 on success, -1 on malformed input.  Exposed for
 * the round-trip regress test. */
int rdp_bitmap_planar_decompress_24(uint8_t *dst, size_t dst_len,
		const uint8_t *src, size_t src_len, uint32_t width, uint32_t height);

#endif /* RDP_BITMAP_PLANAR_H */
