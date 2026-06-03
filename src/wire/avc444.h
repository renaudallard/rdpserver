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
 * avc444.h -- RDPGFX AVC444 (YUV 4:4:4) H.264 encoder.
 *
 * AVC444 (MS-RDPEGFX codecId 0x000E) carries full-resolution chroma by
 * encoding two YUV420 H.264 sub-streams per frame: a "main" view holding
 * the luma and the even-row/even-col chroma, and an "auxiliary" view
 * holding the chroma samples the main view subsamples away.  The client
 * recombines them into YUV444, so colored text and thin high-contrast
 * edges stay sharp where AVC420's 4:2:0 chroma blurs them.
 */

#ifndef RDP_AVC444_H
#define RDP_AVC444_H

#include <stddef.h>
#include <stdint.h>

struct rdp_avc444;

/* Open an AVC444 encoder for the given desktop geometry.  Both H.264
 * sub-streams are encoded at the next multiple of 16 (MS-RDPEGFX requires
 * 16x16-aligned AVC bitmaps; the aux luma's 16-row chroma packing fills
 * exactly at that alignment).  Returns NULL on failure. */
struct rdp_avc444 *rdp_avc444_open(int width, int height);

/* Re-open at a new geometry (dynamic resize).  Returns 0 on success. */
int rdp_avc444_resize(struct rdp_avc444 *a, int width, int height);

/* Desktop geometry to use for the RDPGFX destRect/regionRect.  This is
 * the requested size, not the 16-aligned encode size, so non-aligned
 * desktops keep full resolution (the padded edge pixels are decoded but
 * never mapped onto the surface). */
void rdp_avc444_dims(const struct rdp_avc444 *a, int *w, int *h);

/* Force the next encoded frame on both sub-streams to be an IDR. */
void rdp_avc444_force_idr(struct rdp_avc444 *a);

/* Encode one BGR24 top-down frame (src_w*src_h*3 bytes, row stride
 * src_w*3).  On success the two H.264 sub-streams are returned: the main
 * (luma) view in main_buf/main_len and the auxiliary (chroma) view in
 * aux_buf/aux_len.  Both pointers are valid until the next encode or
 * close.  is_keyframe is set to 1 when the frame is an IDR.  Returns 0 on
 * success, -1 on error.  A zero-length sub-stream (the encoder produced no
 * output this frame) yields a zero main_len/aux_len and returns 0. */
int rdp_avc444_encode(struct rdp_avc444 *a,
		const uint8_t *bgr, int src_w, int src_h,
		const uint8_t **main_buf, size_t *main_len,
		const uint8_t **aux_buf, size_t *aux_len,
		int *is_keyframe);

void rdp_avc444_close(struct rdp_avc444 *a);

/* Pack a BGR24 top-down image into the six AVC444 v1 YUV420 planes at the
 * 16-aligned geometry w16 x h16 (both multiples of 16).  Source reads are
 * clamped to [0,src_w) x [0,src_h) so the padding region replicates the
 * edge pixels.  Plane layout (MS-RDPEGFX 3.3.8.3.2, "main" + "aux"):
 *   y1: main luma,        w16 x h16
 *   u1,v1: main chroma,   (w16/2) x (h16/2)  -- 2x2 box average
 *   y2: aux luma,         w16 x h16          -- odd chroma rows, 16-row blocks
 *   u2,v2: aux chroma,    (w16/2) x (h16/2)  -- even-row odd-col chroma
 * Exposed (non-static) so the wire-format regression test can verify the
 * exact sample placement. */
void rdp_avc444_pack(const uint8_t *bgr, int src_w, int src_h,
		int w16, int h16,
		uint8_t *y1, uint8_t *u1, uint8_t *v1,
		uint8_t *y2, uint8_t *u2, uint8_t *v2);

#endif /* RDP_AVC444_H */
