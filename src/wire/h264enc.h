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
 * h264enc.h -- thin wrapper around libx264 for RDPGFX AVC420.
 *
 * Configured for low-latency RDP: ultrafast preset, zerolatency
 * tune, single thread, Annex B NAL output, no B-frames, keyframe
 * every 60 frames or on demand (see rdp_h264_force_idr).
 */

#ifndef RDP_H264ENC_H
#define RDP_H264ENC_H

#include <stddef.h>
#include <stdint.h>

struct rdp_h264;

/* Open an encoder for the given frame geometry.  Returns NULL on
 * failure (missing libx264 at runtime, bad geometry, etc.). */
struct rdp_h264 *rdp_h264_open(int width, int height);

/* Re-open at a new geometry (e.g., on dynamic resize).  Returns 0
 * on success. */
int rdp_h264_resize(struct rdp_h264 *e, int width, int height);

/* Encoded geometry, rounded down to even (H.264 4:2:0 needs even
 * dimensions).  Use these for the RDPGFX AVC420 destRect/regionRect so
 * the surface region matches the H.264 frame. */
void rdp_h264_dims(const struct rdp_h264 *e, int *w, int *h);

/* Force the next encoded frame to be an IDR keyframe.  Use on a client
 * resync (e.g. a freshly created RDPGFX surface) so recovery does not
 * have to wait for the periodic keyframe interval. */
void rdp_h264_force_idr(struct rdp_h264 *e);

/* Set the peak bitrate cap (kbps) used by encoders opened afterwards;
 * pass a value derived from network auto-detection, or 0 for the fixed
 * default.  Applies to both AVC420 and the AVC444 sub-streams. */
void rdp_h264_set_target_kbps(int kbps);

/* Encode one frame.  `bgr` is width*height*3 bytes, top-down,
 * packed BGR (the same format rdp-session sends).  On success the
 * encoded H.264 bitstream is in `*out_buf` / `*out_len`; the
 * pointer is valid until the next call to encode or close.
 * `*is_keyframe` is set to 1 if the frame is an IDR. */
int rdp_h264_encode(struct rdp_h264 *e,
		const uint8_t *bgr, int width, int height,
		const uint8_t **out_buf, size_t *out_len,
		int *is_keyframe);

/* Encode a caller-supplied YUV420 image.  `y` is stride_y*height bytes,
 * `u`/`v` are stride_c*(height/2) bytes, all at the encoder's geometry
 * (see rdp_h264_dims).  The caller retains ownership of the planes.
 * Used by the AVC444 encoder to drive its two sub-streams.  Output is in
 * `*out_buf`/`*out_len`, valid until the next encode or close on `e`. */
int rdp_h264_encode_planar(struct rdp_h264 *e,
		uint8_t *y, uint8_t *u, uint8_t *v,
		int stride_y, int stride_c,
		const uint8_t **out_buf, size_t *out_len,
		int *is_keyframe);

void rdp_h264_close(struct rdp_h264 *e);

#endif /* RDP_H264ENC_H */
