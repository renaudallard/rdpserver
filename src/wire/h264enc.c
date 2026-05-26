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
 * h264enc.c -- libx264 encoder for RDPGFX AVC420.
 */

#include "h264enc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x264.h>

struct rdp_h264 {
	x264_t       *enc;
	x264_param_t  param;
	x264_picture_t pic_in;
	x264_picture_t pic_out;
	int            width;
	int            height;
	int64_t        pts;
	/* Concatenated NAL output buffer. */
	uint8_t       *nal_buf;
	size_t         nal_cap;
};

static int
init_encoder(struct rdp_h264 *e, int w, int h)
{
	x264_param_default_preset(&e->param, "ultrafast", "zerolatency");
	e->param.i_width  = w;
	e->param.i_height = h;
	e->param.i_csp    = X264_CSP_I420;
	e->param.i_threads = 0;
	e->param.b_repeat_headers = 1;
	e->param.b_annexb = 1;
	e->param.i_keyint_max = 60;
	e->param.i_keyint_min = 60;
	e->param.i_bframe = 0;
	e->param.rc.i_rc_method = X264_RC_CRF;
	e->param.rc.f_rf_constant = 32.0f;
	e->param.rc.i_vbv_max_bitrate = 4000;
	e->param.rc.i_vbv_buffer_size = 2000;
	e->param.rc.f_rf_constant_max = 45.0f;
	e->param.i_log_level = X264_LOG_NONE;

	e->enc = x264_encoder_open(&e->param);
	if (e->enc == NULL) return -1;
	x264_picture_init(&e->pic_in);
	e->pic_in.i_type = X264_TYPE_AUTO;
	e->pic_in.img.i_csp = X264_CSP_I420;
	e->pic_in.img.i_plane = 3;
	e->width = w;
	e->height = h;
	e->pts = 0;
	return 0;
}

struct rdp_h264 *
rdp_h264_open(int width, int height)
{
	struct rdp_h264 *e = calloc(1, sizeof *e);
	if (e == NULL) return NULL;
	if (init_encoder(e, width, height) != 0) {
		free(e);
		return NULL;
	}
	return e;
}

int
rdp_h264_resize(struct rdp_h264 *e, int width, int height)
{
	if (e->enc) x264_encoder_close(e->enc);
	e->enc = NULL;
	return init_encoder(e, width, height);
}

/* BGR24 top-down -> YUV420P.  Allocates planes inside pic_in. */
static void
bgr_to_yuv420(struct rdp_h264 *e, const uint8_t *bgr, int w, int h)
{
	int x, y;
	int luma_stride = w;
	int chroma_stride = w / 2;
	size_t ysz = (size_t)w * h;
	size_t uvsz = (size_t)(w / 2) * (h / 2);
	uint8_t *Y, *U, *V;

	if (e->pic_in.img.plane[0] == NULL
	    || e->width != w || e->height != h) {
		free(e->pic_in.img.plane[0]);
		e->pic_in.img.plane[0] = malloc(ysz + uvsz * 2);
		if (e->pic_in.img.plane[0] == NULL) return;
	}
	Y = e->pic_in.img.plane[0];
	U = Y + ysz;
	V = U + uvsz;
	e->pic_in.img.plane[1] = U;
	e->pic_in.img.plane[2] = V;
	e->pic_in.img.i_stride[0] = luma_stride;
	e->pic_in.img.i_stride[1] = chroma_stride;
	e->pic_in.img.i_stride[2] = chroma_stride;

	for (y = 0; y < h; y++) {
		const uint8_t *row = bgr + (size_t)y * w * 3;
		for (x = 0; x < w; x++) {
			uint8_t b = row[x * 3 + 0];
			uint8_t g = row[x * 3 + 1];
			uint8_t r = row[x * 3 + 2];
			int yv = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
			Y[y * luma_stride + x] = (uint8_t)(yv > 255 ? 255 : yv);
			if ((x & 1) == 0 && (y & 1) == 0) {
				int uv = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
				int vv = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
				U[(y / 2) * chroma_stride + x / 2] =
					(uint8_t)(uv > 255 ? 255 : (uv < 0 ? 0 : uv));
				V[(y / 2) * chroma_stride + x / 2] =
					(uint8_t)(vv > 255 ? 255 : (vv < 0 ? 0 : vv));
			}
		}
	}
}

int
rdp_h264_encode(struct rdp_h264 *e,
		const uint8_t *bgr, int width, int height,
		const uint8_t **out_buf, size_t *out_len,
		int *is_keyframe)
{
	x264_nal_t *nals = NULL;
	int i_nals = 0;
	int frame_size;
	int i;
	size_t total = 0;

	bgr_to_yuv420(e, bgr, width, height);
	e->pic_in.i_pts = e->pts++;
	frame_size = x264_encoder_encode(e->enc, &nals, &i_nals,
		&e->pic_in, &e->pic_out);
	if (frame_size < 0) return -1;
	if (frame_size == 0 || i_nals == 0) {
		*out_buf = NULL;
		*out_len = 0;
		*is_keyframe = 0;
		return 0;
	}

	/* Concatenate NALs into a single buffer. */
	for (i = 0; i < i_nals; i++)
		total += (size_t)nals[i].i_payload;
	if (total > e->nal_cap) {
		free(e->nal_buf);
		e->nal_buf = malloc(total);
		e->nal_cap = total;
		if (e->nal_buf == NULL) return -1;
	}
	{
		size_t off = 0;
		for (i = 0; i < i_nals; i++) {
			memcpy(e->nal_buf + off, nals[i].p_payload,
				(size_t)nals[i].i_payload);
			off += (size_t)nals[i].i_payload;
		}
	}
	*out_buf = e->nal_buf;
	*out_len = total;
	*is_keyframe = (e->pic_out.b_keyframe != 0);
	return 0;
}

void
rdp_h264_close(struct rdp_h264 *e)
{
	if (e == NULL) return;
	if (e->enc) x264_encoder_close(e->enc);
	free(e->pic_in.img.plane[0]);
	free(e->nal_buf);
	free(e);
}
