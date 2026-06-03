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
 * avc444.c -- RDPGFX AVC444 (YUV 4:4:4) encoder over two H.264 streams.
 *
 * The frame is converted to full-resolution YUV and split into two
 * YUV420 sub-frames per MS-RDPEGFX 3.3.8.3.2: a "main" view (luma +
 * even-row/even-col chroma) and an "auxiliary" view that carries the
 * chroma the main view drops.  Each is encoded as its own H.264 stream;
 * the client recombines them into YUV444.  The BT.601 coefficients match
 * h264enc.c's AVC420 path so colours are identical between the two
 * codecs.
 */

#include "avc444.h"

#include "h264enc.h"

#include <stdlib.h>
#include <string.h>

struct rdp_avc444 {
	struct rdp_h264 *main;   /* luma sub-stream (main YUV420 view) */
	struct rdp_h264 *aux;    /* chroma sub-stream (auxiliary view) */
	int      req_w, req_h;   /* desktop size, for destRect/regionRect */
	int      w16, h16;       /* 16-aligned encode geometry */
	uint8_t *planes;         /* single allocation, sliced into six planes */
	uint8_t *y1, *u1, *v1;   /* main:  luma w16xh16, chroma (w16/2)x(h16/2) */
	uint8_t *y2, *u2, *v2;   /* aux:   luma w16xh16, chroma (w16/2)x(h16/2) */
};

/* Studio-swing BT.601, identical to h264enc.c bgr_to_yuv420.  Loop
 * indices are never negative, so only the upper bound is clamped (the
 * padding region replicates the right/bottom edge pixels). */
static uint8_t
luma_at(const uint8_t *bgr, int sw, int sh, int x, int y)
{
	int b, g, r, yv;
	const uint8_t *p;
	if (x >= sw) x = sw - 1;
	if (y >= sh) y = sh - 1;
	p = bgr + ((size_t)y * sw + x) * 3;
	b = p[0]; g = p[1]; r = p[2];
	yv = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
	return (uint8_t)(yv > 255 ? 255 : yv);
}

static void
chroma_at(const uint8_t *bgr, int sw, int sh, int x, int y,
		uint8_t *u, uint8_t *v)
{
	int b, g, r, uv, vv;
	const uint8_t *p;
	if (x >= sw) x = sw - 1;
	if (y >= sh) y = sh - 1;
	p = bgr + ((size_t)y * sw + x) * 3;
	b = p[0]; g = p[1]; r = p[2];
	uv = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
	vv = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
	*u = (uint8_t)(uv > 255 ? 255 : (uv < 0 ? 0 : uv));
	*v = (uint8_t)(vv > 255 ? 255 : (vv < 0 ? 0 : vv));
}

void
rdp_avc444_pack(const uint8_t *bgr, int src_w, int src_h,
		int w16, int h16,
		uint8_t *y1, uint8_t *u1, uint8_t *v1,
		uint8_t *y2, uint8_t *u2, uint8_t *v2)
{
	int cw = w16 / 2, ch = h16 / 2;
	int x, y, cx, cy, hy;

	/* B1: main luma = full-resolution Y. */
	for (y = 0; y < h16; y++)
		for (x = 0; x < w16; x++)
			y1[(size_t)y * w16 + x] =
				luma_at(bgr, src_w, src_h, x, y);

	/* B2/B3: main chroma = 2x2 box average.  The decoder reconstructs
	 * the dropped even-col/even-row sample from this average and the
	 * three neighbours carried in the aux view, so the average (not the
	 * bare top-left sample) is what keeps that reconstruction faithful. */
	for (cy = 0; cy < ch; cy++) {
		for (cx = 0; cx < cw; cx++) {
			int x0 = 2 * cx, y0 = 2 * cy;
			uint8_t ua, va, ub, vb, uc, vc, ud, vd;
			chroma_at(bgr, src_w, src_h, x0, y0, &ua, &va);
			chroma_at(bgr, src_w, src_h, x0 + 1, y0, &ub, &vb);
			chroma_at(bgr, src_w, src_h, x0, y0 + 1, &uc, &vc);
			chroma_at(bgr, src_w, src_h, x0 + 1, y0 + 1, &ud, &vd);
			u1[(size_t)cy * cw + cx] =
				(uint8_t)(((int)ua + ub + uc + ud) / 4);
			v1[(size_t)cy * cw + cx] =
				(uint8_t)(((int)va + vb + vc + vd) / 4);
		}
	}

	/* B45: aux luma packs every odd source row of the full-resolution
	 * chroma, interleaved in 16-row blocks -- the top 8 rows of each
	 * block hold U odd rows, the next 8 hold V odd rows.  With h16 a
	 * multiple of 16 the blocks fill the plane exactly. */
	for (hy = 0; hy < ch; hy++) {
		int srcy = 2 * hy + 1;
		int ru = (hy / 8) * 16 + (hy % 8);
		int rv = ru + 8;
		for (x = 0; x < w16; x++) {
			uint8_t u, v;
			chroma_at(bgr, src_w, src_h, x, srcy, &u, &v);
			y2[(size_t)ru * w16 + x] = u;
			y2[(size_t)rv * w16 + x] = v;
		}
	}

	/* B6/B7: aux chroma = even-row, odd-col chroma. */
	for (cy = 0; cy < ch; cy++) {
		for (cx = 0; cx < cw; cx++) {
			uint8_t u, v;
			chroma_at(bgr, src_w, src_h,
				2 * cx + 1, 2 * cy, &u, &v);
			u2[(size_t)cy * cw + cx] = u;
			v2[(size_t)cy * cw + cx] = v;
		}
	}
}

static int
setup(struct rdp_avc444 *a, int w, int h)
{
	int w16 = (w + 15) & ~15;
	int h16 = (h + 15) & ~15;
	size_t ysz = (size_t)w16 * h16;
	size_t csz = (size_t)(w16 / 2) * (h16 / 2);
	int mw = 0, mh = 0;

	rdp_h264_close(a->main);
	rdp_h264_close(a->aux);
	a->main = NULL;
	a->aux = NULL;
	free(a->planes);
	a->planes = NULL;
	/* Clear the slice pointers too: they aliased into the freed buffer
	 * and are only re-pointed after the malloc below succeeds.  If this
	 * setup fails partway, leaving them dangling would let a later encode
	 * write through freed memory. */
	a->y1 = a->u1 = a->v1 = a->y2 = a->u2 = a->v2 = NULL;

	a->main = rdp_h264_open(w16, h16);
	a->aux = rdp_h264_open(w16, h16);
	if (a->main == NULL || a->aux == NULL)
		return -1;
	/* The 16-aligned dims are even, so the encoder must not have
	 * rounded them down; bail if it did rather than feed mismatched
	 * planes. */
	rdp_h264_dims(a->main, &mw, &mh);
	if (mw != w16 || mh != h16)
		return -1;

	a->planes = malloc(2 * ysz + 4 * csz);
	if (a->planes == NULL)
		return -1;
	a->y1 = a->planes;
	a->u1 = a->y1 + ysz;
	a->v1 = a->u1 + csz;
	a->y2 = a->v1 + csz;
	a->u2 = a->y2 + ysz;
	a->v2 = a->u2 + csz;

	a->req_w = w;
	a->req_h = h;
	a->w16 = w16;
	a->h16 = h16;
	return 0;
}

struct rdp_avc444 *
rdp_avc444_open(int width, int height)
{
	struct rdp_avc444 *a = calloc(1, sizeof *a);
	if (a == NULL)
		return NULL;
	if (setup(a, width, height) != 0) {
		rdp_avc444_close(a);
		return NULL;
	}
	return a;
}

int
rdp_avc444_resize(struct rdp_avc444 *a, int width, int height)
{
	return setup(a, width, height);
}

void
rdp_avc444_dims(const struct rdp_avc444 *a, int *w, int *h)
{
	if (w != NULL) *w = a->req_w;
	if (h != NULL) *h = a->req_h;
}

void
rdp_avc444_force_idr(struct rdp_avc444 *a)
{
	if (a == NULL)
		return;
	rdp_h264_force_idr(a->main);
	rdp_h264_force_idr(a->aux);
}

int
rdp_avc444_encode(struct rdp_avc444 *a,
		const uint8_t *bgr, int src_w, int src_h,
		const uint8_t **main_buf, size_t *main_len,
		const uint8_t **aux_buf, size_t *aux_len,
		int *is_keyframe)
{
	int km = 0, ka = 0;

	/* A failed open or resize leaves the sub-encoders and/or the plane
	 * buffer NULL; refuse to run rather than dereference them. */
	if (a->main == NULL || a->aux == NULL || a->planes == NULL)
		return -1;
	/* The frame must cover at least the desktop; the padding region up
	 * to the 16-aligned size replicates the edge pixels. */
	if (src_w < a->req_w || src_h < a->req_h)
		return -1;

	rdp_avc444_pack(bgr, src_w, src_h, a->w16, a->h16,
		a->y1, a->u1, a->v1, a->y2, a->u2, a->v2);

	if (rdp_h264_encode_planar(a->main, a->y1, a->u1, a->v1,
		a->w16, a->w16 / 2, main_buf, main_len, &km) != 0)
		return -1;
	if (rdp_h264_encode_planar(a->aux, a->y2, a->u2, a->v2,
		a->w16, a->w16 / 2, aux_buf, aux_len, &ka) != 0)
		return -1;

	*is_keyframe = km;  /* both sub-streams force their IDR together */
	return 0;
}

void
rdp_avc444_close(struct rdp_avc444 *a)
{
	if (a == NULL)
		return;
	rdp_h264_close(a->main);
	rdp_h264_close(a->aux);
	free(a->planes);
	free(a);
}
