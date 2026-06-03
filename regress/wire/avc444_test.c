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
 * avc444_test.c -- AVC444 (YUV 4:4:4) split, wire format, and codec select.
 *
 * The split is the correctness-critical piece (a wrong index makes the
 * client render garbage), so the six output planes are checked element by
 * element against an independent reference that recomputes the full-chroma
 * YUV with the same coefficients and applies the MS-RDPEGFX 3.3.8.3.2
 * layout.  The wire builder is parsed back to confirm the RFX_AVC444
 * LC/length field and the two sub-streams, codec selection is exercised
 * for the v10.x/v8.1 cases, and a live encode confirms both sub-streams
 * come out and the resulting PDU parses.
 */

#include "../../src/wire/avc444.h"
#include "../../src/channels/rdpgfx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

/* Independent reference: the same studio-swing BT.601 used by the encoder,
 * with the source coordinates clamped so the padding region replicates the
 * edge pixels. */
static uint8_t
ref_y(const uint8_t *bgr, int sw, int sh, int x, int y)
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
ref_uv(const uint8_t *bgr, int sw, int sh, int x, int y,
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

static uint8_t *
make_image(int w, int h)
{
	uint8_t *bgr = malloc((size_t)w * h * 3);
	int x, y;
	if (bgr == NULL) FAIL("oom image");
	/* Three independently varying channels so a U/V swap or an index
	 * error in any plane changes a sample we check. */
	for (y = 0; y < h; y++) {
		for (x = 0; x < w; x++) {
			uint8_t *p = bgr + ((size_t)y * w + x) * 3;
			p[0] = (uint8_t)((x * 3 + y) & 0xff);   /* B */
			p[1] = (uint8_t)((y * 5) & 0xff);       /* G */
			p[2] = (uint8_t)((x * 7) & 0xff);       /* R */
		}
	}
	return bgr;
}

/* Verify rdp_avc444_pack places every sample where MS-RDPEGFX 3.3.8.3.2
 * says, for a source of src_w x src_h packed into w16 x h16. */
static void
test_pack(int src_w, int src_h, int w16, int h16)
{
	uint8_t *bgr = make_image(src_w, src_h);
	int cw = w16 / 2, ch = h16 / 2;
	size_t ysz = (size_t)w16 * h16, csz = (size_t)cw * ch;
	uint8_t *y1 = malloc(ysz), *u1 = malloc(csz), *v1 = malloc(csz);
	uint8_t *y2 = malloc(ysz), *u2 = malloc(csz), *v2 = malloc(csz);
	int x, y, cx, cy, hy;

	if (!y1 || !u1 || !v1 || !y2 || !u2 || !v2) FAIL("oom planes");
	rdp_avc444_pack(bgr, src_w, src_h, w16, h16, y1, u1, v1, y2, u2, v2);

	/* B1: main luma = full Y. */
	for (y = 0; y < h16; y++)
		for (x = 0; x < w16; x++)
			if (y1[(size_t)y * w16 + x]
			    != ref_y(bgr, src_w, src_h, x, y))
				FAIL("y1[%d,%d] mismatch (%dx%d->%dx%d)",
					x, y, src_w, src_h, w16, h16);

	/* B2/B3: main chroma = 2x2 box average of the full chroma. */
	for (cy = 0; cy < ch; cy++) {
		for (cx = 0; cx < cw; cx++) {
			uint8_t ua, va, ub, vb, uc, vc, ud, vd;
			int eu, ev;
			ref_uv(bgr, src_w, src_h, 2 * cx, 2 * cy, &ua, &va);
			ref_uv(bgr, src_w, src_h, 2 * cx + 1, 2 * cy, &ub, &vb);
			ref_uv(bgr, src_w, src_h, 2 * cx, 2 * cy + 1, &uc, &vc);
			ref_uv(bgr, src_w, src_h, 2 * cx + 1, 2 * cy + 1,
				&ud, &vd);
			eu = ((int)ua + ub + uc + ud) / 4;
			ev = ((int)va + vb + vc + vd) / 4;
			if (u1[(size_t)cy * cw + cx] != eu)
				FAIL("u1[%d,%d] avg mismatch", cx, cy);
			if (v1[(size_t)cy * cw + cx] != ev)
				FAIL("v1[%d,%d] avg mismatch", cx, cy);
		}
	}

	/* B6/B7: aux chroma = even-row, odd-col chroma. */
	for (cy = 0; cy < ch; cy++) {
		for (cx = 0; cx < cw; cx++) {
			uint8_t eu, ev;
			ref_uv(bgr, src_w, src_h, 2 * cx + 1, 2 * cy, &eu, &ev);
			if (u2[(size_t)cy * cw + cx] != eu)
				FAIL("u2[%d,%d] mismatch", cx, cy);
			if (v2[(size_t)cy * cw + cx] != ev)
				FAIL("v2[%d,%d] mismatch", cx, cy);
		}
	}

	/* B45: aux luma packs the odd chroma rows in 16-row blocks (8 U
	 * rows then 8 V rows). */
	for (hy = 0; hy < ch; hy++) {
		int srcy = 2 * hy + 1;
		int ru = (hy / 8) * 16 + (hy % 8);
		int rv = ru + 8;
		for (x = 0; x < w16; x++) {
			uint8_t eu, ev;
			ref_uv(bgr, src_w, src_h, x, srcy, &eu, &ev);
			if (y2[(size_t)ru * w16 + x] != eu)
				FAIL("y2 U row hy=%d x=%d mismatch", hy, x);
			if (y2[(size_t)rv * w16 + x] != ev)
				FAIL("y2 V row hy=%d x=%d mismatch", hy, x);
		}
	}

	free(bgr);
	free(y1); free(u1); free(v1); free(y2); free(u2); free(v2);
}

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Build an AVC444 frame PDU and parse it back, confirming the RFX_AVC444
 * LC/length field and the two RFX_AVC420 sub-streams. */
static void
test_wire(void)
{
	uint8_t main_data[40], aux_data[25];
	uint8_t out[512];
	ssize_t n;
	const uint8_t *p;
	uint32_t s1_len, cb, lc, len1, bdl;
	size_t i;

	for (i = 0; i < sizeof main_data; i++)
		main_data[i] = (uint8_t)(0xA0 + i);
	for (i = 0; i < sizeof aux_data; i++)
		aux_data[i] = (uint8_t)(0x10 + i);

	n = rdp_rdpgfx_build_avc444_frame(out, sizeof out, 5, 7, 1920, 1080,
		main_data, sizeof main_data, aux_data, sizeof aux_data);
	if (n <= 0) FAIL("build_avc444_frame returned %zd", (ssize_t)n);

	/* StartFrame */
	p = out;
	if (ld16(p) != RDPGFX_CMDID_STARTFRAME) FAIL("no StartFrame");
	if (ld32(p + 4) != 16) FAIL("StartFrame len");
	if (ld32(p + 12) != 7) FAIL("StartFrame frameId");
	p += 16;

	/* WireToSurface1 */
	if (ld16(p) != RDPGFX_CMDID_WIRETOSURFACE_1) FAIL("no WireToSurface1");
	{
		uint32_t wlen = ld32(p + 4);
		const uint8_t *body = p + 8;
		if (ld16(body) != 5) FAIL("surfaceId");
		if (ld16(body + 2) != RDPGFX_CODECID_AVC444)
			FAIL("codecId not AVC444 (0x%04x)", ld16(body + 2));
		/* destRect right/bottom = desktop size */
		if (ld16(body + 5 + 4) != 1920) FAIL("destRect right");
		if (ld16(body + 5 + 6) != 1080) FAIL("destRect bottom");
		bdl = ld32(body + 13);
		/* bitmapData = cb(4) + s1(14+40) + s2(14+25) */
		s1_len = 14 + (uint32_t)sizeof main_data;
		if (bdl != 4 + s1_len + 14 + (uint32_t)sizeof aux_data)
			FAIL("bitmapDataLength %u", bdl);

		/* cbAvc420EncodedBitstream1 */
		p = body + 17;
		cb = ld32(p);
		lc = (cb >> 30) & 0x3;
		len1 = cb & 0x3FFFFFFF;
		if (lc != 0) FAIL("LC=%u, expected 0 (both streams)", lc);
		if (len1 != s1_len) FAIL("stream1 length %u != %u",
			len1, s1_len);
		p += 4;

		/* stream1 metablock + main data */
		if (ld32(p) != 1) FAIL("stream1 numRegionRects");
		if (ld16(p + 4 + 4) != 1920) FAIL("stream1 rect right");
		if (ld16(p + 4 + 6) != 1080) FAIL("stream1 rect bottom");
		if (memcmp(p + 14, main_data, sizeof main_data) != 0)
			FAIL("stream1 H.264 data mismatch");
		p += s1_len;

		/* stream2 metablock + aux data */
		if (ld32(p) != 1) FAIL("stream2 numRegionRects");
		if (memcmp(p + 14, aux_data, sizeof aux_data) != 0)
			FAIL("stream2 H.264 data mismatch");
		p += 14 + sizeof aux_data;

		/* p should now sit at EndFrame, which is wlen-(8+wire_body)
		 * after body start; verify against the wire length. */
		if ((size_t)(p - (body - 8)) != wlen)
			FAIL("WireToSurface1 length mismatch");
	}

	/* EndFrame */
	if (ld16(p) != RDPGFX_CMDID_ENDFRAME) FAIL("no EndFrame");
	if (ld32(p + 8) != 7) FAIL("EndFrame frameId");
	if ((size_t)(p + 12 - out) != (size_t)n) FAIL("trailing bytes");
}

/* One capset helper for the select tests. */
static void
set_cap(struct rdpgfx_caps_advertise *adv, uint32_t ver, uint32_t flags)
{
	adv->sets[adv->count].version = ver;
	adv->sets[adv->count].length = 4;
	adv->sets[adv->count].flags = flags;
	adv->count++;
}

static void
test_select(void)
{
	struct rdpgfx_caps_advertise adv;
	uint32_t ver, flags;
	enum rdpgfx_codec codec;

	/* v10.2 without AVC_DISABLED, allow_avc444 on -> AVC444. */
	memset(&adv, 0, sizeof adv);
	set_cap(&adv, 0x000A0200, 0);
	if (rdp_rdpgfx_select_caps(&adv, &ver, &flags, &codec, 1, 0, 1) != 0)
		FAIL("select v10.2 failed");
	if (codec != RDPGFX_CODEC_AVC444) FAIL("v10.2 should pick AVC444");
	if (ver != 0x000A0200) FAIL("v10.2 version");

	/* Same client, allow_avc444 off -> AVC420. */
	if (rdp_rdpgfx_select_caps(&adv, &ver, &flags, &codec, 1, 0, 0) != 0)
		FAIL("select v10.2 (no 444) failed");
	if (codec != RDPGFX_CODEC_AVC420) FAIL("v10.2 no-444 should be AVC420");

	/* v8.1 AVC420_ENABLED: no AVC444 even with allow_avc444. */
	memset(&adv, 0, sizeof adv);
	set_cap(&adv, RDPGFX_CAPVERSION_81, RDPGFX_CAPS_FLAG_AVC420_ENABLED);
	if (rdp_rdpgfx_select_caps(&adv, &ver, &flags, &codec, 0, 0, 1) != 0)
		FAIL("select v8.1 failed");
	if (codec != RDPGFX_CODEC_AVC420) FAIL("v8.1 has no AVC444");
}

/* Open the encoder, push a frame, and confirm both sub-streams come out
 * non-empty, the first frame is a keyframe, and the wire PDU parses. */
static void
test_encode(void)
{
	struct rdp_avc444 *a;
	uint8_t *bgr, *out;
	const uint8_t *m, *x;
	size_t ml, xl, out_cap;
	int key = 0, w = 0, h = 0;
	ssize_t n;

	a = rdp_avc444_open(640, 480);
	if (a == NULL) FAIL("avc444_open");
	rdp_avc444_dims(a, &w, &h);
	if (w != 640 || h != 480) FAIL("dims %dx%d", w, h);

	bgr = make_image(640, 480);
	rdp_avc444_force_idr(a);
	if (rdp_avc444_encode(a, bgr, 640, 480, &m, &ml, &x, &xl, &key) != 0)
		FAIL("avc444_encode");
	if (m == NULL || ml == 0) FAIL("empty main stream");
	if (x == NULL || xl == 0) FAIL("empty aux stream");
	if (!key) FAIL("first frame not a keyframe");

	out_cap = ml + xl + 256;
	out = malloc(out_cap);
	if (out == NULL) FAIL("oom out");
	n = rdp_rdpgfx_build_avc444_frame(out, out_cap, 1, 1,
		(uint16_t)w, (uint16_t)h, m, ml, x, xl);
	if (n <= 0) FAIL("build from live encode failed (%zd)", (ssize_t)n);
	if (ld16(out) != RDPGFX_CMDID_STARTFRAME) FAIL("live PDU header");

	/* Resize re-tears-down and re-allocates the sub-encoders and the
	 * sliced plane buffer; encoding must still work afterwards. */
	free(bgr);
	if (rdp_avc444_resize(a, 800, 600) != 0) FAIL("avc444_resize");
	rdp_avc444_dims(a, &w, &h);
	if (w != 800 || h != 600) FAIL("dims after resize %dx%d", w, h);
	bgr = make_image(800, 600);
	rdp_avc444_force_idr(a);
	if (rdp_avc444_encode(a, bgr, 800, 600, &m, &ml, &x, &xl, &key) != 0)
		FAIL("avc444_encode after resize");
	if (m == NULL || ml == 0 || x == NULL || xl == 0)
		FAIL("empty stream after resize");

	free(out);
	free(bgr);
	rdp_avc444_close(a);
}

int
main(void)
{
	/* 16-aligned (no padding) and unaligned (edge-replicated padding). */
	test_pack(16, 16, 16, 16);
	test_pack(32, 48, 32, 48);
	test_pack(18, 18, 32, 32);
	test_pack(1, 1, 16, 16);
	test_wire();
	test_select();
	test_encode();
	(void)printf("avc444_test: all ok\n");
	return 0;
}
