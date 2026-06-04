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
 * drdynvc_test.c -- regression test for DRDYNVC dynamic-channel
 * reassembly.
 *
 * The DVC transport multiplexes several dynamic channels onto one
 * static channel, so fragmented PDUs from different channels can
 * interleave on the wire.  GFX and AUDIO_INPUT must therefore keep
 * SEPARATE per-channel reassembly buffers; a single shared buffer
 * lets an interleaved AUDIO_INPUT DATA_FIRST clobber a GFX frame that
 * is still being reassembled (and vice versa).  The interleave case
 * below fails on the old shared-buffer code and passes on the fixed
 * tree.
 *
 * DVC framing used here (MS-RDPEDYC):
 *   header byte = (cmd << 4) | (sp << 2) | cbId
 *     cmd  = DRDYNVC_CMD_DATA_FIRST (2) or DRDYNVC_CMD_DATA (3)
 *     cbId = 0  -> channel id is 1 byte
 *     sp   = 0  -> (DATA_FIRST only) total length is 1 byte
 *   DATA_FIRST PDU: [hdr][chanId(1)][totalLen(1)][fragment...]
 *   DATA       PDU: [hdr][chanId(1)][fragment...]
 */

#include "../../src/channels/drdynvc.h"
#include "../../src/channels/cam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

#define GFX_CHAN     1
#define AUDIO_CHAN   3
#define CAMENUM_CHAN 5
#define CAMDEV_CHAN  6

/* Fill buf[0..n) with a channel-specific known pattern. */
static void
fill_pattern(uint8_t *buf, size_t n, uint8_t base)
{
	size_t i;
	for (i = 0; i < n; i++)
		buf[i] = (uint8_t)(base + (uint8_t)i);
}

/* Build a DATA_FIRST PDU (cbId=0, sp=0) into out; returns its length. */
static size_t
build_first(uint8_t *out, uint8_t chan, uint8_t total_len,
		const uint8_t *frag, size_t frag_len)
{
	size_t n = 0;
	out[n++] = (uint8_t)((DRDYNVC_CMD_DATA_FIRST << 4) | (0 << 2) | 0);
	out[n++] = chan;
	out[n++] = total_len;
	memcpy(out + n, frag, frag_len);
	n += frag_len;
	return n;
}

/* Build a DATA (continuation or standalone) PDU (cbId=0). */
static size_t
build_data(uint8_t *out, uint8_t chan, const uint8_t *frag, size_t frag_len)
{
	size_t n = 0;
	out[n++] = (uint8_t)((DRDYNVC_CMD_DATA << 4) | (0 << 2) | 0);
	out[n++] = chan;
	memcpy(out + n, frag, frag_len);
	n += frag_len;
	return n;
}

/*
 * The core regression: two fragmented PDUs, one per channel, whose
 * fragments interleave.  With a single shared buffer the AUDIO_INPUT
 * DATA_FIRST (step 2) overwrites the in-progress GFX frame, so the GFX
 * completion (step 3) would carry corrupted bytes / a wrong length.
 */
static void
test_interleaved_reassembly(void)
{
	struct drdynvc_state st;
	uint8_t pdu[256];
	uint8_t gfx_pat[100], audio_pat[60];
	const size_t N_g = 100, F_g = 40;   /* GFX:   40 + 60 bytes  */
	const size_t N_a = 60,  F_a = 25;   /* AUDIO: 25 + 35 bytes  */
	const uint8_t *out_data;
	size_t out_len, n;
	uint8_t resp[64];
	size_t resp_len;
	uint16_t w = 0, h = 0;
	int r;

	memset(&st, 0, sizeof st);
	st.gfx_channel_id = GFX_CHAN;
	st.audioin_channel_id = AUDIO_CHAN;

	fill_pattern(gfx_pat, N_g, 0xA0);
	fill_pattern(audio_pat, N_a, 0x50);

	/* 1. GFX DATA_FIRST, first F_g bytes -> incomplete. */
	n = build_first(pdu, GFX_CHAN, (uint8_t)N_g, gfx_pat, F_g);
	out_data = (const uint8_t *)0x1;
	out_len = 12345;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 0) FAIL("gfx first: r=%d (want 0)", r);
	if (out_data != NULL || out_len != 0)
		FAIL("gfx first set out params on incomplete");

	/* 2. AUDIO_INPUT DATA_FIRST, first F_a bytes -> incomplete.  On the
	 * old shared-buffer code this clobbers the GFX reassembly. */
	n = build_first(pdu, AUDIO_CHAN, (uint8_t)N_a, audio_pat, F_a);
	out_data = (const uint8_t *)0x1;
	out_len = 12345;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 0) FAIL("audio first: r=%d (want 0)", r);
	if (out_data != NULL || out_len != 0)
		FAIL("audio first set out params on incomplete");

	/* 3. GFX DATA continuation -> completes with the FULL GFX pattern. */
	n = build_data(pdu, GFX_CHAN, gfx_pat + F_g, N_g - F_g);
	out_data = NULL;
	out_len = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 3) FAIL("gfx complete: r=%d (want 3)", r);
	if (out_len != N_g)
		FAIL("gfx complete: len=%zu (want %zu)", out_len, N_g);
	if (out_data == NULL || memcmp(out_data, gfx_pat, N_g) != 0)
		FAIL("gfx complete: payload corrupted (shared-buffer bug)");

	/* 4. AUDIO_INPUT DATA continuation -> full AUDIO pattern. */
	n = build_data(pdu, AUDIO_CHAN, audio_pat + F_a, N_a - F_a);
	out_data = NULL;
	out_len = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 9) FAIL("audio complete: r=%d (want 9)", r);
	if (out_len != N_a)
		FAIL("audio complete: len=%zu (want %zu)", out_len, N_a);
	if (out_data == NULL || memcmp(out_data, audio_pat, N_a) != 0)
		FAIL("audio complete: payload corrupted");

	rdp_drdynvc_cleanup(&st);
}

/* Same-channel two-fragment GFX reassembly sanity (no interleave). */
static void
test_same_channel_two_fragments(void)
{
	struct drdynvc_state st;
	uint8_t pdu[256];
	uint8_t pat[120];
	const size_t N = 120, F = 70;
	const uint8_t *out_data;
	size_t out_len, n;
	uint8_t resp[64];
	size_t resp_len;
	uint16_t w = 0, h = 0;
	int r;

	memset(&st, 0, sizeof st);
	st.gfx_channel_id = GFX_CHAN;
	st.audioin_channel_id = AUDIO_CHAN;
	fill_pattern(pat, N, 0x10);

	n = build_first(pdu, GFX_CHAN, (uint8_t)N, pat, F);
	out_data = NULL; out_len = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 0) FAIL("same-chan first: r=%d (want 0)", r);

	n = build_data(pdu, GFX_CHAN, pat + F, N - F);
	out_data = NULL; out_len = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 3) FAIL("same-chan complete: r=%d (want 3)", r);
	if (out_len != N || out_data == NULL ||
	    memcmp(out_data, pat, N) != 0)
		FAIL("same-chan complete: payload mismatch");

	rdp_drdynvc_cleanup(&st);
}

/* Single (unfragmented) DATA PDU on each channel passes through. */
static void
test_single_pdu_passthrough(void)
{
	struct drdynvc_state st;
	uint8_t pdu[256];
	uint8_t gfx_pat[32], audio_pat[24];
	const uint8_t *out_data;
	size_t out_len, n;
	uint8_t resp[64];
	size_t resp_len;
	uint16_t w = 0, h = 0;
	int r;

	memset(&st, 0, sizeof st);
	st.gfx_channel_id = GFX_CHAN;
	st.audioin_channel_id = AUDIO_CHAN;
	fill_pattern(gfx_pat, sizeof gfx_pat, 0xC0);
	fill_pattern(audio_pat, sizeof audio_pat, 0x70);

	/* GFX single DATA (cmd=DATA, no FIRST). */
	n = build_data(pdu, GFX_CHAN, gfx_pat, sizeof gfx_pat);
	out_data = NULL; out_len = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 3) FAIL("gfx single: r=%d (want 3)", r);
	if (out_len != sizeof gfx_pat || out_data == NULL ||
	    memcmp(out_data, gfx_pat, sizeof gfx_pat) != 0)
		FAIL("gfx single: payload mismatch");

	/* AUDIO_INPUT single DATA. */
	n = build_data(pdu, AUDIO_CHAN, audio_pat, sizeof audio_pat);
	out_data = NULL; out_len = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &out_data, &out_len);
	if (r != 9) FAIL("audio single: r=%d (want 9)", r);
	if (out_len != sizeof audio_pat || out_data == NULL ||
	    memcmp(out_data, audio_pat, sizeof audio_pat) != 0)
		FAIL("audio single: payload mismatch");

	rdp_drdynvc_cleanup(&st);
}

/* Build a Create Response PDU (cbId=0): [hdr][chanId(1)][status(4 LE)]. */
static size_t
build_create_resp(uint8_t *out, uint8_t chan, int32_t status)
{
	size_t n = 0;
	out[n++] = (uint8_t)((DRDYNVC_CMD_CREATE << 4) | (0 << 2) | 0);
	out[n++] = chan;
	out[n++] = (uint8_t)((uint32_t)status & 0xff);
	out[n++] = (uint8_t)(((uint32_t)status >> 8) & 0xff);
	out[n++] = (uint8_t)(((uint32_t)status >> 16) & 0xff);
	out[n++] = (uint8_t)(((uint32_t)status >> 24) & 0xff);
	return n;
}

/* The camera Create Request builders: byte layout and rejection of a bad
 * (attacker-controlled) per-device channel name. */
static void
test_cam_build_create(void)
{
	struct drdynvc_state st;
	uint8_t out[300];
	size_t name_len = sizeof(CAM_ENUM_CHANNEL_NAME);
	ssize_t n;

	memset(&st, 0, sizeof st);
	n = rdp_drdynvc_build_create_cam_enum(&st, out, sizeof out);
	if (n != (ssize_t)(2 + name_len)) FAIL("cam_enum len %zd", (ssize_t)n);
	if (out[0] != ((DRDYNVC_CMD_CREATE << 4) | (2 << 2) | 0))
		FAIL("cam_enum hdr");
	if (out[1] != CAMENUM_CHAN) FAIL("cam_enum id");
	if (memcmp(out + 2, CAM_ENUM_CHANNEL_NAME, name_len) != 0)
		FAIL("cam_enum name");
	if (st.camenum_channel_id != CAMENUM_CHAN || !st.camenum_create_pending)
		FAIL("cam_enum state");

	memset(&st, 0, sizeof st);
	n = rdp_drdynvc_build_create_cam_device(&st, "cam0", 4, out, sizeof out);
	if (n != 2 + 4 + 1) FAIL("cam_dev len %zd", (ssize_t)n);
	if (out[1] != CAMDEV_CHAN) FAIL("cam_dev id");
	if (memcmp(out + 2, "cam0", 4) != 0 || out[6] != 0)
		FAIL("cam_dev name/nul");
	if (st.camdev_channel_id != CAMDEV_CHAN || !st.camdev_create_pending)
		FAIL("cam_dev state");

	/* Bad device names are rejected. */
	if (rdp_drdynvc_build_create_cam_device(&st, "cam0", 0, out, sizeof out)
	    != -1) FAIL("cam_dev empty accepted");
	if (rdp_drdynvc_build_create_cam_device(&st, NULL, 4, out, sizeof out)
	    != -1) FAIL("cam_dev null accepted");
	{
		char big[300];
		memset(big, 'x', sizeof big);
		if (rdp_drdynvc_build_create_cam_device(&st, big, sizeof big,
		    out, sizeof out) != -1) FAIL("cam_dev oversize accepted");
	}
	{
		const char emb[] = { 'a', 0, 'b', 'c' };
		if (rdp_drdynvc_build_create_cam_device(&st, emb, sizeof emb,
		    out, sizeof out) != -1) FAIL("cam_dev embedded nul accepted");
	}
	if (rdp_drdynvc_build_create_cam_device(&st, "cam0", 4, out, 5) != -1)
		FAIL("cam_dev small cap accepted");
}

/* Create Responses on the camera channels map to the right codes. */
static void
test_cam_create_response(void)
{
	struct drdynvc_state st;
	uint8_t out[300], resp[64];
	size_t resp_len, n;
	const uint8_t *od; size_t ol;
	uint16_t w = 0, h = 0;
	int r;

	memset(&st, 0, sizeof st);
	(void)rdp_drdynvc_build_create_cam_enum(&st, out, sizeof out);
	n = build_create_resp(out, CAMENUM_CHAN, 0);
	r = rdp_drdynvc_handle(&st, out, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 13) FAIL("cam_enum create r=%d (want 13)", r);
	if (st.camenum_create_pending) FAIL("cam_enum still pending");

	memset(&st, 0, sizeof st);
	(void)rdp_drdynvc_build_create_cam_device(&st, "cam0", 4, out, sizeof out);
	n = build_create_resp(out, CAMDEV_CHAN, 0);
	r = rdp_drdynvc_handle(&st, out, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 14) FAIL("cam_dev create r=%d (want 14)", r);

	/* A declined (nonzero status) device create clears the channel. */
	memset(&st, 0, sizeof st);
	(void)rdp_drdynvc_build_create_cam_device(&st, "cam0", 4, out, sizeof out);
	n = build_create_resp(out, CAMDEV_CHAN, 5);
	r = rdp_drdynvc_handle(&st, out, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 0) FAIL("cam_dev decline r=%d (want 0)", r);
	if (st.camdev_channel_id != -1) FAIL("cam_dev id not cleared");
}

/* Camera DATA passthrough, reassembly, and the per-channel-buffer guarantee. */
static void
test_cam_data(void)
{
	struct drdynvc_state st;
	uint8_t pdu[256], resp[64], pat[100];
	const size_t N = 100, F = 40;
	const uint8_t *od; size_t ol, n, resp_len;
	uint16_t w = 0, h = 0;
	int r;

	/* Single DATA on each camera channel. */
	memset(&st, 0, sizeof st);
	st.camenum_channel_id = CAMENUM_CHAN;
	st.camdev_channel_id = CAMDEV_CHAN;
	fill_pattern(pat, 32, 0x30);
	n = build_data(pdu, CAMENUM_CHAN, pat, 32);
	od = NULL; ol = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 15 || ol != 32 || od == NULL || memcmp(od, pat, 32) != 0)
		FAIL("cam_enum single data");
	n = build_data(pdu, CAMDEV_CHAN, pat, 32);
	od = NULL; ol = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 16 || ol != 32 || od == NULL || memcmp(od, pat, 32) != 0)
		FAIL("cam_dev single data");

	/* Fragmented device frame reassembles. */
	memset(&st, 0, sizeof st);
	st.camdev_channel_id = CAMDEV_CHAN;
	fill_pattern(pat, N, 0x80);
	n = build_first(pdu, CAMDEV_CHAN, (uint8_t)N, pat, F);
	od = (const uint8_t *)0x1; ol = 1;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 0) FAIL("cam_dev frag first r=%d", r);
	n = build_data(pdu, CAMDEV_CHAN, pat + F, N - F);
	od = NULL; ol = 0;
	r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp, &resp_len,
		&w, &h, &od, &ol);
	if (r != 16 || ol != N || od == NULL || memcmp(od, pat, N) != 0)
		FAIL("cam_dev frag payload");
	rdp_drdynvc_cleanup(&st);

	/* Enumerator and device fragments interleave without clobbering. */
	{
		uint8_t ep[80], dp[80];
		memset(&st, 0, sizeof st);
		st.camenum_channel_id = CAMENUM_CHAN;
		st.camdev_channel_id = CAMDEV_CHAN;
		fill_pattern(ep, 80, 0x10);
		fill_pattern(dp, 80, 0x90);
		n = build_first(pdu, CAMENUM_CHAN, 80, ep, 30);
		od = NULL; ol = 0;
		(void)rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp,
			&resp_len, &w, &h, &od, &ol);
		n = build_first(pdu, CAMDEV_CHAN, 80, dp, 30);
		od = NULL; ol = 0;
		(void)rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp,
			&resp_len, &w, &h, &od, &ol);
		n = build_data(pdu, CAMENUM_CHAN, ep + 30, 50);
		od = NULL; ol = 0;
		r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp,
			&resp_len, &w, &h, &od, &ol);
		if (r != 15 || ol != 80 || memcmp(od, ep, 80) != 0)
			FAIL("cam interleave enum corrupted");
		n = build_data(pdu, CAMDEV_CHAN, dp + 30, 50);
		od = NULL; ol = 0;
		r = rdp_drdynvc_handle(&st, pdu, n, resp, sizeof resp,
			&resp_len, &w, &h, &od, &ol);
		if (r != 16 || ol != 80 || memcmp(od, dp, 80) != 0)
			FAIL("cam interleave dev corrupted");
		rdp_drdynvc_cleanup(&st);
	}
}

int
main(void)
{
	test_same_channel_two_fragments();
	test_single_pdu_passthrough();
	test_interleaved_reassembly();
	test_cam_build_create();
	test_cam_create_response();
	test_cam_data();
	return 0;
}
