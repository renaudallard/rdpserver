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
 * rdpgfx.c -- RDPGFX PDU builders for AVC420 H.264 streaming.
 */

#include "rdpgfx.h"

#include "../include/rdp_log.h"
#include "../common/buf.h"

#include <string.h>

static int
put_gfx_header(struct rdp_buf *b, uint16_t cmdId, uint32_t pduLen)
{
	if (rdp_buf_put_u16le(b, cmdId) != 0) return -1;
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* flags */
	if (rdp_buf_put_u32le(b, pduLen) != 0) return -1;
	return 0;
}

static uint32_t
ld32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int
rdp_rdpgfx_parse_caps_advertise(const uint8_t *pdu, size_t len,
		struct rdpgfx_caps_advertise *out)
{
	uint16_t cmdId, cnt, i;
	size_t off;

	if (len < RDPGFX_HEADER_SIZE + 2) return -1;
	cmdId = (uint16_t)pdu[0] | ((uint16_t)pdu[1] << 8);
	if (cmdId != RDPGFX_CMDID_CAPSADVERTISE) return -1;

	cnt = (uint16_t)pdu[8] | ((uint16_t)pdu[9] << 8);
	out->count = 0;
	off = 10;
	rdp_info("rdpgfx: caps advertise, %u cap sets", (unsigned)cnt);
	for (i = 0; i < cnt && off + 8 <= len; i++) {
		uint32_t ver = ld32le(pdu + off);
		uint32_t dlen = ld32le(pdu + off + 4);
		uint32_t flags = 0;
		if (dlen >= 4 && off + 8 + 4 <= len)
			flags = ld32le(pdu + off + 8);
		rdp_info("rdpgfx:   [%u] ver=0x%08x flags=0x%08x",
			(unsigned)i, ver, flags);
		if (out->count < RDPGFX_MAX_CAPSETS) {
			out->sets[out->count].version = ver;
			out->sets[out->count].length = dlen;
			out->sets[out->count].flags = flags;
			out->count++;
		}
		off += 8 + dlen;
	}
	return 0;
}

int
rdp_rdpgfx_select_caps(const struct rdpgfx_caps_advertise *adv,
		uint32_t *out_version, uint32_t *out_flags,
		enum rdpgfx_codec *out_codec)
{
	static const uint32_t pref[] = {
		0x000A0700, 0x000A0600, 0x000A0502,
		0x000A0400, 0x000A0301, 0x000A0200,
		0x000A0100, RDPGFX_CAPVERSION_10,
	};
	uint16_t i;
	size_t p;
	int has_avc420 = 0;
	int has_v10_noavc = 0;
	int has_v8 = 0;
	uint32_t v10_avc_disabled_ver = 0;

	for (i = 0; i < adv->count; i++) {
		if (adv->sets[i].version == RDPGFX_CAPVERSION_81
		    && (adv->sets[i].flags
			& RDPGFX_CAPS_FLAG_AVC420_ENABLED))
			has_avc420 = 1;
		if (adv->sets[i].version >= RDPGFX_CAPVERSION_10
		    && (adv->sets[i].flags
			& RDPGFX_CAPS_FLAG_AVC_DISABLED)) {
			has_v10_noavc = 1;
			v10_avc_disabled_ver = adv->sets[i].version;
		}
		if (adv->sets[i].version == 0x00080004
		    || adv->sets[i].version == RDPGFX_CAPVERSION_81)
			has_v8 = 1;
	}

	/* Prefer AVC420 when v8.1 AVC420_ENABLED is advertised. */
	if (has_avc420) {
		for (p = 0; p < sizeof pref / sizeof pref[0]; p++) {
			for (i = 0; i < adv->count; i++) {
				if (adv->sets[i].version != pref[p])
					continue;
				if (adv->sets[i].flags
				    & RDPGFX_CAPS_FLAG_AVC_DISABLED)
					continue;
				*out_version = adv->sets[i].version;
				*out_flags = 0;
				*out_codec = RDPGFX_CODEC_AVC420;
				return 0;
			}
		}
		*out_version = RDPGFX_CAPVERSION_81;
		*out_flags = RDPGFX_CAPS_FLAG_AVC420_ENABLED;
		*out_codec = RDPGFX_CODEC_AVC420;
		return 0;
	}

	/*
	 * CAPROGRESSIVE is implemented and wired up but unusable for
	 * any current Microsoft RDP client.  Empirically:
	 *
	 *   mstsc (Windows 11):       confirmed v8.1 flags=0,
	 *                             confirmed v10.6 AVC_DISABLED;
	 *                             both rejected with cmd=4 close
	 *                             and 0xd06.
	 *   macOS Windows App 11.3.5: confirmed v10.3 AVC_DISABLED;
	 *                             rejected with cmd=4 close and
	 *                             0x200d.
	 *
	 * All three share the same libtermsrv connection-control
	 * code that requires AVC over GFX.  The CAPROGRESSIVE decoder
	 * is present in the binary but gated off at a higher layer.
	 * Keep the encoder code so a future non-AVC GFX client (e.g.,
	 * a test harness or a non-Microsoft client) can use it.
	 */
	(void)v10_avc_disabled_ver;
	(void)has_v10_noavc;
	(void)has_v8;
	return -1;
}

ssize_t
rdp_rdpgfx_build_caps_confirm(uint8_t *out, size_t cap,
		uint32_t version, uint32_t flags)
{
	struct rdp_buf b;
	uint32_t bodyLen = 12;
	if (cap < RDPGFX_HEADER_SIZE + bodyLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_CAPSCONFIRM,
		RDPGFX_HEADER_SIZE + bodyLen) != 0) return -1;
	if (rdp_buf_put_u32le(&b, version) != 0) return -1;
	if (rdp_buf_put_u32le(&b, 4) != 0) return -1;
	if (rdp_buf_put_u32le(&b, flags) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

int
rdp_rdpgfx_parse_frame_ack(const uint8_t *pdu, size_t len,
		uint32_t *queue_depth, uint32_t *frame_id,
		uint32_t *total_decoded)
{
	if (len < RDPGFX_HEADER_SIZE + 12) return -1;
	*queue_depth = ld32le(pdu + 8);
	*frame_id = ld32le(pdu + 12);
	*total_decoded = ld32le(pdu + 16);
	return 0;
}

ssize_t
rdp_rdpgfx_build_reset(uint8_t *out, size_t cap,
		uint16_t w, uint16_t h)
{
	struct rdp_buf b;
	/* FreeRDP expects total PDU (header+body) = 340 bytes.
	 * Body = 12 (w+h+count) + 20 (1 monitor) + 300 (pad) = 332. */
	uint32_t pduLen = 340;
	uint8_t body[332];

	memset(body, 0, sizeof body);
	if (cap < pduLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_RESETGRAPHICS, pduLen) != 0)
		return -1;
	body[0] = w & 0xff; body[1] = (w >> 8) & 0xff;
	body[4] = h & 0xff; body[5] = (h >> 8) & 0xff;
	body[8] = 1;  /* monitorCount */
	/* monitor[0]: left=0, top=0, right=w-1, bottom=h-1, flags=1 (primary) */
	body[20] = (w - 1) & 0xff; body[21] = ((w - 1) >> 8) & 0xff;
	body[24] = (h - 1) & 0xff; body[25] = ((h - 1) >> 8) & 0xff;
	body[28] = 1;  /* flags = TS_MONITOR_PRIMARY */
	if (rdp_buf_put(&b, body, sizeof body) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpgfx_build_create_surface(uint8_t *out, size_t cap,
		uint16_t surface_id, uint16_t w, uint16_t h)
{
	struct rdp_buf b;
	uint32_t pduLen = RDPGFX_HEADER_SIZE + 7;
	if (cap < pduLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_CREATESURFACE, pduLen) != 0)
		return -1;
	if (rdp_buf_put_u16le(&b, surface_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, w) != 0) return -1;
	if (rdp_buf_put_u16le(&b, h) != 0) return -1;
	if (rdp_buf_put_u8(&b, RDPGFX_PIXELFORMAT_XRGB_8888) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpgfx_build_map_surface(uint8_t *out, size_t cap,
		uint16_t surface_id, uint16_t w, uint16_t h)
{
	struct rdp_buf b;
	uint32_t pduLen = RDPGFX_HEADER_SIZE + 12;
	if (cap < pduLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_MAPSURFACETOOUTPUT,
		pduLen) != 0) return -1;
	if (rdp_buf_put_u16le(&b, surface_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;   /* reserved */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;   /* outputOriginX */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;   /* outputOriginY */
	(void)w; (void)h;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpgfx_build_avc420_frame(uint8_t *out, size_t cap,
		uint16_t surface_id, uint32_t frame_id,
		uint16_t w, uint16_t h,
		const uint8_t *h264_data, size_t h264_len)
{
	struct rdp_buf b;
	size_t off = 0;
	/* StartFrame(8+8) + WireToSurface1(8+body) + EndFrame(8+4) */
	size_t start_len = RDPGFX_HEADER_SIZE + 8;
	/* wire body: surfaceId(2)+codecId(2)+pixelFormat(1)+destRect(8)
	 * +bitmapDataLength(4)+numRegionRects(4)+rect(8)+qual(2)+data */
	size_t wire_body = 17 + 4 + 8 + 2 + h264_len;
	size_t wire_len  = RDPGFX_HEADER_SIZE + wire_body;
	size_t end_len   = RDPGFX_HEADER_SIZE + 4;
	size_t total     = start_len + wire_len + end_len;

	if (total > cap) return -1;
	rdp_buf_init(&b, out, cap);

	/* StartFrame */
	if (put_gfx_header(&b, RDPGFX_CMDID_STARTFRAME,
		(uint32_t)start_len) != 0) return -1;
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;    /* timestamp */
	if (rdp_buf_put_u32le(&b, frame_id) != 0) return -1;

	/* WireToSurface1 */
	if (put_gfx_header(&b, RDPGFX_CMDID_WIRETOSURFACE_1,
		(uint32_t)wire_len) != 0) return -1;
	if (rdp_buf_put_u16le(&b, surface_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, RDPGFX_CODECID_AVC420) != 0) return -1;
	if (rdp_buf_put_u8(&b, RDPGFX_PIXELFORMAT_XRGB_8888) != 0) return -1;
	/* destRect: left=0, top=0, right=w, bottom=h */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, w) != 0) return -1;
	if (rdp_buf_put_u16le(&b, h) != 0) return -1;
	/* bitmapDataLength */
	{
		uint32_t bdl = (uint32_t)(4 + 8 + 2 + h264_len);
		if (rdp_buf_put_u32le(&b, bdl) != 0) return -1;
	}
	/* RFX_AVC420_BITMAP_STREAM: meta + data */
	/* numRegionRects = 1 */
	if (rdp_buf_put_u32le(&b, 1) != 0) return -1;
	/* regionRect: x=0, y=0, width=w, height=h */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, w) != 0) return -1;
	if (rdp_buf_put_u16le(&b, h) != 0) return -1;
	/* qpVal: qp=22 (bits 0-5), reserved=0 (bit 6), progressive=0 (bit 7) */
	if (rdp_buf_put_u8(&b, 22) != 0) return -1;
	/* qualityVal: 100 (best quality) */
	if (rdp_buf_put_u8(&b, 100) != 0) return -1;
	/* H.264 NAL data */
	if (rdp_buf_put(&b, h264_data, h264_len) != 0) return -1;

	/* EndFrame */
	if (put_gfx_header(&b, RDPGFX_CMDID_ENDFRAME,
		(uint32_t)end_len) != 0) return -1;
	if (rdp_buf_put_u32le(&b, frame_id) != 0) return -1;

	(void)off;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpgfx_build_progressive_frame(uint8_t *out, size_t cap,
		uint16_t surface_id, uint32_t frame_id,
		const uint8_t *prog_data, size_t prog_len)
{
	struct rdp_buf b;
	/* StartFrame(8+8) + WireToSurface2(8+body) + EndFrame(8+4)
	 * Wire body: surfaceId(2)+codecId(2)+codecContextId(4)
	 *            +pixelFormat(1)+bitmapDataLength(4)+data */
	size_t start_len = RDPGFX_HEADER_SIZE + 8;
	size_t wire_body = 2 + 2 + 4 + 1 + 4 + prog_len;
	size_t wire_len  = RDPGFX_HEADER_SIZE + wire_body;
	size_t end_len   = RDPGFX_HEADER_SIZE + 4;
	size_t total     = start_len + wire_len + end_len;

	if (total > cap) return -1;
	rdp_buf_init(&b, out, cap);

	if (put_gfx_header(&b, RDPGFX_CMDID_STARTFRAME,
		(uint32_t)start_len) != 0) return -1;
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;     /* timestamp */
	if (rdp_buf_put_u32le(&b, frame_id) != 0) return -1;

	if (put_gfx_header(&b, RDPGFX_CMDID_WIRETOSURFACE_2,
		(uint32_t)wire_len) != 0) return -1;
	if (rdp_buf_put_u16le(&b, surface_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, RDPGFX_CODECID_CAPROGRESSIVE) != 0)
		return -1;
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;     /* codecContextId */
	if (rdp_buf_put_u8(&b, RDPGFX_PIXELFORMAT_XRGB_8888) != 0)
		return -1;
	if (rdp_buf_put_u32le(&b, (uint32_t)prog_len) != 0) return -1;
	if (rdp_buf_put(&b, prog_data, prog_len) != 0) return -1;

	if (put_gfx_header(&b, RDPGFX_CMDID_ENDFRAME,
		(uint32_t)end_len) != 0) return -1;
	if (rdp_buf_put_u32le(&b, frame_id) != 0) return -1;

	return (ssize_t)rdp_buf_used(&b);
}
