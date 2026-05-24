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

int
rdp_rdpgfx_parse_caps_advertise(const uint8_t *pdu, size_t len)
{
	uint16_t cmdId;
	if (len < RDPGFX_HEADER_SIZE + 2) return -1;
	cmdId = (uint16_t)pdu[0] | ((uint16_t)pdu[1] << 8);
	if (cmdId != RDPGFX_CMDID_CAPSADVERTISE) return -1;
	{
		uint16_t cnt = (uint16_t)pdu[8] | ((uint16_t)pdu[9] << 8);
		rdp_info("rdpgfx: caps advertise, %u cap sets", (unsigned)cnt);
	}
	return 0;
}

ssize_t
rdp_rdpgfx_build_caps_confirm(uint8_t *out, size_t cap)
{
	struct rdp_buf b;
	/* CapsConfirm body: capsSet { version u32, dataLen u32, flags u32 } */
	uint32_t pduLen = RDPGFX_HEADER_SIZE + 12;
	if (cap < pduLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_CAPSCONFIRM, pduLen) != 0)
		return -1;
	if (rdp_buf_put_u32le(&b, RDPGFX_CAPVERSION_81) != 0) return -1;
	if (rdp_buf_put_u32le(&b, 4) != 0) return -1;   /* dataLen */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;   /* flags=0 */
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpgfx_build_reset(uint8_t *out, size_t cap,
		uint16_t w, uint16_t h)
{
	struct rdp_buf b;
	/* ResetGraphics: width u32, height u32, monitorCount u32,
	 * then one RDPGFX_MONITOR_DEF (left u32, top u32, right u32,
	 * bottom u32, flags u32, pad u32[5]).
	 * Total body = 12 + 40 = 52. */
	uint32_t pduLen = RDPGFX_HEADER_SIZE + 340;
	uint8_t body[340];
	memset(body, 0, sizeof body);

	if (cap < pduLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_RESETGRAPHICS, pduLen) != 0)
		return -1;
	/* width, height, monitorCount */
	body[0] = w & 0xff; body[1] = (w >> 8) & 0xff;
	body[4] = h & 0xff; body[5] = (h >> 8) & 0xff;
	body[8] = 1; /* monitorCount */
	/* monitor[0]: left=0, top=0, right=w, bottom=h */
	body[20] = w & 0xff; body[21] = (w >> 8) & 0xff;
	body[24] = h & 0xff; body[25] = (h >> 8) & 0xff;
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
		uint16_t surface_id)
{
	struct rdp_buf b;
	uint32_t pduLen = RDPGFX_HEADER_SIZE + 12;
	if (cap < pduLen) return -1;
	rdp_buf_init(&b, out, cap);
	if (put_gfx_header(&b, RDPGFX_CMDID_MAPSURFACETOOUTPUT, pduLen) != 0)
		return -1;
	if (rdp_buf_put_u16le(&b, surface_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;   /* reserved */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;   /* outputOriginX */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;   /* outputOriginY */
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
	/* StartFrame (8+8) + WireToSurface1 (8+13+meta+data) + EndFrame (8+4) */
	/* Meta: numRegionRects=1, rect(8), qualDesc(2) = 10+4 = 14 */
	size_t start_len = RDPGFX_HEADER_SIZE + 8;
	size_t wire_body = 13 + 4 + 8 + 2 + h264_len;
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
	/* qualityVal=85, progressiveVal=0 */
	if (rdp_buf_put_u8(&b, 85) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	/* H.264 NAL data */
	if (rdp_buf_put(&b, h264_data, h264_len) != 0) return -1;

	/* EndFrame */
	if (put_gfx_header(&b, RDPGFX_CMDID_ENDFRAME,
		(uint32_t)end_len) != 0) return -1;
	if (rdp_buf_put_u32le(&b, frame_id) != 0) return -1;

	(void)off;
	return (ssize_t)rdp_buf_used(&b);
}
