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
 * rdpgfx.h -- MS-RDPEGFX Graphics Pipeline PDU builders/parsers.
 */

#ifndef RDP_RDPGFX_H
#define RDP_RDPGFX_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RDPGFX_CMDID_WIRETOSURFACE_1      0x0001
#define RDPGFX_CMDID_CREATESURFACE        0x0009
#define RDPGFX_CMDID_DELETESURFACE        0x000A
#define RDPGFX_CMDID_STARTFRAME           0x000B
#define RDPGFX_CMDID_ENDFRAME             0x000C
#define RDPGFX_CMDID_FRAMEACKNOWLEDGE     0x000D
#define RDPGFX_CMDID_RESETGRAPHICS        0x000E
#define RDPGFX_CMDID_MAPSURFACETOOUTPUT   0x000F
#define RDPGFX_CMDID_CAPSADVERTISE        0x0012
#define RDPGFX_CMDID_CAPSCONFIRM          0x0013

#define RDPGFX_CAPVERSION_81              0x00080105
#define RDPGFX_CAPVERSION_10              0x000A0002

#define RDPGFX_CODECID_CAPROGRESSIVE      0x0009
#define RDPGFX_CODECID_AVC420             0x000B
#define RDPGFX_CODECID_CAPROGRESSIVE_V2   0x000C

#define RDPGFX_PIXELFORMAT_XRGB_8888     0x20
#define RDPGFX_PIXELFORMAT_ARGB_8888     0x21

#define RDPGFX_HEADER_SIZE 8

#define RDPGFX_CAPS_FLAG_AVC420_ENABLED   0x00000010u
#define RDPGFX_CAPS_FLAG_AVC_DISABLED     0x00000020u

#define RDPGFX_MAX_CAPSETS 16

enum rdpgfx_codec {
	RDPGFX_CODEC_NONE = 0,
	RDPGFX_CODEC_AVC420,
	RDPGFX_CODEC_CAPROGRESSIVE,
};

struct rdpgfx_capset {
	uint32_t version;
	uint32_t length;
	uint32_t flags;
};

struct rdpgfx_caps_advertise {
	uint16_t count;
	struct rdpgfx_capset sets[RDPGFX_MAX_CAPSETS];
};

struct rdpgfx_state {
	int      active;         /* 1 after CapsConfirm sent */
	int      surface_created;/* 1 after ResetGraphics+CreateSurface */
	int      caps_received;  /* 1 after client caps advertise */
	int      dv_chan_id;     /* DRDYNVC channel ID for GFX */
	enum rdpgfx_codec codec;
	uint16_t surface_id;
	uint32_t frame_id;
	uint32_t last_ack_frame;
	uint32_t queue_depth;
	uint16_t desktop_w;
	uint16_t desktop_h;
};

/* Parse RDPGFX_CMDID_CAPSADVERTISE into structured output. */
int rdp_rdpgfx_parse_caps_advertise(const uint8_t *pdu, size_t len,
		struct rdpgfx_caps_advertise *out);

/* Select best GFX codec from client's advertise.
 * Returns 0 on success (out_version/out_flags/out_codec set), -1 if no GFX. */
int rdp_rdpgfx_select_caps(const struct rdpgfx_caps_advertise *adv,
		uint32_t *out_version, uint32_t *out_flags,
		enum rdpgfx_codec *out_codec);

/* Build RDPGFX_CMDID_CAPSCONFIRM with specified version and flags. */
ssize_t rdp_rdpgfx_build_caps_confirm(uint8_t *out, size_t cap,
		uint32_t version, uint32_t flags);

/* Parse RDPGFX_CMDID_FRAMEACKNOWLEDGE. */
int rdp_rdpgfx_parse_frame_ack(const uint8_t *pdu, size_t len,
		uint32_t *queue_depth, uint32_t *frame_id,
		uint32_t *total_decoded);

/* Build RDPGFX_CMDID_RESETGRAPHICS. */
ssize_t rdp_rdpgfx_build_reset(uint8_t *out, size_t cap,
		uint16_t w, uint16_t h);

/* Build RDPGFX_CMDID_CREATESURFACE + MAPSURFACETOOUTPUT. */
ssize_t rdp_rdpgfx_build_create_surface(uint8_t *out, size_t cap,
		uint16_t surface_id, uint16_t w, uint16_t h);

ssize_t rdp_rdpgfx_build_map_surface(uint8_t *out, size_t cap,
		uint16_t surface_id, uint16_t w, uint16_t h);

/* Build StartFrame + WireToSurface1 (AVC420) + EndFrame. */
ssize_t rdp_rdpgfx_build_avc420_frame(uint8_t *out, size_t cap,
		uint16_t surface_id, uint32_t frame_id,
		uint16_t w, uint16_t h,
		const uint8_t *h264_data, size_t h264_len);

#endif /* RDP_RDPGFX_H */
