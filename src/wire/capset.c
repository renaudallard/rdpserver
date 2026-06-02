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
 * capset.c -- Demand Active / Confirm Active builders/parsers.
 *
 * Wire shape of the Demand Active "shareControlData" portion that
 * we generate (MS-RDPBCGR 2.2.1.13.1.1):
 *
 *   uint32  shareId            (LE)
 *   uint16  lengthSourceDescriptor    (LE)
 *   uint16  lengthCombinedCapabilities (LE)
 *   bytes   sourceDescriptor   ("RDP\0" or similar)
 *   uint16  numberCapabilities (LE)
 *   uint16  pad2octets         (0)
 *   ...     capability sets ...
 *   uint32  sessionId          (0)
 */

#include "capset.h"

#include "../common/buf.h"

#include <string.h>

/* Each cap-set helper appends one TLV.  Returns 0 on success.  Caller
 * is responsible for budget. */
static int
cap_open(struct rdp_buf *b, uint16_t type, size_t **len_ptr_out,
		uint8_t **hdr_out)
{
	uint8_t *hdr = rdp_buf_reserve(b, 4);
	if (hdr == NULL) return -1;
	hdr[0] = (uint8_t)(type & 0xff);
	hdr[1] = (uint8_t)((type >> 8) & 0xff);
	*hdr_out = hdr;
	*len_ptr_out = NULL;
	return 0;
}

static void
cap_close(struct rdp_buf *b, uint8_t *hdr, size_t header_used)
{
	uint16_t sz = (uint16_t)(rdp_buf_used(b) - header_used + 4);
	hdr[2] = (uint8_t)(sz & 0xff);
	hdr[3] = (uint8_t)((sz >> 8) & 0xff);
}

static int
write_cap_general(struct rdp_buf *b)
{
	uint8_t *hdr; size_t *p; size_t start;
	if (cap_open(b, RDP_CAP_GENERAL, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	if (rdp_buf_put_u16le(b, 4) != 0) return -1;   /* osMajorType = OSMAJORTYPE_UNIX */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* osMinorType */
	if (rdp_buf_put_u16le(b, 0x0200) != 0) return -1; /* protocolVersion */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* pad2 */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* compressionTypes */
	if (rdp_buf_put_u16le(b,
		RDP_GEN_EXTRA_NO_BITMAP_COMPRESSION_HDR
		| RDP_GEN_EXTRA_LONG_CREDENTIALS
		| RDP_GEN_EXTRA_AUTORECONNECT
		| RDP_GEN_EXTRA_FASTPATH_OUTPUT) != 0) return -1;
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* updateCapabilityFlag */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* remoteUnshareFlag */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;   /* generalCompressionLevel */
	if (rdp_buf_put_u8(b, 1) != 0) return -1;       /* refreshRectSupport */
	if (rdp_buf_put_u8(b, 1) != 0) return -1;       /* suppressOutputSupport */
	cap_close(b, hdr, start);
	return 0;
}

static int
write_cap_bitmap(struct rdp_buf *b, uint16_t w, uint16_t h)
{
	uint8_t *hdr; size_t *p; size_t start;
	if (cap_open(b, RDP_CAP_BITMAP, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	if (rdp_buf_put_u16le(b, 24) != 0) return -1;       /* preferredBpp */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;        /* receive1BitPerPixel */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;        /* receive4BitsPerPixel */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;        /* receive8BitsPerPixel */
	if (rdp_buf_put_u16le(b, w) != 0) return -1;
	if (rdp_buf_put_u16le(b, h) != 0) return -1;
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;        /* pad2 */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;        /* desktopResizeFlag */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;        /* bitmapCompressionFlag */
	if (rdp_buf_put_u8(b, 0) != 0) return -1;            /* highColorFlags */
	if (rdp_buf_put_u8(b, 1) != 0) return -1;            /* drawingFlags */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;        /* multipleRectangleSupport */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;        /* pad2 */
	cap_close(b, hdr, start);
	return 0;
}

static int
write_cap_order(struct rdp_buf *b)
{
	uint8_t *hdr; size_t *p; size_t start;
	uint8_t zero32[32] = {0};
	if (cap_open(b, RDP_CAP_ORDER, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	/* terminalDescriptor: 16 ANSI bytes (unused). */
	if (rdp_buf_put(b, zero32, 16) != 0) return -1;
	if (rdp_buf_put_u32le(b, 0) != 0) return -1;    /* pad4A */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;    /* desktopSaveXGranularity */
	if (rdp_buf_put_u16le(b, 20) != 0) return -1;   /* desktopSaveYGranularity */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* pad2A */
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;    /* maximumOrderLevel */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* numberFonts */
	if (rdp_buf_put_u16le(b, 0x0002) != 0) return -1; /* NEGOTIATE_ORDER_SUPPORT */
	/* orderSupport[32]: all zero -- we negotiate no drawing orders. */
	if (rdp_buf_put(b, zero32, 32) != 0) return -1;
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* textFlags */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* orderSupportExFlags */
	if (rdp_buf_put_u32le(b, 0) != 0) return -1;    /* pad4B */
	if (rdp_buf_put_u32le(b, 0xa1000) != 0) return -1; /* desktopSaveSize */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* pad2C */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* pad2D */
	if (rdp_buf_put_u16le(b, 0x06a1) != 0) return -1; /* textANSICodePage */
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;    /* pad2E */
	cap_close(b, hdr, start);
	return 0;
}

__attribute__((unused)) static int
write_cap_bitmapcache(struct rdp_buf *b)
{
	uint8_t *hdr; size_t *p; size_t start;
	uint8_t zero[36] = {0};
	if (cap_open(b, RDP_CAP_BITMAPCACHE, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	/* 24 bytes of pad4 followed by three (entries16, size16) pairs
	 * we leave at 0 -- effectively "no bitmap caching." */
	if (rdp_buf_put(b, zero, 36) != 0) return -1;
	cap_close(b, hdr, start);
	return 0;
}

static int
write_cap_pointer(struct rdp_buf *b)
{
	uint8_t *hdr; size_t *p; size_t start;
	if (cap_open(b, RDP_CAP_POINTER, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	if (rdp_buf_put_u16le(b, 1) != 0) return -1;     /* colorPointerFlag */
	if (rdp_buf_put_u16le(b, 16) != 0) return -1;    /* colorPointerCacheSize */
	if (rdp_buf_put_u16le(b, 20) != 0) return -1;    /* pointerCacheSize */
	cap_close(b, hdr, start);
	return 0;
}

static int
write_cap_input(struct rdp_buf *b)
{
	uint8_t *hdr; size_t *p; size_t start;
	uint8_t imeFileName[64] = {0};
	if (cap_open(b, RDP_CAP_INPUT, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	if (rdp_buf_put_u16le(b,
		RDP_INPUT_FLAG_SCANCODES
		| RDP_INPUT_FLAG_MOUSEX
		| RDP_INPUT_FLAG_FASTPATH_INPUT
		| RDP_INPUT_FLAG_FASTPATH_INPUT2
		| RDP_INPUT_FLAG_UNICODE) != 0) return -1;
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;     /* pad2 */
	if (rdp_buf_put_u32le(b, 0x0409) != 0) return -1; /* keyboardLayout */
	if (rdp_buf_put_u32le(b, 4) != 0) return -1;     /* keyboardType */
	if (rdp_buf_put_u32le(b, 0) != 0) return -1;     /* keyboardSubType */
	if (rdp_buf_put_u32le(b, 12) != 0) return -1;    /* keyboardFunctionKey */
	if (rdp_buf_put(b, imeFileName, sizeof imeFileName) != 0) return -1;
	cap_close(b, hdr, start);
	return 0;
}

static int
write_cap_simple(struct rdp_buf *b, uint16_t type, const uint8_t *body, size_t n)
{
	uint8_t *hdr; size_t *p; size_t start;
	if (cap_open(b, type, &p, &hdr) != 0) return -1;
	start = rdp_buf_used(b);
	if (n > 0 && rdp_buf_put(b, body, n) != 0) return -1;
	cap_close(b, hdr, start);
	return 0;
}

__attribute__((unused)) static int
write_cap_glyph(struct rdp_buf *b)
{
	uint8_t body[48] = {0};
	/* 10 glyph cache entries (4 bytes each = 40), one frag cache entry
	 * (4 bytes), GlyphSupportLevel u16 = 0 (NONE), pad u16. */
	return write_cap_simple(b, RDP_CAP_GLYPHCACHE, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_brush(struct rdp_buf *b)
{
	uint8_t body[4] = { 0, 0, 0, 0 }; /* brushSupportLevel = BRUSH_DEFAULT */
	return write_cap_simple(b, RDP_CAP_BRUSH, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_offscreen(struct rdp_buf *b)
{
	uint8_t body[8] = {0}; /* offscreenSupportLevel = 0 (FALSE) */
	return write_cap_simple(b, RDP_CAP_OFFSCREENCACHE, body, sizeof body);
}

static int
write_cap_share(struct rdp_buf *b)
{
	uint8_t body[4] = {0};
	/* nodeId (server channel) = 1002. */
	body[0] = 1002 & 0xff;
	body[1] = (1002 >> 8) & 0xff;
	return write_cap_simple(b, RDP_CAP_SHARE, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_sound(struct rdp_buf *b)
{
	uint8_t body[4] = {0}; /* soundFlags = 0 */
	return write_cap_simple(b, RDP_CAP_SOUND, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_font(struct rdp_buf *b)
{
	uint8_t body[4] = {0};
	body[0] = 1; /* fontSupportFlags = FONTSUPPORT_FONTLIST */
	return write_cap_simple(b, RDP_CAP_FONT, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_control(struct rdp_buf *b)
{
	uint8_t body[8] = {0};
	body[2] = 2; /* controlInterest = CONTROLPRIORITY_NEVER */
	body[4] = 2; /* detachInterest */
	return write_cap_simple(b, RDP_CAP_CONTROL, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_wa(struct rdp_buf *b)
{
	uint8_t body[8] = {0};
	return write_cap_simple(b, RDP_CAP_WINDOWACTIVATION, body, sizeof body);
}

__attribute__((unused)) static int
write_cap_colorcache(struct rdp_buf *b)
{
	uint8_t body[4] = {0};
	body[0] = 6; /* colorTableCacheSize */
	return write_cap_simple(b, RDP_CAP_COLORCACHE, body, sizeof body);
}

static int
write_cap_vc(struct rdp_buf *b)
{
	uint8_t body[8] = {0};
	/* flags = 0 (no compression), VCChunkSize = 0x1600 */
	body[4] = 0x00;
	body[5] = 0x16;
	body[6] = 0x00;
	body[7] = 0x00;
	return write_cap_simple(b, RDP_CAP_VIRTUALCHANNEL, body, sizeof body);
}

static int
write_cap_multifragment(struct rdp_buf *b)
{
	uint8_t body[4] = {0};
	/* MaxRequestSize = 0xffff. */
	body[0] = 0xff;
	body[1] = 0xff;
	return write_cap_simple(b, RDP_CAP_MULTIFRAGMENT, body, sizeof body);
}

static int
write_cap_largepointer(struct rdp_buf *b)
{
	uint8_t body[2] = { 0x01, 0x00 }; /* LARGE_POINTER_FLAG_96x96 */
	return write_cap_simple(b, RDP_CAP_LARGEPOINTER, body, sizeof body);
}

static int
write_cap_surface_commands(struct rdp_buf *b)
{
	uint8_t body[8];
	memset(body, 0, sizeof body);
	body[0] = 0x52; /* SET_SURFACE_BITS | FRAME_MARKER | STREAM_SURFACE_BITS */
	return write_cap_simple(b, RDP_CAP_SURFACECOMMANDS, body, sizeof body);
}

static int
write_cap_frame_acknowledge(struct rdp_buf *b)
{
	uint8_t body[4];
	body[0] = 2; body[1] = 0; body[2] = 0; body[3] = 0;
	return write_cap_simple(b, 0x001E, body, sizeof body);
}

ssize_t
rdp_capset_build_demand_active(uint8_t *out, size_t cap,
		uint32_t share_id, uint16_t desktop_w, uint16_t desktop_h)
{
	struct rdp_buf b, cb;
	uint8_t caps[2048];
	uint16_t cap_count = 17;
	const char *src = "RDP";

	/* Server Demand Active carries only the server-side capability
	 * sets (MS-RDPBCGR 2.2.7).  Per-channel client caps -- bitmap
	 * cache, glyph cache, brush, offscreen, sound, font, control,
	 * window activation, colour cache -- are sent by the client in
	 * Confirm Active. */
	rdp_buf_init(&cb, caps, sizeof caps);
	if (write_cap_general(&cb)   != 0) return -1;
	if (write_cap_bitmap(&cb, desktop_w, desktop_h) != 0) return -1;
	if (write_cap_order(&cb)     != 0) return -1;
	if (write_cap_pointer(&cb)   != 0) return -1;
	if (write_cap_input(&cb)     != 0) return -1;
	if (write_cap_share(&cb)     != 0) return -1;
	if (write_cap_vc(&cb)        != 0) return -1;
	if (write_cap_multifragment(&cb) != 0) return -1;
	if (write_cap_largepointer(&cb)  != 0) return -1;
	if (write_cap_surface_commands(&cb) != 0) return -1;
	if (write_cap_frame_acknowledge(&cb) != 0) return -1;
	cap_count = 11;

	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u32le(&b, share_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)(strlen(src) + 1)) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)(rdp_buf_used(&cb) + 4)) != 0)
		return -1; /* lengthCombinedCapabilities */
	if (rdp_buf_put(&b, src, strlen(src) + 1) != 0) return -1;
	if (rdp_buf_put_u16le(&b, cap_count) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put(&b, caps, rdp_buf_used(&cb)) != 0) return -1;
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;  /* sessionId */
	return (ssize_t)rdp_buf_used(&b);
}

int
rdp_capset_parse_confirm_active(const uint8_t *p, size_t len,
		uint16_t *bpp_out, uint32_t *max_request_size_out,
		uint16_t *color_ptr_out, uint16_t *large_ptr_flags_out,
		uint16_t *pointer_cache_size_out)
{
	uint16_t lenSrc, lenComb, capCount;
	size_t off = 0;

	if (len < 10) return -1;
	off += 4;  /* shareId */
	off += 2;  /* originatorId */
	lenSrc  = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8); off += 2;
	lenComb = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8); off += 2;
	if (off + lenSrc + lenComb > len) return -1;
	off += lenSrc;
	if (lenComb < 4) return -1;
	capCount = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8); off += 2;
	off += 2;  /* pad2 */
	if (bpp_out) *bpp_out = 24;
	if (max_request_size_out) *max_request_size_out = 0;
	if (color_ptr_out) *color_ptr_out = 0;
	if (large_ptr_flags_out) *large_ptr_flags_out = 0;
	if (pointer_cache_size_out) *pointer_cache_size_out = 0;
	/* Iterate caps; we just sanity-check lengths. */
	{
		size_t end = off + lenComb - 4;
		size_t i;
		uint16_t total = 0;
		for (i = 0; i < capCount && off + 4 <= end; i++) {
			uint16_t ctype = (uint16_t)p[off]
				| ((uint16_t)p[off + 1] << 8);
			uint16_t clen  = (uint16_t)p[off + 2]
				| ((uint16_t)p[off + 3] << 8);
			if (clen < 4 || off + clen > end)
				return -1;
			if (ctype == RDP_CAP_BITMAP && clen >= 4 + 2 && bpp_out)
				*bpp_out = (uint16_t)p[off + 4]
					| ((uint16_t)p[off + 5] << 8);
			if (ctype == RDP_CAP_MULTIFRAGMENT && clen >= 8
			    && max_request_size_out)
				*max_request_size_out =
					 (uint32_t)p[off + 4]
					| ((uint32_t)p[off + 5] << 8)
					| ((uint32_t)p[off + 6] << 16)
					| ((uint32_t)p[off + 7] << 24);
			if (ctype == RDP_CAP_POINTER && clen >= 4 + 2
			    && color_ptr_out)
				*color_ptr_out = (uint16_t)p[off + 4]
					| ((uint16_t)p[off + 5] << 8);          /* colorPointerFlag */
			if (ctype == RDP_CAP_POINTER && pointer_cache_size_out) {
				if (clen >= 4 + 6)
					*pointer_cache_size_out = (uint16_t)p[off + 8]
						| ((uint16_t)p[off + 9] << 8); /* pointerCacheSize */
				else if (clen >= 4 + 4)
					*pointer_cache_size_out = (uint16_t)p[off + 6]
						| ((uint16_t)p[off + 7] << 8); /* colorPointerCacheSize */
			}
			if (ctype == RDP_CAP_LARGEPOINTER && clen >= 4 + 2
			    && large_ptr_flags_out)
				*large_ptr_flags_out = (uint16_t)p[off + 4]
					| ((uint16_t)p[off + 5] << 8);          /* largePointerSupportFlags */
			off += clen;
			total++;
		}
		(void)total;
	}
	return 0;
}
