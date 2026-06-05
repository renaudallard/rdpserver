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
 * capset.h -- RDP capability sets.
 *
 * Demand Active (sent by server) and Confirm Active (received from
 * client) carry an array of capability set blocks of the form:
 *
 *   uint16  capabilitySetType
 *   uint16  lengthCapability    (includes header)
 *   bytes   capabilityData
 *
 * The server-side strategy is:
 *  - Advertise EVERY mandatory cap (mstsc errors out if any of the
 *    "must be present" sets is missing).
 *  - Advertise drawing-order support as ZERO -- we only do bitmap
 *    updates in v1, no MemBlt / GlyphIndex / etc.
 *  - Advertise glyph cache support as GLYPH_SUPPORT_NONE.
 *  - Advertise no SurfaceCommands and no BitmapCodecs, so the client
 *    falls back to the legacy bitmap path.
 */

#ifndef RDP_CAPSET_H
#define RDP_CAPSET_H

#include "../include/compat.h"

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

#define RDP_CAP_GENERAL          0x0001
#define RDP_CAP_BITMAP           0x0002
#define RDP_CAP_ORDER            0x0003
#define RDP_CAP_BITMAPCACHE      0x0004
#define RDP_CAP_CONTROL          0x0005
#define RDP_CAP_WINDOWACTIVATION 0x0007
#define RDP_CAP_POINTER          0x0008
#define RDP_CAP_SHARE            0x0009
#define RDP_CAP_COLORCACHE       0x000A
#define RDP_CAP_SOUND            0x000C
#define RDP_CAP_INPUT            0x000D
#define RDP_CAP_FONT             0x000E
#define RDP_CAP_BRUSH            0x000F
#define RDP_CAP_GLYPHCACHE       0x0010
#define RDP_CAP_OFFSCREENCACHE   0x0011
#define RDP_CAP_BITMAPCACHE_HOSTSUPPORT 0x0012
/* Client-to-server only; the server never emits it, but parses it from the
 * Confirm Active to learn the client enabled its bitmap cache. */
#define RDP_CAP_BITMAPCACHE_REV2 0x0013
#define RDP_CAP_VIRTUALCHANNEL   0x0014
#define RDP_CAP_MULTIFRAGMENT    0x001A
#define RDP_CAP_LARGEPOINTER     0x001B
#define RDP_CAP_SURFACECOMMANDS  0x001C
#define RDP_CAP_BITMAPCODECS     0x001D

/* Order capability orderSupport[] index for MemBlt (MS-RDPBCGR 2.2.7.1.3). */
#define RDP_ORDER_NEG_MEMBLT_INDEX 3

/* General capability flags / extra flags. */
#define RDP_GEN_EXTRA_NO_BITMAP_COMPRESSION_HDR 0x0400
#define RDP_GEN_EXTRA_LONG_CREDENTIALS          0x0004
#define RDP_GEN_EXTRA_AUTORECONNECT             0x0008
#define RDP_GEN_EXTRA_ENC_SALTED_CHECKSUM       0x0010
#define RDP_GEN_EXTRA_FASTPATH_OUTPUT           0x0001

/* Input capability flags. */
#define RDP_INPUT_FLAG_SCANCODES       0x0001
#define RDP_INPUT_FLAG_MOUSEX          0x0004
#define RDP_INPUT_FLAG_FASTPATH_INPUT  0x0008
#define RDP_INPUT_FLAG_UNICODE         0x0010
#define RDP_INPUT_FLAG_FASTPATH_INPUT2 0x0020

/* Build a Demand Active body (after the shareControl header) into
 * out.  share_id is the per-session identifier the server chose;
 * desktop_w/h are the negotiated dimensions.  When remoteapp is nonzero
 * the RAIL and Window List capability sets are added.  When bitmap_cache is
 * nonzero the Bitmap Cache Rev2 and host-support capability sets are added and
 * the MemBlt order is advertised, so the server may use the persistent bitmap
 * cache.  Returns bytes written. */
ssize_t rdp_capset_build_demand_active(uint8_t *out, size_t cap,
		uint32_t share_id, uint16_t desktop_w, uint16_t desktop_h,
		int remoteapp, int bitmap_cache);

/* Parse a Confirm Active capability blob and extract things we care
 * about: the client's desktop bpp and, when present, the
 * MultifragmentUpdate MaxRequestSize, the Pointer colorPointerFlag, the
 * LargePointer largePointerSupportFlags and the Pointer cap's pointer
 * cache size.  bitmap_cache_ok_out is set to 1 only when the client both
 * announced MemBlt order support and sent a Bitmap Cache Rev2 cap, i.e. it
 * will accept the cached-tile drawing orders; 0 otherwise.  Any out-param may
 * be NULL.  max_request_size_out, color_ptr_out, large_ptr_flags_out,
 * pointer_cache_size_out and bitmap_cache_ok_out default to 0 when absent.
 * Returns 0 on success. */
int rdp_capset_parse_confirm_active(const uint8_t *p, size_t len,
		uint16_t *bpp_out, uint32_t *max_request_size_out,
		uint16_t *color_ptr_out, uint16_t *large_ptr_flags_out,
		uint16_t *pointer_cache_size_out, int *bitmap_cache_ok_out);

#endif /* RDP_CAPSET_H */
