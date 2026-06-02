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
 * fastpath.h -- Fast-Path Output and Input PDU encoders/decoders.
 *
 * Fast-path skips the X.224/MCS framing for performance.  Every
 * fast-path PDU is:
 *   uint8   header           (action bits + numEvents + encryption flags)
 *   uint8/16 length          (1 byte if top bit 0, else 2 bytes BE w/ top bits 10)
 *   ... events / updates
 *
 * For TLS-secured connections the encryption flags are 0.
 *
 * Output update record format:
 *   uint8   updateHeader   (low 4 bits = updateCode,
 *                            high 4 bits = fragmentation + compression flags)
 *   uint16  size           (LE)
 *   bytes   updateData
 */

#ifndef RDP_FASTPATH_H
#define RDP_FASTPATH_H

#include "../include/compat.h"

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

#define RDP_FP_ACTION_OUTPUT     0x00
#define RDP_FP_ACTION_INPUT      0x00 /* same bit field meaning */
#define RDP_FP_HEADER            0x00

#define RDP_FP_UPDATE_ORDERS       0
#define RDP_FP_UPDATE_BITMAP       1
#define RDP_FP_UPDATE_PALETTE      2
#define RDP_FP_UPDATE_SYNCHRONIZE  3
#define RDP_FP_UPDATE_SURFCMDS     4
#define RDP_FP_UPDATE_PTR_NULL     5
#define RDP_FP_UPDATE_PTR_DEFAULT  6
#define RDP_FP_UPDATE_PTR_POSITION 8
#define RDP_FP_UPDATE_COLOR        9
#define RDP_FP_UPDATE_CACHED      10
#define RDP_FP_UPDATE_POINTER     11

#define RDP_FP_FRAGMENT_SINGLE     0
#define RDP_FP_FRAGMENT_LAST       1
#define RDP_FP_FRAGMENT_FIRST      2
#define RDP_FP_FRAGMENT_NEXT       3

/* A fast-path PDU length is carried in a 15-bit determinant, so the
 * absolute ceiling is 0x7FFF.  We cap our own output at 0x3FFF to stay
 * comfortably under that and leave room for the variable header.  The
 * safe fragment size is the largest update body slice we will emit per
 * fragment when a single update would not fit. */
#define RDP_FP_MAX_PACKET_SIZE     0x3FFF
#define RDP_FP_FRAGMENT_SAFE_SIZE  0x3F80

#define RDP_FP_INPUT_SCANCODE      0
#define RDP_FP_INPUT_MOUSE         1
#define RDP_FP_INPUT_MOUSEX        2
#define RDP_FP_INPUT_SYNC          3
#define RDP_FP_INPUT_UNICODE       4

/* Build a fast-path output PDU with a single update of the given
 * type, carrying body[0..body_len) as the updateData.  Returns total
 * wire bytes written. */
ssize_t rdp_fp_build_update(uint8_t *out, size_t cap,
		uint8_t update_type, const void *body, size_t body_len);

/* Like rdp_fp_build_update but lets the caller set the fragmentation
 * flag (RDP_FP_FRAGMENT_SINGLE / FIRST / NEXT / LAST) so an oversized
 * update body can be sliced across several fast-path PDUs.  Returns
 * total wire bytes written, or -1 if it would not fit. */
ssize_t rdp_fp_build_update_frag(uint8_t *out, size_t cap,
		uint8_t update_type, uint8_t fragment,
		const void *body, size_t body_len);

/* Assemble a bare TS_UPDATE_BITMAP body (no fast-path wrapper) for the
 * rect [x..x+w, y..y+h) from `pixels` (24bpp packed BGR, top-down).
 * Returns the body size in bytes, or -1 if it exceeds cap or 0xffff.
 * The body can then be wrapped whole via rdp_fp_build_bitmap_update or,
 * when too large, sliced across fragments via rdp_fp_build_update_frag. */
ssize_t rdp_fp_build_bitmap_body(uint8_t *out, size_t cap,
		uint16_t x, uint16_t y, uint16_t w, uint16_t h,
		const uint8_t *pixels, size_t pixels_stride);

/* Build a Synchronize fast-path update (empty body). */
ssize_t rdp_fp_build_synchronize(uint8_t *out, size_t cap);

/* Build a System Pointer Default fast-path update. */
ssize_t rdp_fp_build_pointer_default(uint8_t *out, size_t cap);

/* Build a New Pointer (TS_POINTERATTRIBUTE, xorBpp=32 ARGB) fast-path
 * update for a w x h color cursor.  argb is the session wire format:
 * top-down rows of R,G,B,A, stride = bytes per source row (normally
 * w*4).  cache_index selects the client pointer cache slot, hot_x/hot_y
 * are the hotspot.  Returns total wire bytes written, or -1 if it would
 * not fit cap or a single fast-path PDU.  The caller is responsible for
 * clamping w,h to the cap-derived maximum before calling. */
ssize_t rdp_fp_build_pointer_new(uint8_t *out, size_t cap,
		uint16_t cache_index, uint16_t hot_x, uint16_t hot_y,
		uint16_t w, uint16_t h, const uint8_t *argb, size_t stride);

/* Build a Cached Pointer fast-path update that recalls a previously
 * sent New Pointer from client cache slot cache_index.  Body is a
 * single u16 LE cacheIndex.  Returns total wire bytes, or -1 if it
 * would not fit cap. */
ssize_t rdp_fp_build_pointer_cached(uint8_t *out, size_t cap, uint16_t cache_index);

/* Build a Bitmap fast-path update covering rect [x..x+w, y..y+h)
 * with `pixels` (24bpp packed BGR, top-down).  The wire format
 * expects bottom-up rows padded to a 4-pixel width, which this
 * function handles.  Returns wire bytes written or -1 if the
 * update doesn't fit (caller is expected to tile larger frames). */
ssize_t rdp_fp_build_bitmap_update(uint8_t *out, size_t cap,
		uint16_t x, uint16_t y, uint16_t w, uint16_t h,
		const uint8_t *pixels, size_t pixels_stride);

/* Decoded fast-path input event. */
struct rdp_fp_input_event {
	uint8_t  type;
	uint16_t flags;       /* per spec for the event type */
	uint16_t keycode;     /* scancode or unicode unit, if applicable */
	int32_t  x, y;        /* mouse coords */
};

/* Parse a fast-path input PDU from buf.  Caller has already
 * accumulated len bytes.  Callback gets each decoded event.  Returns
 * 0 on success and the number of events via *n_events_out, -1 on
 * malformed input. */
typedef void (*rdp_fp_input_cb)(void *ctx,
		const struct rdp_fp_input_event *ev);

int rdp_fp_parse_input(const uint8_t *buf, size_t len,
		rdp_fp_input_cb cb, void *ctx, unsigned *n_events_out);

/* Helper: detect whether a buffer starts with a fast-path PDU
 * (action bits 0) versus a TPKT (first byte == 3). */
int rdp_fp_looks_like(const uint8_t *buf, size_t len);

#endif /* RDP_FASTPATH_H */
