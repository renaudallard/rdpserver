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
 * proto.h -- backend RPC: framing between the rdpd worker and the
 * per-user rdp-session helper.
 *
 * Transport: AF_UNIX SOCK_STREAM socket pair, set up by sessmgr at
 * SPAWN time.  We use STREAM (rather than SEQPACKET) so individual
 * messages can be larger than the kernel's SEQPACKET frame cap;
 * a full uncompressed 1280x720 frame is 2.6 MiB.
 *
 * Wire frame:
 *
 *   u32 type        (little-endian)
 *   u32 length      (little-endian, payload length excluding header)
 *   bytes payload   (length bytes)
 *
 * Messages, in conversational order:
 *
 *   HELLO_S2W   rdp-session announces its display mode to the worker
 *               (w, h, bpp).  Sent once at connect.
 *   FRAME       rdp-session -> worker.  Carries a rectangular pixel
 *               update in 24-bit BGR, bottom-up rows.  Worker tiles
 *               this into RDP fast-path bitmap updates.
 *   H264_FRAME  rdp-session -> worker.  Pre-encoded H.264 bitstream.
 *               Worker wraps it into RDPGFX AVC420 PDUs directly.
 *   INPUT_KEY   worker -> rdp-session.  Translated PC/AT scancode +
 *               down/up flag + extended flag.
 *   INPUT_MOUSE worker -> rdp-session.  Absolute pixel coordinates,
 *               button bitmap, modifier flags.
 *   BYE         either side announces clean shutdown.  No payload.
 */

#ifndef RDP_BACKEND_PROTO_H
#define RDP_BACKEND_PROTO_H

#include <stdint.h>

#define RDP_BE_HEADER 8

#define RDP_BE_HELLO_S2W    1u
#define RDP_BE_FRAME        2u
#define RDP_BE_INPUT_KEY    3u
#define RDP_BE_INPUT_MOUSE  4u
#define RDP_BE_BYE          5u
/* Clipboard.  All flow in both directions.  CLIP_OFFER announces
 * which formats are available; CLIP_REQUEST asks for one of them;
 * CLIP_DATA returns the bytes for that format.  Formats use a
 * bitmap: bit 0 = UTF-8 text. */
#define RDP_BE_CLIP_OFFER   6u
#define RDP_BE_CLIP_REQUEST 7u
#define RDP_BE_CLIP_DATA    8u
#define RDP_BE_RESIZE       9u
#define RDP_BE_AUDIO       10u

/* File system operations (session <-> worker for RDPDR drives).
 * Request: session sends FS_REQ with an rdp_be_fs_req header.
 * Response: worker sends FS_RSP with an rdp_be_fs_rsp header + data. */
#define RDP_BE_H264_FRAME  13u
#define RDP_BE_INPUT_UNICODE 14u
#define RDP_BE_CURSOR      15u   /* session -> worker */
#define RDP_BE_INPUT_SYNC  16u   /* worker -> session: lock-key state; 1..16 used */

#define RDP_BE_FS_REQ      11u
#define RDP_BE_FS_RSP      12u

#define RDP_FS_OPEN        1u
#define RDP_FS_READ        2u
#define RDP_FS_WRITE       3u
#define RDP_FS_CLOSE       4u
#define RDP_FS_LIST        5u

struct rdp_be_fs_req {
	uint32_t req_id;
	uint32_t op;
	uint32_t device_id;
	uint32_t file_id;
	uint32_t length;
	uint64_t offset;
};

struct rdp_be_fs_rsp {
	uint32_t req_id;
	uint32_t status;
	uint32_t file_id;
	uint32_t length;
};

#define RDP_BE_CLIP_FMT_TEXT  0x00000001u

/* Hello payload (8 bytes). */
struct rdp_be_hello {
	uint16_t width;
	uint16_t height;
	uint16_t bpp;
	uint16_t reserved;
};

/* Frame payload header (8 bytes) followed by w*h*3 bytes BGR. */
struct rdp_be_frame_hdr {
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
};

/* H.264-encoded frame payload header (12 bytes) followed by h264_len
 * bytes of compressed H.264 bitstream. */
struct rdp_be_h264_frame_hdr {
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
	uint32_t h264_len;
};

/* Key event payload (8 bytes). */
struct rdp_be_input_key {
	uint16_t scancode;
	uint8_t  down;       /* 1 = press, 0 = release */
	uint8_t  extended;   /* PC/AT E0 prefix */
	uint8_t  pad[4];
};

/* Unicode key event payload (8 bytes).  Carries a Unicode scalar
 * value; the session injects it by remapping a spare X keycode to the
 * matching keysym.  Only presses are forwarded (down is always 1). */
struct rdp_be_input_unicode {
	uint32_t codepoint;
	uint8_t  down;
	uint8_t  pad[3];
};

/* Lock-key sync payload (4 bytes).  flags carries the MS-RDPBCGR
 * fast-path SYNC toggle bits: SCROLL=0x01, NUM=0x02, CAPS=0x04,
 * KANA=0x08.  It is the absolute desired lock state, not a toggle. */
struct rdp_be_input_sync {
	uint32_t flags;
};

/* Mouse event payload (12 bytes). */
struct rdp_be_input_mouse {
	int32_t  x;
	int32_t  y;
	uint16_t buttons;    /* bit 0 = left, 1 = right, 2 = middle */
	uint16_t flags;      /* bit 0 = motion, 1 = down/up */
};

/* CLIP_OFFER payload: just a u32 format bitmap. */
struct rdp_be_clip_offer {
	uint32_t formats;
};

/* CLIP_REQUEST payload: u32 format selector. */
struct rdp_be_clip_request {
	uint32_t format;
};

/* CLIP_DATA payload: u32 format, u32 status (0=ok, !=0 fail), then
 * `len - 8` bytes of UTF-8 text (for format=TEXT). */
struct rdp_be_clip_data_hdr {
	uint32_t format;
	uint32_t status;
};

/* RESIZE payload (worker -> session): new desktop dimensions. */
struct rdp_be_resize {
	uint16_t width;
	uint16_t height;
	uint16_t pad[2];
};

/* CURSOR payload: 8-byte header then width*height*4 bytes, top-down,
 * R,G,B,A per pixel (A = X cursor alpha). */
struct rdp_be_cursor_hdr {
	uint16_t width;
	uint16_t height;
	uint16_t hotspot_x;
	uint16_t hotspot_y;
};

#endif /* RDP_BACKEND_PROTO_H */
