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
 * ddx_proto.h -- control protocol between the DDX module (inside Xorg)
 * and rdp-session.
 *
 * Transport: pre-connected AF_UNIX SOCK_STREAM socketpair.
 * rdp-session sets RDPSERVER_CTRL_FD=N before exec'ing Xorg.
 *
 * Wire format: same 8-byte header as the backend protocol:
 *   u32 type (LE)
 *   u32 length (LE, payload bytes excluding header)
 *   [payload]
 *
 * SHM_READY carries the shm fd via SCM_RIGHTS ancillary data.
 */

#ifndef RDPSERVER_DDX_PROTO_H
#define RDPSERVER_DDX_PROTO_H

#include <stdint.h>

#define DDX_PROTO_HEADER  8

/* DDX -> rdp-session */
#define DDX_MSG_SHM_READY   1u
#define DDX_MSG_DAMAGE      2u

/* rdp-session -> DDX */
#define DDX_MSG_INPUT_KEY   3u
#define DDX_MSG_INPUT_MOUSE 4u
#define DDX_MSG_RESIZE      5u

/* SHM_READY payload (12 bytes). fd sent via SCM_RIGHTS. */
struct ddx_shm_ready {
	uint16_t width;
	uint16_t height;
	uint32_t stride;
	uint32_t size;
};

/* DAMAGE payload: 4 bytes header + nrects * 8 bytes. */
struct ddx_damage_hdr {
	uint16_t nrects;
	uint16_t reserved;
};

struct ddx_damage_rect {
	int16_t x, y, w, h;
};

/* INPUT_KEY payload (4 bytes). */
struct ddx_input_key {
	uint16_t scancode;
	uint8_t  down;
	uint8_t  extended;
};

/* INPUT_MOUSE payload (12 bytes). */
struct ddx_input_mouse {
	int32_t  x;
	int32_t  y;
	uint16_t buttons;
	uint16_t flags;
};

/* RESIZE payload (4 bytes). */
struct ddx_resize {
	uint16_t width;
	uint16_t height;
};

#endif
