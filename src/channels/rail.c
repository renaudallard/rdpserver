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
 * rail.c -- MS-RDPERP RAIL order PDU build/parse.
 */

#include "rail.h"

#include <string.h>

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
st16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

ssize_t
rdp_rail_build_handshake(uint8_t *out, size_t cap, uint32_t build_number)
{
	if (cap < 8) return -1;
	st16(out, RAIL_ORDER_HANDSHAKE);
	st16(out + 2, 8);            /* orderLength includes the 4-byte header */
	st32(out + 4, build_number);
	return 8;
}

ssize_t
rdp_rail_build_exec_result(uint8_t *out, size_t cap, uint16_t flags,
		uint16_t result, uint32_t raw_result,
		const uint8_t *exe_utf16, uint16_t exe_len)
{
	/* header(4) + flags(2) + execResult(2) + rawResult(4) + padding(2)
	 * + exeOrFileLength(2) + exeOrFile(exe_len). */
	size_t total;
	if (exe_utf16 == NULL) exe_len = 0;
	total = 16 + (size_t)exe_len;
	if (total > 0xffff || cap < total) return -1;
	st16(out, RAIL_ORDER_EXEC_RESULT);
	st16(out + 2, (uint16_t)total);
	st16(out + 4, flags);
	st16(out + 6, result);
	st32(out + 8, raw_result);
	st16(out + 12, 0);                 /* padding */
	st16(out + 14, exe_len);
	if (exe_len > 0)
		memcpy(out + 16, exe_utf16, exe_len);
	return (ssize_t)total;
}

int
rdp_rail_parse_order(const uint8_t *p, size_t len, struct rdp_rail_order *out)
{
	uint16_t order_type, order_len;
	size_t off;

	memset(out, 0, sizeof *out);
	if (len < 4) return -1;
	order_type = ld16(p);
	order_len = ld16(p + 2);
	if (order_len < 4 || order_len > len) return -1;
	out->order_type = order_type;
	out->order_length = order_len;
	off = 4;

	switch (order_type) {
	case RAIL_ORDER_HANDSHAKE:
		if (order_len < 8) return -1;
		out->build_number = ld32(p + off);
		return 0;
	case RAIL_ORDER_HANDSHAKE_EX:
		if (order_len < 12) return -1;
		out->build_number = ld32(p + off);
		return 0;
	case RAIL_ORDER_CLIENTSTATUS:
		if (order_len < 8) return -1;
		out->client_status = ld32(p + off);
		return 0;
	case RAIL_ORDER_EXEC: {
		/* flags(2) exeLen(2) workLen(2) argLen(2) then the strings. */
		uint16_t el, wl, al;
		if (order_len < 12) return -1;
		out->exec_flags = ld16(p + off);
		el = ld16(p + off + 2);
		wl = ld16(p + off + 4);
		al = ld16(p + off + 6);
		off += 8;
		/* The three string runs must fit within the declared order. */
		if ((size_t)el + wl + al > (size_t)order_len - off)
			return -1;
		if (el > 0) { out->exe = p + off; out->exe_len = el; off += el; }
		if (wl > 0) { out->workdir = p + off; out->workdir_len = wl;
			off += wl; }
		if (al > 0) { out->args = p + off; out->args_len = al; }
		return 0;
	}
	default:
		/* SYSPARAM, ACTIVATE, etc.: header parsed, body not needed. */
		return 0;
	}
}

/* Window Information Order FieldsPresentFlags (MS-RDPERP 2.2.1.3.1.2). */
#define WO_TYPE_WINDOW        0x01000000u
#define WO_STATE_NEW          0x10000000u
#define WO_STATE_DELETED      0x20000000u
#define WO_FIELD_TITLE        0x00000004u
#define WO_FIELD_STYLE        0x00000008u
#define WO_FIELD_SHOW         0x00000010u
#define WO_FIELD_WND_RECTS    0x00000100u
#define WO_FIELD_VISIBILITY   0x00000200u
#define WO_FIELD_WND_SIZE     0x00000400u
#define WO_FIELD_WND_OFFSET   0x00000800u
#define WO_FIELD_VIS_OFFSET   0x00001000u
#define WO_FIELD_CLIENT_OFF   0x00004000u
#define WO_FIELD_WND_DELTA    0x00008000u

ssize_t
rdp_rail_build_window_new(uint8_t *out, size_t cap,
		const struct rdp_rail_window *w)
{
	uint16_t tl = (w->title != NULL) ? w->title_len : 0;
	/* Fixed fields total 82 bytes plus the title string. */
	size_t total = 82 + (size_t)tl;
	size_t o = 0;
	uint16_t rw = (w->w > 0xffff) ? 0xffff : (uint16_t)w->w;
	uint16_t rh = (w->h > 0xffff) ? 0xffff : (uint16_t)w->h;
	uint32_t fields = WO_TYPE_WINDOW | WO_STATE_NEW
		| WO_FIELD_STYLE | WO_FIELD_SHOW | WO_FIELD_TITLE
		| WO_FIELD_CLIENT_OFF | WO_FIELD_WND_OFFSET | WO_FIELD_WND_DELTA
		| WO_FIELD_WND_SIZE | WO_FIELD_WND_RECTS | WO_FIELD_VIS_OFFSET
		| WO_FIELD_VISIBILITY;

	if (total > 0xffff || cap < total) return -1;
	out[o++] = 0x2C;                         /* alt-sec WINDOW order */
	st16(out + o, (uint16_t)total); o += 2;  /* orderSize incl. this byte */
	st32(out + o, fields); o += 4;
	st32(out + o, w->window_id); o += 4;
	/* Fields are emitted in the wire order, not FieldsPresentFlags order. */
	st32(out + o, w->style); o += 4;          /* STYLE */
	st32(out + o, w->ext_style); o += 4;
	out[o++] = w->show_state;                 /* SHOW */
	st16(out + o, tl); o += 2;                 /* TITLE */
	if (tl > 0) { memcpy(out + o, w->title, tl); o += tl; }
	st32(out + o, (uint32_t)w->x); o += 4;    /* CLIENT_AREA_OFFSET */
	st32(out + o, (uint32_t)w->y); o += 4;
	st32(out + o, (uint32_t)w->x); o += 4;    /* WND_OFFSET */
	st32(out + o, (uint32_t)w->y); o += 4;
	st32(out + o, 0); o += 4;                 /* WND_CLIENT_DELTA = 0,0 */
	st32(out + o, 0); o += 4;
	st32(out + o, w->w); o += 4;              /* WND_SIZE */
	st32(out + o, w->h); o += 4;
	st16(out + o, 1); o += 2;                 /* WND_RECTS: one rect */
	st16(out + o, 0); o += 2;                 /* left */
	st16(out + o, 0); o += 2;                 /* top */
	st16(out + o, rw); o += 2;                /* right */
	st16(out + o, rh); o += 2;                /* bottom */
	st32(out + o, (uint32_t)w->x); o += 4;    /* VIS_OFFSET */
	st32(out + o, (uint32_t)w->y); o += 4;
	st16(out + o, 1); o += 2;                 /* VISIBILITY: one rect */
	st16(out + o, 0); o += 2;
	st16(out + o, 0); o += 2;
	st16(out + o, rw); o += 2;
	st16(out + o, rh); o += 2;
	return (ssize_t)o;
}

ssize_t
rdp_rail_build_window_delete(uint8_t *out, size_t cap, uint32_t window_id)
{
	if (cap < 11) return -1;
	out[0] = 0x2C;                                 /* alt-sec WINDOW order */
	st16(out + 1, 11);                             /* orderSize */
	st32(out + 3, WO_TYPE_WINDOW | WO_STATE_DELETED);
	st32(out + 7, window_id);
	return 11;
}
