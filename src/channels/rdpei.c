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
 * rdpei.c -- MS-RDPEI multitouch and pen input PDU build/parse.
 */

#include "rdpei.h"

#include <string.h>

/* Bounds-checked read cursor over the PDU body. */
struct cur {
	const uint8_t *p;
	size_t         n;
};

static int
rd_u8(struct cur *c, uint8_t *v)
{
	if (c->n < 1) return -1;
	*v = c->p[0];
	c->p++; c->n--;
	return 0;
}

static int
rd_u16le(struct cur *c, uint16_t *v)
{
	if (c->n < 2) return -1;
	*v = (uint16_t)(c->p[0] | ((uint16_t)c->p[1] << 8));
	c->p += 2; c->n -= 2;
	return 0;
}

static int
rd_u32le(struct cur *c, uint32_t *v)
{
	if (c->n < 4) return -1;
	*v = (uint32_t)c->p[0] | ((uint32_t)c->p[1] << 8)
		| ((uint32_t)c->p[2] << 16) | ((uint32_t)c->p[3] << 24);
	c->p += 4; c->n -= 4;
	return 0;
}

/*
 * MS-RDPEI variable-length integers.  The first byte carries a
 * length (and, for the signed forms, a sign) prefix in its high bits;
 * the remaining low bits are the most-significant value bits, with any
 * following bytes appended most-significant-first.
 */

/* TWO_BYTE_UNSIGNED: bit 0x80 => a second byte follows; low 7 bits are
 * the high value bits. */
static int
rd_2bu(struct cur *c, uint16_t *v)
{
	uint8_t b, b1;
	if (rd_u8(c, &b) != 0) return -1;
	if (b & 0x80) {
		if (rd_u8(c, &b1) != 0) return -1;
		*v = (uint16_t)(((b & 0x7F) << 8) | b1);
	} else {
		*v = (uint16_t)(b & 0x7F);
	}
	return 0;
}

/* TWO_BYTE_SIGNED: bit 0x80 => second byte; bit 0x40 => negative; low
 * 6 bits are the high value bits. */
static int
rd_2bs(struct cur *c, int16_t *v)
{
	uint8_t b, b1;
	int neg, val;
	if (rd_u8(c, &b) != 0) return -1;
	neg = (b & 0x40) != 0;
	val = b & 0x3F;
	if (b & 0x80) {
		if (rd_u8(c, &b1) != 0) return -1;
		val = (val << 8) | b1;
	}
	*v = (int16_t)(neg ? -val : val);
	return 0;
}

/* FOUR_BYTE_UNSIGNED: bits 0xC0 => count of following bytes (0-3); low
 * 6 bits are the high value bits. */
static int
rd_4bu(struct cur *c, uint32_t *v)
{
	uint8_t b;
	int count, i;
	uint32_t val;
	if (rd_u8(c, &b) != 0) return -1;
	count = (b & 0xC0) >> 6;
	val = b & 0x3F;
	for (i = 0; i < count; i++) {
		if (rd_u8(c, &b) != 0) return -1;
		val = (val << 8) | b;
	}
	*v = val;
	return 0;
}

/* FOUR_BYTE_SIGNED: bits 0xC0 => count (0-3); bit 0x20 => negative; low
 * 5 bits are the high value bits. */
static int
rd_4bs(struct cur *c, int32_t *v)
{
	uint8_t b;
	int count, neg, i;
	uint32_t val;
	if (rd_u8(c, &b) != 0) return -1;
	count = (b & 0xC0) >> 6;
	neg = (b & 0x20) != 0;
	val = b & 0x1F;
	for (i = 0; i < count; i++) {
		if (rd_u8(c, &b) != 0) return -1;
		val = (val << 8) | b;
	}
	*v = neg ? -(int32_t)val : (int32_t)val;
	return 0;
}

/* EIGHT_BYTE_UNSIGNED: bits 0xE0 => count of following bytes (0-7); low
 * 5 bits are the high value bits. */
static int
rd_8bu(struct cur *c, uint64_t *v)
{
	uint8_t b;
	int count, i;
	uint64_t val;
	if (rd_u8(c, &b) != 0) return -1;
	count = (b & 0xE0) >> 5;
	val = b & 0x1F;
	for (i = 0; i < count; i++) {
		if (rd_u8(c, &b) != 0) return -1;
		val = (val << 8) | b;
	}
	*v = val;
	return 0;
}

ssize_t
rdp_rdpei_build_sc_ready(uint8_t *out, size_t cap, uint32_t version)
{
	/* V1 body is just the 4-byte protocolVersion (no features field). */
	if (cap < 10) return -1;
	out[0] = RDPEI_EVENTID_SC_READY & 0xff;
	out[1] = (RDPEI_EVENTID_SC_READY >> 8) & 0xff;
	out[2] = 10; out[3] = 0; out[4] = 0; out[5] = 0;   /* pduLength = 10 */
	out[6] = version & 0xff;
	out[7] = (version >> 8) & 0xff;
	out[8] = (version >> 16) & 0xff;
	out[9] = (version >> 24) & 0xff;
	return 10;
}

/* Parse the touch/pen frame array into the flattened contact list. */
static int
parse_frames(struct cur *c, struct rdp_rdpei_event *out, int is_pen)
{
	uint32_t encode_time;
	uint16_t frame_count, f;

	if (rd_4bu(c, &encode_time) != 0) return -1;
	if (rd_2bu(c, &frame_count) != 0) return -1;
	for (f = 0; f < frame_count; f++) {
		uint16_t contact_count, ci;
		uint64_t frame_offset;
		if (rd_2bu(c, &contact_count) != 0) return -1;
		if (rd_8bu(c, &frame_offset) != 0) return -1;
		for (ci = 0; ci < contact_count; ci++) {
			struct rdp_rdpei_contact ct;
			uint16_t fields;
			memset(&ct, 0, sizeof ct);
			ct.is_pen = is_pen;
			if (rd_u8(c, &ct.id) != 0) return -1;
			if (rd_2bu(c, &fields) != 0) return -1;
			if (rd_4bs(c, &ct.x) != 0) return -1;
			if (rd_4bs(c, &ct.y) != 0) return -1;
			if (rd_4bu(c, &ct.flags) != 0) return -1;
			if (!is_pen) {
				if (fields & 0x0001) {   /* contact rect */
					int16_t t;
					if (rd_2bs(c, &t) != 0) return -1;
					if (rd_2bs(c, &t) != 0) return -1;
					if (rd_2bs(c, &t) != 0) return -1;
					if (rd_2bs(c, &t) != 0) return -1;
				}
				if (fields & 0x0002) {   /* orientation */
					uint32_t o;
					if (rd_4bu(c, &o) != 0) return -1;
				}
				if (fields & 0x0004) {   /* pressure */
					if (rd_4bu(c, &ct.pressure) != 0) return -1;
				}
			} else {
				if (fields & 0x0001) {   /* penFlags */
					uint32_t pf;
					if (rd_4bu(c, &pf) != 0) return -1;
				}
				if (fields & 0x0002) {   /* pressure */
					if (rd_4bu(c, &ct.pressure) != 0) return -1;
				}
				if (fields & 0x0004) {   /* rotation */
					uint16_t r;
					if (rd_2bu(c, &r) != 0) return -1;
				}
				if (fields & 0x0008) {   /* tiltX */
					int16_t tx;
					if (rd_2bs(c, &tx) != 0) return -1;
				}
				if (fields & 0x0010) {   /* tiltY */
					int16_t ty;
					if (rd_2bs(c, &ty) != 0) return -1;
				}
			}
			if (out->contact_count < RDPEI_MAX_CONTACTS)
				out->contacts[out->contact_count++] = ct;
		}
	}
	return 0;
}

int
rdp_rdpei_parse_event(const uint8_t *p, size_t len,
		struct rdp_rdpei_event *out)
{
	struct cur c;
	uint32_t pdu_len;

	if (len < 6) return -1;
	memset(out, 0, sizeof *out);
	out->event_id = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
	pdu_len = (uint32_t)p[2] | ((uint32_t)p[3] << 8)
		| ((uint32_t)p[4] << 16) | ((uint32_t)p[5] << 24);
	if (pdu_len < 6 || pdu_len > len) return -1;
	c.p = p + 6;
	c.n = pdu_len - 6;

	switch (out->event_id) {
	case RDPEI_EVENTID_CS_READY:
		if (rd_u32le(&c, &out->cs_flags) != 0) return -1;
		if (rd_u32le(&c, &out->cs_version) != 0) return -1;
		if (rd_u16le(&c, &out->cs_max_contacts) != 0) return -1;
		return 0;
	case RDPEI_EVENTID_TOUCH:
		return parse_frames(&c, out, 0);
	case RDPEI_EVENTID_PEN:
		return parse_frames(&c, out, 1);
	case RDPEI_EVENTID_DISMISS_HOVER: {
		uint8_t id;
		if (rd_u8(&c, &id) != 0) return -1;
		out->contacts[0].id = id;
		out->contacts[0].flags = RDPEI_CONTACT_UP;
		out->contact_count = 1;
		return 0;
	}
	default:
		/* SUSPEND/RESUME or unknown: header parsed, no body needed. */
		return 0;
	}
}
