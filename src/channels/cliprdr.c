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
 * cliprdr.c -- CLIPRDR PDU builders/parsers.
 */

#include "cliprdr.h"

#include "../common/buf.h"

#include <stdlib.h>
#include <string.h>

static int
write_hdr(struct rdp_buf *b, uint16_t msg_type, uint16_t msg_flags,
		uint32_t data_len)
{
	if (rdp_buf_put_u16le(b, msg_type) != 0) return -1;
	if (rdp_buf_put_u16le(b, msg_flags) != 0) return -1;
	if (rdp_buf_put_u32le(b, data_len) != 0) return -1;
	return 0;
}

ssize_t
rdp_cliprdr_build_monitor_ready(uint8_t *out, size_t cap)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_MONITOR_READY, 0, 0) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_cliprdr_build_clip_caps(uint8_t *out, size_t cap)
{
	struct rdp_buf b;
	/* Outer CLIPRDR header + caps body (16 bytes:
	 *   u16 cCapabilitiesSets, u16 pad
	 *   one CB_CAPSTYPE_GENERAL set (12 bytes):
	 *     u16 capabilitySetType = 1
	 *     u16 lengthCapability = 12
	 *     u32 version = CB_CAPS_VERSION_2
	 *     u32 generalFlags = CB_USE_LONG_FORMAT_NAMES). */
	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_CLIP_CAPS, 0, 16) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 1) != 0) return -1;     /* cCapabilitiesSets */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;     /* pad */
	if (rdp_buf_put_u16le(&b, CB_CAPSTYPE_GENERAL) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 12) != 0) return -1;
	if (rdp_buf_put_u32le(&b, CB_CAPS_VERSION_2) != 0) return -1;
	if (rdp_buf_put_u32le(&b, CB_USE_LONG_FORMAT_NAMES) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_cliprdr_build_format_list_response(uint8_t *out, size_t cap, int ok)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_FORMAT_LIST_RESPONSE,
		ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL, 0) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

/* CB_FORMAT_LIST in long-format-names mode: a sequence of
 * { u32 formatId, wchar_t* formatName (UTF-16LE, NUL-terminated) }.
 * For an unnamed format we still write a single 0x0000 (the empty
 * name terminator). */
ssize_t
rdp_cliprdr_build_format_list_unicode_text(uint8_t *out, size_t cap)
{
	struct rdp_buf b;
	uint32_t payload_len = 4 + 2;   /* one entry: u32 fmt + u16 NUL */
	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_FORMAT_LIST, 0, payload_len) != 0) return -1;
	if (rdp_buf_put_u32le(&b, CF_UNICODETEXT) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_cliprdr_build_format_data_request(uint8_t *out, size_t cap,
		uint32_t format_id)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_FORMAT_DATA_REQUEST, 0, 4) != 0) return -1;
	if (rdp_buf_put_u32le(&b, format_id) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_cliprdr_build_format_data_response(uint8_t *out, size_t cap,
		const void *data, size_t data_len, int ok)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_FORMAT_DATA_RESPONSE,
		ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL,
		(uint32_t)data_len) != 0) return -1;
	if (data_len > 0 && rdp_buf_put(&b, data, data_len) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

int
rdp_cliprdr_parse_hdr(const uint8_t *p, size_t len,
		struct rdp_cliprdr_hdr *out)
{
	if (len < RDP_CLIPRDR_HDR_LEN) return -1;
	out->msg_type  = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
	out->msg_flags = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
	out->data_len  = (uint32_t)p[4] | ((uint32_t)p[5] << 8)
		| ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
	return 0;
}

int
rdp_cliprdr_parse_format_list(const uint8_t *p, size_t len,
		int use_long_names,
		int *has_unicode_text, int *has_text)
{
	size_t off = 0;

	*has_unicode_text = 0;
	*has_text = 0;
	if (use_long_names) {
		while (off + 4 <= len) {
			uint32_t fmt;
			size_t name_start;
			fmt = (uint32_t)p[off]
				| ((uint32_t)p[off + 1] << 8)
				| ((uint32_t)p[off + 2] << 16)
				| ((uint32_t)p[off + 3] << 24);
			off += 4;
			name_start = off;
			/* UTF-16LE NUL-terminated name. */
			while (off + 1 < len) {
				if (p[off] == 0 && p[off + 1] == 0) {
					off += 2;
					break;
				}
				off += 2;
			}
			(void)name_start;
			if (fmt == CF_UNICODETEXT) *has_unicode_text = 1;
			else if (fmt == CF_TEXT)   *has_text = 1;
		}
	} else {
		/* 36-byte stride: 4 fmt id + 32 ASCII name. */
		while (off + 36 <= len) {
			uint32_t fmt = (uint32_t)p[off]
				| ((uint32_t)p[off + 1] << 8)
				| ((uint32_t)p[off + 2] << 16)
				| ((uint32_t)p[off + 3] << 24);
			off += 36;
			if (fmt == CF_UNICODETEXT) *has_unicode_text = 1;
			else if (fmt == CF_TEXT)   *has_text = 1;
		}
	}
	return 0;
}

int
rdp_cliprdr_parse_format_data_request(const uint8_t *p, size_t len,
		uint32_t *format_id_out)
{
	if (len < 4) return -1;
	*format_id_out = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	return 0;
}

void
rdp_cliprdr_reasm_init(struct rdp_cliprdr_reasm *r, size_t max_pdu)
{
	r->buf = NULL;
	r->cap = 0;
	r->len = 0;
	r->max_pdu = max_pdu;
	r->active = 0;
}

void
rdp_cliprdr_reasm_reset(struct rdp_cliprdr_reasm *r)
{
	free(r->buf);
	r->buf = NULL;
	r->cap = 0;
	r->len = 0;
	r->active = 0;
}

int
rdp_cliprdr_reasm_feed(struct rdp_cliprdr_reasm *r,
		const uint8_t *frag, size_t frag_len,
		uint32_t total, uint32_t flags,
		const uint8_t **pdu, size_t *pdu_len)
{
	/* A self-contained single fragment is the common case: hand it back
	 * in place with no allocation. */
	if ((flags & CHANNEL_FLAG_FIRST) && (flags & CHANNEL_FLAG_LAST)) {
		rdp_cliprdr_reasm_reset(r);
		*pdu = frag;
		*pdu_len = frag_len;
		return 1;
	}
	if (flags & CHANNEL_FLAG_FIRST) {
		rdp_cliprdr_reasm_reset(r);
		if (total == 0 || total > r->max_pdu)
			return -1;
		r->buf = malloc(total);
		if (r->buf == NULL)
			return -1;
		r->cap = total;
		r->active = 1;
	}
	if (!r->active)
		return -1;   /* a NEXT/LAST fragment without a FIRST */
	if (frag_len > r->cap - r->len) {
		rdp_cliprdr_reasm_reset(r);
		return -1;   /* fragment overruns the declared total */
	}
	memcpy(r->buf + r->len, frag, frag_len);
	r->len += frag_len;
	if (flags & CHANNEL_FLAG_LAST) {
		*pdu = r->buf;
		*pdu_len = r->len;
		return 1;
	}
	return 0;
}
