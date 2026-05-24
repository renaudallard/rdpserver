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
 * ber.c -- BER encoders/decoders.
 */

#include "ber.h"

#include <string.h>

int
rdp_ber_write_tag(struct rdp_buf *b, uint8_t cls, uint8_t pc, uint8_t tag)
{
	return rdp_buf_put_u8(b, (uint8_t)(cls | pc | (tag & 0x1f)));
}

int
rdp_ber_write_app_tag(struct rdp_buf *b, uint8_t pc, uint32_t tag)
{
	if (tag < 31)
		return rdp_ber_write_tag(b, RDP_BER_CLASS_APPLICATION, pc,
			(uint8_t)tag);
	/* Multi-byte: first octet = class | pc | 0x1F, then base-128
	 * with continuation bits in big-endian order. */
	if (rdp_buf_put_u8(b,
		(uint8_t)(RDP_BER_CLASS_APPLICATION | pc | 0x1f)) != 0)
		return -1;
	{
		uint8_t out[5];
		int n = 0;
		uint32_t v = tag;
		out[n++] = (uint8_t)(v & 0x7f);
		v >>= 7;
		while (v != 0) {
			out[n++] = (uint8_t)((v & 0x7f) | 0x80);
			v >>= 7;
		}
		while (n > 0) {
			if (rdp_buf_put_u8(b, out[--n]) != 0)
				return -1;
		}
	}
	return 0;
}

int
rdp_ber_write_length(struct rdp_buf *b, size_t length)
{
	if (length <= 0x7f)
		return rdp_buf_put_u8(b, (uint8_t)length);
	if (length <= 0xff) {
		if (rdp_buf_put_u8(b, 0x81) != 0) return -1;
		return rdp_buf_put_u8(b, (uint8_t)length);
	}
	if (length <= 0xffff) {
		if (rdp_buf_put_u8(b, 0x82) != 0) return -1;
		return rdp_buf_put_u16be(b, (uint16_t)length);
	}
	if (length <= 0xffffff) {
		if (rdp_buf_put_u8(b, 0x83) != 0) return -1;
		if (rdp_buf_put_u8(b, (uint8_t)(length >> 16)) != 0) return -1;
		if (rdp_buf_put_u8(b, (uint8_t)(length >> 8)) != 0) return -1;
		return rdp_buf_put_u8(b, (uint8_t)length);
	}
	if (rdp_buf_put_u8(b, 0x84) != 0) return -1;
	return rdp_buf_put_u32be(b, (uint32_t)length);
}

int
rdp_ber_write_universal(struct rdp_buf *b, uint8_t pc, uint8_t tag, size_t length)
{
	if (rdp_ber_write_tag(b, RDP_BER_CLASS_UNIVERSAL, pc, tag) != 0)
		return -1;
	return rdp_ber_write_length(b, length);
}

int
rdp_ber_write_integer(struct rdp_buf *b, uint32_t v)
{
	uint8_t bytes[4];
	int n;

	if (v <= 0x7f) {
		n = 1;
		bytes[0] = (uint8_t)v;
	} else if (v <= 0x7fff) {
		n = 2;
		bytes[0] = (uint8_t)(v >> 8);
		bytes[1] = (uint8_t)v;
	} else if (v <= 0x7fffff) {
		n = 3;
		bytes[0] = (uint8_t)(v >> 16);
		bytes[1] = (uint8_t)(v >> 8);
		bytes[2] = (uint8_t)v;
	} else if (v <= 0x7fffffff) {
		n = 4;
		bytes[0] = (uint8_t)(v >> 24);
		bytes[1] = (uint8_t)(v >> 16);
		bytes[2] = (uint8_t)(v >> 8);
		bytes[3] = (uint8_t)v;
	} else {
		/* Need a leading zero to keep two's-complement positive. */
		if (rdp_ber_write_universal(b, RDP_BER_PRIMITIVE,
			RDP_BER_TAG_INTEGER, 5) != 0) return -1;
		if (rdp_buf_put_u8(b, 0) != 0) return -1;
		if (rdp_buf_put_u32be(b, v) != 0) return -1;
		return 0;
	}
	if (rdp_ber_write_universal(b, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_INTEGER, (size_t)n) != 0) return -1;
	return rdp_buf_put(b, bytes, (size_t)n);
}

int
rdp_ber_write_boolean(struct rdp_buf *b, int v)
{
	if (rdp_ber_write_universal(b, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_BOOLEAN, 1) != 0) return -1;
	return rdp_buf_put_u8(b, v ? 0xff : 0x00);
}

int
rdp_ber_write_octet_string(struct rdp_buf *b, const void *data, size_t n)
{
	if (rdp_ber_write_universal(b, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_OCTET_STRING, n) != 0) return -1;
	return rdp_buf_put(b, data, n);
}

int
rdp_ber_write_enumerated(struct rdp_buf *b, uint8_t v)
{
	if (rdp_ber_write_universal(b, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_ENUMERATED, 1) != 0) return -1;
	return rdp_buf_put_u8(b, v);
}

size_t
rdp_ber_sizeof_length(size_t length)
{
	if (length <= 0x7f)     return 1;
	if (length <= 0xff)     return 2;
	if (length <= 0xffff)   return 3;
	if (length <= 0xffffff) return 4;
	return 5;
}

size_t
rdp_ber_sizeof_app_tag(uint32_t tag)
{
	size_t n;

	if (tag < 31) return 1;
	n = 1;
	do { n++; tag >>= 7; } while (tag != 0);
	return n;
}

ssize_t
rdp_ber_read_length(const uint8_t *p, size_t left, size_t *out)
{
	uint8_t b0;

	if (left < 1) return -1;
	b0 = p[0];
	if ((b0 & 0x80) == 0) {
		*out = b0;
		return 1;
	} else {
		unsigned int n = (unsigned int)(b0 & 0x7f);
		size_t v = 0;
		unsigned int i;
		if (n == 0 || n > 4 || left < 1 + n) return -1;
		for (i = 0; i < n; i++)
			v = (v << 8) | (size_t)p[1 + i];
		*out = v;
		return (ssize_t)(1 + n);
	}
}

ssize_t
rdp_ber_read_universal_tag(const uint8_t *p, size_t left,
		uint8_t pc, uint8_t tag, size_t *value_len_out)
{
	uint8_t want = (uint8_t)(RDP_BER_CLASS_UNIVERSAL | pc | (tag & 0x1f));
	ssize_t r;

	if (left < 1) return -1;
	if (p[0] != want) return -1;
	r = rdp_ber_read_length(p + 1, left - 1, value_len_out);
	if (r < 0) return -1;
	if ((size_t)(r + 1) + *value_len_out > left) return -1;
	return r + 1;
}

ssize_t
rdp_ber_read_app_tag(const uint8_t *p, size_t left,
		uint8_t pc, uint32_t tag, size_t *value_len_out)
{
	size_t off = 0;
	uint32_t got;
	ssize_t r;

	if (tag < 31) {
		uint8_t want = (uint8_t)(RDP_BER_CLASS_APPLICATION | pc
			| (tag & 0x1f));
		if (left < 1 || p[0] != want) return -1;
		off = 1;
	} else {
		uint8_t want = (uint8_t)(RDP_BER_CLASS_APPLICATION | pc | 0x1f);
		if (left < 1 || p[0] != want) return -1;
		off = 1;
		got = 0;
		while (off < left) {
			uint8_t c = p[off++];
			got = (got << 7) | (uint32_t)(c & 0x7f);
			if ((c & 0x80) == 0)
				break;
		}
		if (off > left || got != tag) return -1;
	}
	r = rdp_ber_read_length(p + off, left - off, value_len_out);
	if (r < 0) return -1;
	if (off + (size_t)r + *value_len_out > left) return -1;
	return (ssize_t)off + r;
}

ssize_t
rdp_ber_read_integer(const uint8_t *p, size_t left, uint32_t *out)
{
	size_t vlen;
	ssize_t r;
	uint32_t v = 0;
	size_t i;

	r = rdp_ber_read_universal_tag(p, left, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_INTEGER, &vlen);
	if (r < 0) return -1;
	if (vlen == 0 || vlen > 5) return -1;
	if (vlen == 5 && p[r] != 0) return -1;  /* not a non-negative INTEGER */
	for (i = (vlen == 5) ? 1 : 0; i < vlen; i++)
		v = (v << 8) | (uint32_t)p[r + i];
	*out = v;
	return r + (ssize_t)vlen;
}

ssize_t
rdp_ber_read_enumerated(const uint8_t *p, size_t left, uint8_t *out)
{
	size_t vlen;
	ssize_t r;

	r = rdp_ber_read_universal_tag(p, left, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_ENUMERATED, &vlen);
	if (r < 0) return -1;
	if (vlen != 1) return -1;
	*out = p[r];
	return r + 1;
}

ssize_t
rdp_ber_read_boolean(const uint8_t *p, size_t left, int *out)
{
	size_t vlen;
	ssize_t r;

	r = rdp_ber_read_universal_tag(p, left, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_BOOLEAN, &vlen);
	if (r < 0) return -1;
	if (vlen != 1) return -1;
	*out = p[r] != 0;
	return r + 1;
}

ssize_t
rdp_ber_read_octet_string(const uint8_t *p, size_t left,
		const uint8_t **data_out, size_t *len_out)
{
	size_t vlen;
	ssize_t r;

	r = rdp_ber_read_universal_tag(p, left, RDP_BER_PRIMITIVE,
		RDP_BER_TAG_OCTET_STRING, &vlen);
	if (r < 0) return -1;
	*data_out = p + r;
	*len_out = vlen;
	return r + (ssize_t)vlen;
}
