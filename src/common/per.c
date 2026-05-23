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
 * per.c -- PER Aligned helpers, minimal subset.
 */

#include "per.h"

#include <string.h>

/* Canonical GCC OID encoding: itu-t recommendation t 124 version 1.
 * Object Identifier in PER Aligned is preceded by a length octet
 * giving the byte count of the OID body.  The body is the standard
 * BER-style packed OID bytes: 00 00 14 7C 00 01. */
static const uint8_t GCC_OID[] = { 0x00, 0x00, 0x14, 0x7c, 0x00, 0x01 };

int
rdp_per_write_length(struct rdp_buf *b, size_t length)
{
	if (length <= 0x7f)
		return rdp_buf_put_u8(b, (uint8_t)length);
	if (length <= 0x3fff)
		return rdp_buf_put_u16be(b, (uint16_t)(0x8000 | length));
	return -1;  /* fragmented form not needed for our payloads */
}

ssize_t
rdp_per_read_length(const uint8_t *p, size_t left, size_t *out)
{
	if (left < 1) return -1;
	if ((p[0] & 0x80) == 0) {
		*out = p[0];
		return 1;
	}
	if ((p[0] & 0xc0) == 0x80) {
		if (left < 2) return -1;
		*out = ((size_t)(p[0] & 0x3f) << 8) | (size_t)p[1];
		return 2;
	}
	return -1;
}

int
rdp_per_write_choice(struct rdp_buf *b, uint8_t choice)
{
	return rdp_buf_put_u8(b, choice);
}

ssize_t
rdp_per_read_choice(const uint8_t *p, size_t left, uint8_t *out)
{
	if (left < 1) return -1;
	*out = p[0];
	return 1;
}

int
rdp_per_write_selection(struct rdp_buf *b, uint8_t bits)
{
	return rdp_buf_put_u8(b, bits);
}

int
rdp_per_write_numeric_string(struct rdp_buf *b, const char *s, size_t n)
{
	size_t i;
	if (rdp_per_write_length(b, n) != 0) return -1;
	/* NumericString in PER packs two BCD digits per octet, big-endian
	 * nibbles.  GCC uses it for conference parameters; for our tag
	 * usage we only emit single-digit strings ("1"). */
	for (i = 0; i + 2 <= n; i += 2) {
		uint8_t hi = (uint8_t)(s[i]     - '0');
		uint8_t lo = (uint8_t)(s[i + 1] - '0');
		if (rdp_buf_put_u8(b, (uint8_t)((hi << 4) | lo)) != 0)
			return -1;
	}
	if (i < n) {
		uint8_t hi = (uint8_t)(s[i] - '0');
		if (rdp_buf_put_u8(b, (uint8_t)(hi << 4)) != 0) return -1;
	}
	return 0;
}

int
rdp_per_write_object_identifier_gcc(struct rdp_buf *b)
{
	if (rdp_per_write_length(b, sizeof GCC_OID) != 0) return -1;
	return rdp_buf_put(b, GCC_OID, sizeof GCC_OID);
}

ssize_t
rdp_per_read_object_identifier_gcc(const uint8_t *p, size_t left)
{
	size_t vlen;
	ssize_t r = rdp_per_read_length(p, left, &vlen);
	if (r < 0) return -1;
	if (vlen != sizeof GCC_OID) return -1;
	if ((size_t)r + vlen > left) return -1;
	if (memcmp(p + r, GCC_OID, sizeof GCC_OID) != 0) return -1;
	return r + (ssize_t)sizeof GCC_OID;
}

int
rdp_per_write_u16(struct rdp_buf *b, uint16_t v)
{
	return rdp_buf_put_u16be(b, v);
}

int
rdp_per_write_u32(struct rdp_buf *b, uint32_t v)
{
	return rdp_buf_put_u32be(b, v);
}

ssize_t
rdp_per_read_u16(const uint8_t *p, size_t left, uint16_t *out)
{
	if (left < 2) return -1;
	*out = (uint16_t)((p[0] << 8) | p[1]);
	return 2;
}

ssize_t
rdp_per_read_u32(const uint8_t *p, size_t left, uint32_t *out)
{
	if (left < 4) return -1;
	*out = ((uint32_t)p[0] << 24)
	     | ((uint32_t)p[1] << 16)
	     | ((uint32_t)p[2] << 8)
	     |  (uint32_t)p[3];
	return 4;
}

int
rdp_per_write_octet_string(struct rdp_buf *b, const void *data, size_t n)
{
	return rdp_buf_put(b, data, n);
}

int
rdp_per_write_user_data_count(struct rdp_buf *b, uint8_t count)
{
	if (count == 0) return -1;
	return rdp_buf_put_u8(b, (uint8_t)(count - 1));
}

ssize_t
rdp_per_read_user_data_count(const uint8_t *p, size_t left, uint8_t *count_out)
{
	if (left < 1) return -1;
	*count_out = (uint8_t)(p[0] + 1);
	return 1;
}

int
rdp_per_write_h221_key(struct rdp_buf *b, const char key[4])
{
	return rdp_buf_put(b, key, 4);
}

ssize_t
rdp_per_read_h221_key(const uint8_t *p, size_t left, char out[4])
{
	if (left < 4) return -1;
	out[0] = (char)p[0];
	out[1] = (char)p[1];
	out[2] = (char)p[2];
	out[3] = (char)p[3];
	return 4;
}
