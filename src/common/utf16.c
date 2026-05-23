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
 * utf16.c -- UTF-16LE conversion.
 *
 * Each function reports the number of bytes it would have written
 * (caller compares to the buffer it provided to detect truncation)
 * or (size_t)-1 on malformed input.
 */

#include "utf16.h"

#define RDP_UTF_ERR ((size_t)-1)

static int
utf8_decode(const uint8_t *p, size_t left, uint32_t *cp_out, size_t *adv_out)
{
	uint32_t cp;
	size_t need;

	if (left == 0)
		return -1;
	if ((p[0] & 0x80) == 0) {
		cp = p[0];
		need = 1;
	} else if ((p[0] & 0xe0) == 0xc0) {
		cp = (uint32_t)(p[0] & 0x1f);
		need = 2;
	} else if ((p[0] & 0xf0) == 0xe0) {
		cp = (uint32_t)(p[0] & 0x0f);
		need = 3;
	} else if ((p[0] & 0xf8) == 0xf0) {
		cp = (uint32_t)(p[0] & 0x07);
		need = 4;
	} else {
		return -1;
	}
	if (left < need)
		return -1;
	for (size_t i = 1; i < need; i++) {
		if ((p[i] & 0xc0) != 0x80)
			return -1;
		cp = (cp << 6) | (uint32_t)(p[i] & 0x3f);
	}
	/* Reject surrogates and overlong encodings of ASCII range. */
	if (cp >= 0xd800 && cp <= 0xdfff)
		return -1;
	if (need == 2 && cp < 0x80) return -1;
	if (need == 3 && cp < 0x800) return -1;
	if (need == 4 && cp < 0x10000) return -1;
	if (cp > 0x10ffff) return -1;
	*cp_out = cp;
	*adv_out = need;
	return 0;
}

static size_t
utf8_encode(uint32_t cp, uint8_t *out, size_t out_max)
{
	if (cp < 0x80) {
		if (out_max < 1) return 1;
		out[0] = (uint8_t)cp;
		return 1;
	}
	if (cp < 0x800) {
		if (out_max < 2) return 2;
		out[0] = (uint8_t)(0xc0 | (cp >> 6));
		out[1] = (uint8_t)(0x80 | (cp & 0x3f));
		return 2;
	}
	if (cp < 0x10000) {
		if (cp >= 0xd800 && cp <= 0xdfff) return 0;
		if (out_max < 3) return 3;
		out[0] = (uint8_t)(0xe0 | (cp >> 12));
		out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
		out[2] = (uint8_t)(0x80 | (cp & 0x3f));
		return 3;
	}
	if (cp <= 0x10ffff) {
		if (out_max < 4) return 4;
		out[0] = (uint8_t)(0xf0 | (cp >> 18));
		out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3f));
		out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3f));
		out[3] = (uint8_t)(0x80 | (cp & 0x3f));
		return 4;
	}
	return 0;
}

size_t
rdp_utf8_to_utf16le(uint8_t *dst, size_t dsize,
		const char *s, size_t slen)
{
	const uint8_t *p = (const uint8_t *)s;
	size_t i = 0, w = 0;

	while (i < slen) {
		uint32_t cp;
		size_t adv;
		if (utf8_decode(p + i, slen - i, &cp, &adv) < 0)
			return RDP_UTF_ERR;
		i += adv;
		if (cp <= 0xffff) {
			if (w + 2 <= dsize) {
				dst[w]     = (uint8_t)(cp & 0xff);
				dst[w + 1] = (uint8_t)((cp >> 8) & 0xff);
			}
			w += 2;
		} else {
			uint32_t v = cp - 0x10000;
			uint16_t hi = 0xd800 | (uint16_t)(v >> 10);
			uint16_t lo = 0xdc00 | (uint16_t)(v & 0x3ff);
			if (w + 4 <= dsize) {
				dst[w]     = (uint8_t)(hi & 0xff);
				dst[w + 1] = (uint8_t)((hi >> 8) & 0xff);
				dst[w + 2] = (uint8_t)(lo & 0xff);
				dst[w + 3] = (uint8_t)((lo >> 8) & 0xff);
			}
			w += 4;
		}
	}
	return w;
}

size_t
rdp_utf16le_to_utf8(char *dst, size_t dsize,
		const uint8_t *src, size_t slen)
{
	size_t i = 0, w = 0;

	if (slen % 2 != 0)
		return RDP_UTF_ERR;
	while (i + 2 <= slen) {
		uint32_t cp;
		uint16_t u = (uint16_t)src[i] | ((uint16_t)src[i + 1] << 8);
		i += 2;
		if (u >= 0xd800 && u <= 0xdbff) {
			if (i + 2 > slen) return RDP_UTF_ERR;
			uint16_t lo = (uint16_t)src[i]
				| ((uint16_t)src[i + 1] << 8);
			if (lo < 0xdc00 || lo > 0xdfff)
				return RDP_UTF_ERR;
			i += 2;
			cp = 0x10000 + (((uint32_t)(u - 0xd800)) << 10)
				+ (uint32_t)(lo - 0xdc00);
		} else if (u >= 0xdc00 && u <= 0xdfff) {
			return RDP_UTF_ERR;
		} else {
			cp = u;
		}
		uint8_t tmp[4];
		size_t need = utf8_encode(cp, tmp, sizeof tmp);
		if (need == 0)
			return RDP_UTF_ERR;
		if (w + need <= dsize)
			for (size_t k = 0; k < need; k++)
				dst[w + k] = (char)tmp[k];
		w += need;
	}
	return w;
}
