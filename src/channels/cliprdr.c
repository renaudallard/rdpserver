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

#include <stdio.h>
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

/*
 * CB_FORMAT_LIST.  Long-format-names mode is a sequence of
 * { u32 formatId, UTF-16LE formatName (NUL-terminated) }; an unnamed
 * format writes a single 0x0000 (the empty-name terminator).  Short mode
 * is { u32 formatId, 32-byte ASCII name (NUL-padded) } per entry.  The
 * header dataLen is backfilled once the body length is known.
 */
ssize_t
rdp_cliprdr_build_format_list(uint8_t *out, size_t cap, int use_long_names,
		const struct rdp_clip_fmt *fmts, size_t n)
{
	struct rdp_buf b;
	size_t i, used, body;

	rdp_buf_init(&b, out, cap);
	if (write_hdr(&b, CB_FORMAT_LIST, 0, 0) != 0) return -1;
	for (i = 0; i < n; i++) {
		if (rdp_buf_put_u32le(&b, fmts[i].id) != 0) return -1;
		if (use_long_names) {
			const char *p = fmts[i].name;
			for (; p != NULL && *p != '\0'; p++)
				if (rdp_buf_put_u16le(&b, (uint8_t)*p) != 0)
					return -1;
			if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
		} else {
			uint8_t name32[32];
			size_t l = 0;
			memset(name32, 0, sizeof name32);
			if (fmts[i].name != NULL) {
				l = strlen(fmts[i].name);
				if (l > sizeof name32) l = sizeof name32;
				memcpy(name32, fmts[i].name, l);
			}
			if (rdp_buf_put(&b, name32, sizeof name32) != 0)
				return -1;
		}
	}
	/* Backfill dataLen (body bytes after the 8-byte header). */
	used = rdp_buf_used(&b);
	body = used - RDP_CLIPRDR_HDR_LEN;
	out[4] = (uint8_t)(body & 0xff);
	out[5] = (uint8_t)((body >> 8) & 0xff);
	out[6] = (uint8_t)((body >> 16) & 0xff);
	out[7] = (uint8_t)((body >> 24) & 0xff);
	return (ssize_t)used;
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

/* Does the UTF-16LE name region p[0..plen) equal the ASCII string a
 * (optionally followed by a 2-byte NUL terminator)? */
static int
utf16le_name_eq(const uint8_t *p, size_t plen, const char *a)
{
	size_t al = strlen(a), i;

	if (plen != al * 2 && plen != al * 2 + 2)
		return 0;
	for (i = 0; i < al; i++)
		if (p[i * 2] != (uint8_t)a[i] || p[i * 2 + 1] != 0)
			return 0;
	if (plen == al * 2 + 2 && (p[al * 2] != 0 || p[al * 2 + 1] != 0))
		return 0;
	return 1;
}

/* Does the 32-byte ASCII short-name field equal the NUL-terminated a? */
static int
ascii_name_eq(const uint8_t *p, const char *a)
{
	size_t al = strlen(a), i;

	if (al >= 32)
		return 0;
	if (memcmp(p, a, al) != 0)
		return 0;
	for (i = al; i < 32; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

/* Record one advertised format (id plus its name region) into *out. */
static void
classify_format(struct rdp_cliprdr_formats *out, uint32_t fmt,
		const uint8_t *name, size_t name_len, int utf16)
{
	int is_html;

	if (fmt == CF_UNICODETEXT)
		out->has_unicode_text = 1;
	else if (fmt == CF_TEXT)
		out->has_text = 1;
	else if (fmt == CF_DIB || fmt == CF_DIBV5) {
		/* Prefer CF_DIB; only fall back to V5 if no plain DIB seen. */
		if (!out->has_dib || fmt == CF_DIB) {
			out->has_dib = 1;
			out->dib_id = fmt;
		}
	}
	is_html = utf16 ? utf16le_name_eq(name, name_len, CB_FMT_NAME_HTML)
			: ascii_name_eq(name, CB_FMT_NAME_HTML);
	if (is_html) {
		out->has_html = 1;
		out->html_id = fmt;
	}
}

int
rdp_cliprdr_parse_format_list(const uint8_t *p, size_t len,
		int use_long_names, struct rdp_cliprdr_formats *out)
{
	size_t off = 0;

	memset(out, 0, sizeof *out);
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
			classify_format(out, fmt, p + name_start,
				off - name_start, 1);
		}
	} else {
		/* 36-byte stride: 4 fmt id + 32 ASCII name. */
		while (off + 36 <= len) {
			uint32_t fmt = (uint32_t)p[off]
				| ((uint32_t)p[off + 1] << 8)
				| ((uint32_t)p[off + 2] << 16)
				| ((uint32_t)p[off + 3] << 24);
			classify_format(out, fmt, p + off + 4, 32, 0);
			off += 36;
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

/* The fixed envelope around the HTML fragment.  StartHTML points at <html>,
 * StartFragment just past the StartFragment comment, EndFragment at the
 * EndFragment comment, EndHTML at the buffer end. */
static const char html_pre[]  = "<html>\r\n<body>\r\n";
static const char html_sfrag[] = "<!--StartFragment-->";
static const char html_efrag[] = "<!--EndFragment-->";
static const char html_post[] = "\r\n</body>\r\n</html>";
static const char html_hdr_fmt[] =
	"Version:0.9\r\n"
	"StartHTML:%010zu\r\n"
	"EndHTML:%010zu\r\n"
	"StartFragment:%010zu\r\n"
	"EndFragment:%010zu\r\n";

ssize_t
rdp_cliprdr_html_wrap(uint8_t *out, size_t cap, const uint8_t *html,
		size_t html_len)
{
	char hdr[160];
	int h0;
	size_t hlen, start_html, start_frag, end_frag, end_html;

	/* Offsets are 10 digits wide, so the header length is constant; size
	 * it by formatting with zero offsets, then re-emit with the real
	 * ones (same width). */
	h0 = snprintf(hdr, sizeof hdr, html_hdr_fmt,
		(size_t)0, (size_t)0, (size_t)0, (size_t)0);
	if (h0 < 0 || (size_t)h0 >= sizeof hdr)
		return -1;
	hlen = (size_t)h0;
	/* Bound html_len against the buffer BEFORE any offset addition, so a
	 * near-SIZE_MAX length cannot wrap end_html below cap and slip past
	 * the check into the memcpy. */
	{
		size_t overhead = hlen + (sizeof html_pre - 1)
			+ (sizeof html_sfrag - 1) + (sizeof html_efrag - 1)
			+ (sizeof html_post - 1);
		if (overhead > cap || html_len > cap - overhead)
			return -1;
	}
	start_html = hlen;
	start_frag = hlen + (sizeof html_pre - 1) + (sizeof html_sfrag - 1);
	end_frag   = start_frag + html_len;
	end_html   = end_frag + (sizeof html_efrag - 1)
		+ (sizeof html_post - 1);
	if ((size_t)snprintf(hdr, sizeof hdr, html_hdr_fmt,
		start_html, end_html, start_frag, end_frag) != hlen)
		return -1;   /* an offset overran 10 digits */
	memcpy(out, hdr, hlen);
	memcpy(out + hlen, html_pre, sizeof html_pre - 1);
	memcpy(out + hlen + (sizeof html_pre - 1), html_sfrag,
		sizeof html_sfrag - 1);
	memcpy(out + start_frag, html, html_len);
	memcpy(out + end_frag, html_efrag, sizeof html_efrag - 1);
	memcpy(out + end_frag + (sizeof html_efrag - 1), html_post,
		sizeof html_post - 1);
	return (ssize_t)end_html;
}

/* Find the first occurrence of NUL-terminated needle in p[0..len); on a
 * match set *pos to its offset and return 0. */
static int
find_sub(const uint8_t *p, size_t len, const char *needle, size_t *pos)
{
	size_t nl = strlen(needle), i;

	if (nl == 0 || len < nl)
		return -1;
	for (i = 0; i + nl <= len; i++)
		if (memcmp(p + i, needle, nl) == 0) {
			*pos = i;
			return 0;
		}
	return -1;
}

/* Read the decimal value that follows "key" in the CF_HTML header. */
static int
html_offset(const uint8_t *p, size_t len, const char *key, size_t *out)
{
	size_t at, j, v = 0;
	int any = 0;

	if (find_sub(p, len, key, &at) != 0)
		return -1;
	for (j = at + strlen(key); j < len && p[j] >= '0' && p[j] <= '9';
			j++) {
		v = v * 10 + (size_t)(p[j] - '0');
		if (v > ((size_t)1 << 40))
			return -1;   /* implausible; bail before overflow */
		any = 1;
	}
	if (!any)
		return -1;
	*out = v;
	return 0;
}

int
rdp_cliprdr_html_unwrap(const uint8_t *cfhtml, size_t len, size_t *frag_off,
		size_t *frag_len)
{
	size_t sf, ef, smo, emo;

	/* Preferred: the StartFragment/EndFragment byte offsets in the
	 * header. */
	if (html_offset(cfhtml, len, "StartFragment:", &sf) == 0
	    && html_offset(cfhtml, len, "EndFragment:", &ef) == 0
	    && sf <= ef && ef <= len) {
		*frag_off = sf;
		*frag_len = ef - sf;
		return 0;
	}
	/* Fallback: the literal fragment comment markers. */
	if (find_sub(cfhtml, len, html_sfrag, &smo) == 0
	    && find_sub(cfhtml, len, html_efrag, &emo) == 0) {
		size_t s = smo + (sizeof html_sfrag - 1);
		if (s <= emo && emo <= len) {
			*frag_off = s;
			*frag_len = emo - s;
			return 0;
		}
	}
	/* No envelope recognised: treat the whole buffer as the fragment. */
	*frag_off = 0;
	*frag_len = len;
	return 0;
}

static uint16_t
le16_at(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
le32_at(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#define BMP_FILE_HDR       14u
#define BI_BITFIELDS        3u
#define BI_ALPHABITFIELDS   6u

ssize_t
rdp_cliprdr_dib_to_bmp(const uint8_t *dib, size_t dib_len, uint8_t *out,
		size_t cap)
{
	uint32_t biSize, biCompression = 0, biClrUsed = 0, bfSize;
	uint16_t biBitCount = 0;
	size_t pixoff, palette = 0, masks = 0;

	if (dib_len < 4)
		return -1;
	biSize = le32_at(dib);
	/* The DIB header must lie within the buffer. */
	if (biSize < 12 || biSize > dib_len)
		return -1;

	if (biSize >= 40) {
		/* BITMAPINFOHEADER and its V4/V5 supersets (biSize >= 40 with
		 * biSize <= dib_len guarantees offsets 0..35 are in range). */
		biBitCount    = le16_at(dib + 14);
		biCompression = le32_at(dib + 16);
		biClrUsed     = le32_at(dib + 32);
		if (biBitCount <= 8) {
			uint32_t n = biClrUsed ? biClrUsed
				: ((uint32_t)1u << biBitCount);
			if (n > 256)
				n = 256;
			palette = (size_t)n * 4;   /* RGBQUAD */
		}
		/* BI_BITFIELDS masks trail only the plain 40-byte header; the
		 * V4/V5 headers carry the masks inside themselves. */
		if (biSize == 40 && (biCompression == BI_BITFIELDS
		    || biCompression == BI_ALPHABITFIELDS))
			masks = (biCompression == BI_ALPHABITFIELDS) ? 16 : 12;
	} else if (biSize == 12) {
		/* BITMAPCOREHEADER: biBitCount at offset 10, RGBTRIPLE palette. */
		biBitCount = le16_at(dib + 10);
		if (biBitCount <= 8)
			palette = ((size_t)1u << biBitCount) * 3;
	}

	pixoff = BMP_FILE_HDR + biSize + masks + palette;
	/* bfOffBits is advisory; clamp it inside the file so a malformed
	 * header cannot point a reader past the bitmap. */
	if (pixoff > BMP_FILE_HDR + dib_len)
		pixoff = BMP_FILE_HDR + biSize;

	if (BMP_FILE_HDR + dib_len > 0xffffffffu)
		return -1;
	if (cap < BMP_FILE_HDR + dib_len)
		return -1;
	bfSize = (uint32_t)(BMP_FILE_HDR + dib_len);

	out[0] = 'B';
	out[1] = 'M';
	out[2] = (uint8_t)(bfSize & 0xff);
	out[3] = (uint8_t)((bfSize >> 8) & 0xff);
	out[4] = (uint8_t)((bfSize >> 16) & 0xff);
	out[5] = (uint8_t)((bfSize >> 24) & 0xff);
	out[6] = out[7] = out[8] = out[9] = 0;   /* bfReserved1/2 */
	out[10] = (uint8_t)(pixoff & 0xff);
	out[11] = (uint8_t)((pixoff >> 8) & 0xff);
	out[12] = (uint8_t)((pixoff >> 16) & 0xff);
	out[13] = (uint8_t)((pixoff >> 24) & 0xff);
	memcpy(out + BMP_FILE_HDR, dib, dib_len);
	return (ssize_t)(BMP_FILE_HDR + dib_len);
}

int
rdp_cliprdr_bmp_to_dib(const uint8_t *bmp, size_t bmp_len, size_t *dib_off,
		size_t *dib_len)
{
	/* Strip the 14-byte BITMAPFILEHEADER; the CF_DIB is everything that
	 * follows (the info header, colour masks, palette and pixels). */
	if (bmp_len <= BMP_FILE_HDR || bmp[0] != 'B' || bmp[1] != 'M')
		return -1;
	*dib_off = BMP_FILE_HDR;
	*dib_len = bmp_len - BMP_FILE_HDR;
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
