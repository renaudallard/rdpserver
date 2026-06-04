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
 * bitmap_rle.c -- MS-RDPBCGR interleaved RLE bitmap compression (24 bpp),
 * a faithful port of the FreeRDP encoder (libfreerdp/codec/bitmap.c).
 */

#include "bitmap_rle.h"

#include <string.h>

#define RLE_MAX_DIM 64
#define RLE_MAX_PIX (RLE_MAX_DIM * RLE_MAX_DIM)

/* Bounds-checked output stream: pos tracks the would-be length, ovf is set if a
 * write would exceed cap (the bytes past cap are dropped, never written). */
struct ostrm {
	uint8_t *buf;
	size_t   pos;
	size_t   cap;
	int      ovf;
};

static void
ow8(struct ostrm *s, uint8_t v)
{
	if (s->pos < s->cap)
		s->buf[s->pos] = v;
	else
		s->ovf = 1;
	s->pos++;
}

static void
ow16(struct ostrm *s, uint16_t v)
{
	ow8(s, (uint8_t)(v & 0xff));
	ow8(s, (uint8_t)((v >> 8) & 0xff));
}

static void
owrite(struct ostrm *s, const uint8_t *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		ow8(s, p[i]);
}

/* Bicolor runs are intentionally not emitted: their even/odd run-length and
 * colour-order handling is uniquely error-prone, and a two-colour alternating
 * run is rare in real content.  Such pixels fall through to COLOR IMAGE
 * literals, which are always correct.  bicolor_count is kept (always 0) only so
 * the run-precedence comparisons read the same as the reference encoder. */
struct count {
	uint16_t bicolor_count;
	uint16_t fill_count;
	uint16_t color_count;
	uint16_t mix_count;
	uint16_t fom_count;
	size_t   fom_mask_len;
};

static void
reset_counts(struct count *c)
{
	memset(c, 0, sizeof *c);
}

/* ---- order-code emitters (port of out_*_count_3) --------------------- */

static uint16_t
out_fill_count(uint16_t n, struct ostrm *s)
{
	if (n > 0) {
		if (n < 32) ow8(s, (uint8_t)(n & 0xff));
		else if (n < 256 + 32) { ow8(s, 0x0); ow8(s, (uint8_t)((n - 32) & 0xff)); }
		else { ow8(s, 0xf0); ow16(s, n); }
	}
	return 0;
}

static uint16_t
out_mix_count(uint16_t n, struct ostrm *s)
{
	if (n > 0) {
		if (n < 32) ow8(s, (uint8_t)(((0x1u << 5) | n) & 0xff));
		else if (n < 256 + 32) { ow8(s, 0x20); ow8(s, (uint8_t)((n - 32) & 0xff)); }
		else { ow8(s, 0xf1); ow16(s, n); }
	}
	return 0;
}

static uint16_t
out_fom_count(uint16_t n, struct ostrm *s, const uint8_t *mask, size_t mask_len)
{
	if (n > 0) {
		if ((n % 8) == 0 && n < 249)
			ow8(s, (uint8_t)(((0x2u << 5) | (n / 8)) & 0xff));
		else if (n < 256) { ow8(s, 0x40); ow8(s, (uint8_t)((n - 1) & 0xff)); }
		else { ow8(s, 0xf2); ow16(s, n); }
		owrite(s, mask, mask_len);
	}
	return 0;
}

static uint16_t
out_color_count(uint16_t n, struct ostrm *s, uint32_t color)
{
	if (n > 0) {
		if (n < 32) ow8(s, (uint8_t)(((0x3u << 5) | n) & 0xff));
		else if (n < 256 + 32) { ow8(s, 0x60); ow8(s, (uint8_t)((n - 32) & 0xff)); }
		else { ow8(s, 0xf3); ow16(s, n); }
		ow8(s, (uint8_t)(color & 0xff));
		ow8(s, (uint8_t)((color >> 8) & 0xff));
		ow8(s, (uint8_t)((color >> 16) & 0xff));
	}
	return 0;
}

/* COLOR IMAGE (literal copy): writes the first n accumulated pixels from temp,
 * then logically resets the literal buffer. */
static uint16_t
out_copy_count(uint16_t n, struct ostrm *s, const uint8_t *temp)
{
	if (n > 0) {
		if (n < 32) ow8(s, (uint8_t)(((0x4u << 5) | n) & 0xff));
		else if (n < 256 + 32) { ow8(s, 0x80); ow8(s, (uint8_t)((n - 32) & 0xff)); }
		else { ow8(s, 0xf4); ow16(s, n); }
		owrite(s, temp, 3ULL * n);
	}
	return 0;
}

/* Read a 24-bpp pixel; x >= width replicates last (edge padding, unused with
 * e == 0). */
static uint32_t
in_pixel(const uint8_t *line, uint32_t x, uint32_t width, uint32_t last)
{
	const uint8_t *p;
	if (line == NULL)
		return 0;
	if (x >= width)
		return last;
	p = line + (size_t)x * 3;
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

int
rdp_bitmap_rle_compress_24(uint8_t *dst, size_t cap, size_t *out_len,
    const uint8_t *src, uint32_t width, uint32_t height)
{
	uint8_t fom_mask[RLE_MAX_PIX / 8 + 16];
	uint8_t temp[RLE_MAX_PIX * 3];
	struct ostrm s = { dst, 0, cap, 0 };
	struct count counts;
	const uint32_t mix = 0xFFFFFF;
	uint16_t count = 0;
	uint32_t last_pixel = 0, last_ypixel = 0;
	uint32_t end = width;          /* e == 0 */
	uint32_t out_count = end * 3;
	const uint8_t *start = src;
	const uint8_t *line, *last_line = NULL;
	uint32_t start_line;

	if (width == 0 || height == 0 || width > RLE_MAX_DIM ||
	    height > RLE_MAX_DIM)
		return -1;
	memset(&counts, 0, sizeof counts);
	memset(fom_mask, 0, sizeof fom_mask);
	start_line = height - 1;
	line = start + 3ULL * width * start_line;

	while ((line >= start) && (out_count < 32768)) {
		size_t i = s.pos + 3ULL * count;
		uint32_t j;

		if ((i - 3ULL * counts.color_count >= cap) &&
		    (i - 3ULL * counts.bicolor_count >= cap) &&
		    (i - 3ULL * counts.fill_count >= cap) &&
		    (i - 3ULL * counts.mix_count >= cap) &&
		    (i - 3ULL * counts.fom_count >= cap))
			break;

		out_count += end * 3;

		for (j = 0; j < end; j++) {
			uint32_t pixel = in_pixel(line, j, width, last_pixel);
			uint32_t ypixel = in_pixel(last_line, j, width, last_ypixel);
			int test_fill = (last_line == NULL && pixel == 0) ||
			    (last_line != NULL && pixel == ypixel);
			int test_mix = (last_line == NULL && pixel == mix) ||
			    (last_line != NULL && pixel == (ypixel ^ mix));
			int test_fom = test_fill || test_mix;
			int test_color = (pixel == last_pixel);

			if (!test_fill) {
				if (counts.fill_count > 3 &&
				    counts.fill_count >= counts.color_count &&
				    counts.fill_count >= counts.bicolor_count &&
				    counts.fill_count >= counts.mix_count &&
				    counts.fill_count >= counts.fom_count) {
					if (counts.fill_count > count) return -1;
					count = (uint16_t)(count - counts.fill_count);
					count = out_copy_count(count, &s, temp);
					counts.fill_count = out_fill_count(counts.fill_count, &s);
					reset_counts(&counts);
				}
				counts.fill_count = 0;
			}
			if (!test_mix) {
				if (counts.mix_count > 3 &&
				    counts.mix_count >= counts.fill_count &&
				    counts.mix_count >= counts.bicolor_count &&
				    counts.mix_count >= counts.color_count &&
				    counts.mix_count >= counts.fom_count) {
					if (counts.mix_count > count) return -1;
					count = (uint16_t)(count - counts.mix_count);
					count = out_copy_count(count, &s, temp);
					counts.mix_count = out_mix_count(counts.mix_count, &s);
					reset_counts(&counts);
				}
				counts.mix_count = 0;
			}
			if (!test_color) {
				if (counts.color_count > 3 &&
				    counts.color_count >= counts.fill_count &&
				    counts.color_count >= counts.bicolor_count &&
				    counts.color_count >= counts.mix_count &&
				    counts.color_count >= counts.fom_count) {
					if (counts.color_count > count) return -1;
					count = (uint16_t)(count - counts.color_count);
					count = out_copy_count(count, &s, temp);
					counts.color_count = out_color_count(counts.color_count, &s, last_pixel);
					reset_counts(&counts);
				}
				counts.color_count = 0;
			}
			if (!test_fom) {
				if (counts.fom_count > 3 &&
				    counts.fom_count >= counts.fill_count &&
				    counts.fom_count >= counts.color_count &&
				    counts.fom_count >= counts.mix_count &&
				    counts.fom_count >= counts.bicolor_count) {
					if (counts.fom_count > count) return -1;
					count = (uint16_t)(count - counts.fom_count);
					count = out_copy_count(count, &s, temp);
					counts.fom_count = out_fom_count(counts.fom_count, &s, fom_mask, counts.fom_mask_len);
					reset_counts(&counts);
				}
				counts.fom_count = 0;
				counts.fom_mask_len = 0;
			}

			if (test_fill) counts.fill_count++;
			if (test_mix) counts.mix_count++;
			if (test_color) counts.color_count++;
			if (test_fom) {
				if ((counts.fom_count % 8) == 0) {
					fom_mask[counts.fom_mask_len] = 0;
					counts.fom_mask_len++;
				}
				if (pixel == (ypixel ^ mix)) {
					uint8_t tmp = (uint8_t)((1u << (counts.fom_count % 8)) & 0xff);
					fom_mask[counts.fom_mask_len - 1] |= tmp;
				}
				counts.fom_count++;
			}

			temp[count * 3 + 0] = (uint8_t)(pixel & 0xff);
			temp[count * 3 + 1] = (uint8_t)((pixel >> 8) & 0xff);
			temp[count * 3 + 2] = (uint8_t)((pixel >> 16) & 0xff);
			count++;
			last_pixel = pixel;
			last_ypixel = ypixel;
		}

		/* The fill, mix and fom runs cannot cross into the first line. */
		if (last_line == NULL) {
			if (counts.fill_count > 3 &&
			    counts.fill_count >= counts.color_count &&
			    counts.fill_count >= counts.bicolor_count &&
			    counts.fill_count >= counts.mix_count &&
			    counts.fill_count >= counts.fom_count) {
				if (counts.fill_count > count) return -1;
				count = (uint16_t)(count - counts.fill_count);
				count = out_copy_count(count, &s, temp);
				counts.fill_count = out_fill_count(counts.fill_count, &s);
				reset_counts(&counts);
			}
			counts.fill_count = 0;
			if (counts.mix_count > 3 &&
			    counts.mix_count >= counts.fill_count &&
			    counts.mix_count >= counts.bicolor_count &&
			    counts.mix_count >= counts.color_count &&
			    counts.mix_count >= counts.fom_count) {
				if (counts.mix_count > count) return -1;
				count = (uint16_t)(count - counts.mix_count);
				count = out_copy_count(count, &s, temp);
				counts.mix_count = out_mix_count(counts.mix_count, &s);
				reset_counts(&counts);
			}
			counts.mix_count = 0;
			if (counts.fom_count > 3 &&
			    counts.fom_count >= counts.fill_count &&
			    counts.fom_count >= counts.color_count &&
			    counts.fom_count >= counts.mix_count &&
			    counts.fom_count >= counts.bicolor_count) {
				if (counts.fom_count > count) return -1;
				count = (uint16_t)(count - counts.fom_count);
				count = out_copy_count(count, &s, temp);
				counts.fom_count = out_fom_count(counts.fom_count, &s, fom_mask, counts.fom_mask_len);
				reset_counts(&counts);
			}
			counts.fom_count = 0;
			counts.fom_mask_len = 0;
		}

		last_line = line;
		if (line == start)
			break;
		line = line - 3ULL * width;
		start_line--;
	}

	/* Flush the final pending run / literals. */
	if (counts.fill_count > 3 &&
	    counts.fill_count >= counts.color_count &&
	    counts.fill_count >= counts.bicolor_count &&
	    counts.fill_count >= counts.mix_count &&
	    counts.fill_count >= counts.fom_count) {
		if (counts.fill_count > count) return -1;
		count = (uint16_t)(count - counts.fill_count);
		(void)out_copy_count(count, &s, temp);
		counts.fill_count = out_fill_count(counts.fill_count, &s);
	} else if (counts.mix_count > 3 &&
	    counts.mix_count >= counts.color_count &&
	    counts.mix_count >= counts.bicolor_count &&
	    counts.mix_count >= counts.fill_count &&
	    counts.mix_count >= counts.fom_count) {
		if (counts.mix_count > count) return -1;
		count = (uint16_t)(count - counts.mix_count);
		(void)out_copy_count(count, &s, temp);
		counts.mix_count = out_mix_count(counts.mix_count, &s);
	} else if (counts.color_count > 3 &&
	    counts.color_count >= counts.mix_count &&
	    counts.color_count >= counts.bicolor_count &&
	    counts.color_count >= counts.fill_count &&
	    counts.color_count >= counts.fom_count) {
		if (counts.color_count > count) return -1;
		count = (uint16_t)(count - counts.color_count);
		(void)out_copy_count(count, &s, temp);
		counts.color_count = out_color_count(counts.color_count, &s, last_pixel);
	} else if (counts.fom_count > 3 &&
	    counts.fom_count >= counts.mix_count &&
	    counts.fom_count >= counts.color_count &&
	    counts.fom_count >= counts.fill_count &&
	    counts.fom_count >= counts.bicolor_count) {
		if (counts.fom_count > count) return -1;
		count = (uint16_t)(count - counts.fom_count);
		(void)out_copy_count(count, &s, temp);
		counts.fom_count = out_fom_count(counts.fom_count, &s, fom_mask, counts.fom_mask_len);
	} else {
		(void)out_copy_count(count, &s, temp);
	}

	if (s.ovf)
		return -1;
	*out_len = s.pos;
	return 0;
}

/* ---- independent decoder (MS-RDPBCGR 3.1.9, for the round-trip test) -- */

struct istrm {
	const uint8_t *buf;
	size_t pos;
	size_t len;
};

static int
ir8(struct istrm *s, uint8_t *v)
{
	if (s->pos >= s->len) return -1;
	*v = s->buf[s->pos++];
	return 0;
}

static int
ir16(struct istrm *s, uint16_t *v)
{
	uint8_t a, b;
	if (ir8(s, &a) != 0 || ir8(s, &b) != 0) return -1;
	*v = (uint16_t)(a | (b << 8));
	return 0;
}

static int
ir_pixel(struct istrm *s, uint32_t *v)
{
	uint8_t a, b, c;
	if (ir8(s, &a) != 0 || ir8(s, &b) != 0 || ir8(s, &c) != 0) return -1;
	*v = (uint32_t)a | ((uint32_t)b << 8) | ((uint32_t)c << 16);
	return 0;
}

int
rdp_bitmap_rle_decompress_24(uint8_t *dst, size_t dst_len, const uint8_t *src,
    size_t src_len, uint32_t width, uint32_t height)
{
	struct istrm s = { src, 0, src_len };
	uint32_t fg = 0xFFFFFF;
	size_t out = 0;           /* pixels produced */
	size_t total = (size_t)width * height;
	int first = 1;            /* on the first scanline there is no "above" */

	/* total * 3 must not overflow size_t, or the dst_len check below could
	 * pass for a tiny buffer while the real pixel count is enormous. */
	if (width == 0 || height == 0 || total > SIZE_MAX / 3 ||
	    dst_len < total * 3)
		return -1;

#define ABOVE() ((uint32_t)(first ? 0 : \
	((uint32_t)dst[(out - width) * 3] | \
	 ((uint32_t)dst[(out - width) * 3 + 1] << 8) | \
	 ((uint32_t)dst[(out - width) * 3 + 2] << 16))))
#define PUT(px) do { \
	if (out >= total) return -1; \
	dst[out * 3] = (uint8_t)((px) & 0xff); \
	dst[out * 3 + 1] = (uint8_t)(((px) >> 8) & 0xff); \
	dst[out * 3 + 2] = (uint8_t)(((px) >> 16) & 0xff); \
	out++; \
	if ((out % width) == 0) first = 0; \
} while (0)
#define FOM_RUN(RUNLEN) do { \
	uint32_t mlen_ = ((RUNLEN) + 7) / 8; \
	for (k = 0; k < (RUNLEN); k++) { \
		uint8_t mb_; \
		if (s.pos + (k / 8) >= s.len) return -1; \
		mb_ = s.buf[s.pos + (k / 8)]; \
		if (mb_ & (1u << (k % 8))) PUT(ABOVE() ^ fg); else PUT(ABOVE()); \
	} \
	s.pos += mlen_; \
} while (0)

	while (s.pos < s.len) {
		uint8_t hdr, e;
		uint32_t code, n, col, c1, c2;
		uint16_t nn;
		size_t k;

		if (ir8(&s, &hdr) != 0) break;
		code = hdr >> 5;
		switch (code) {
		case 0:                                  /* FILL (background) */
			n = hdr & 0x1f;
			if (n == 0) { if (ir8(&s, &e)) return -1; n = (uint32_t)e + 32; }
			for (k = 0; k < n; k++) PUT(ABOVE());
			break;
		case 1:                                  /* MIX (foreground) */
			n = hdr & 0x1f;
			if (n == 0) { if (ir8(&s, &e)) return -1; n = (uint32_t)e + 32; }
			for (k = 0; k < n; k++) PUT(ABOVE() ^ fg);
			break;
		case 2:                                  /* FOM (fill or mix) */
			n = hdr & 0x1f;
			if (n == 0) { if (ir8(&s, &e)) return -1; n = (uint32_t)e + 1; }
			else n *= 8;
			FOM_RUN(n);
			break;
		case 3:                                  /* COLOR run */
			n = hdr & 0x1f;
			if (n == 0) { if (ir8(&s, &e)) return -1; n = (uint32_t)e + 32; }
			if (ir_pixel(&s, &col)) return -1;
			for (k = 0; k < n; k++) PUT(col);
			break;
		case 4:                                  /* COLOR IMAGE (literal) */
			n = hdr & 0x1f;
			if (n == 0) { if (ir8(&s, &e)) return -1; n = (uint32_t)e + 32; }
			for (k = 0; k < n; k++) {
				uint32_t px;
				if (ir_pixel(&s, &px)) return -1;
				PUT(px);
			}
			break;
		case 7:
			if (hdr < 0xf0) {                /* BICOLOR (0xe0..0xef) */
				n = hdr & 0x0f;
				if (n == 0) { if (ir8(&s, &e)) return -1; n = (uint32_t)e + 16; }
				n *= 2;
				if (ir_pixel(&s, &c1) || ir_pixel(&s, &c2)) return -1;
				/* The run starts with the second colour field. */
				for (k = 0; k < n; k++) PUT((k & 1) ? c1 : c2);
				break;
			}
			switch (hdr) {                   /* MEGA forms (0xf0..) */
			case 0xf0:
				if (ir16(&s, &nn)) return -1;
				for (k = 0; k < nn; k++) PUT(ABOVE());
				break;
			case 0xf1:
				if (ir16(&s, &nn)) return -1;
				for (k = 0; k < nn; k++) PUT(ABOVE() ^ fg);
				break;
			case 0xf2:
				if (ir16(&s, &nn)) return -1;
				n = nn;
				FOM_RUN(n);
				break;
			case 0xf3:
				if (ir16(&s, &nn)) return -1;
				if (ir_pixel(&s, &col)) return -1;
				for (k = 0; k < nn; k++) PUT(col);
				break;
			case 0xf4:
				if (ir16(&s, &nn)) return -1;
				for (k = 0; k < nn; k++) {
					uint32_t px;
					if (ir_pixel(&s, &px)) return -1;
					PUT(px);
				}
				break;
			case 0xf8:
				if (ir16(&s, &nn)) return -1;
				if (ir_pixel(&s, &c1) || ir_pixel(&s, &c2)) return -1;
				for (k = 0; k < (uint32_t)nn * 2; k++)
					PUT((k & 1) ? c1 : c2);
				break;
			default:
				return -1;
			}
			break;
		default:                                 /* 5,6: not emitted here */
			return -1;
		}
	}

#undef ABOVE
#undef PUT
#undef FOM_RUN
	return (out == total) ? 0 : -1;
}
