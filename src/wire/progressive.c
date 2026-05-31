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
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 */
/*
 * progressive.c -- CAPROGRESSIVE encoder.
 *
 * Pipeline: BGR -> YCbCr (11.5 fixed-point) -> 64x64 tile
 *           -> CDF 9/7 forward DWT (3 levels) -> quantization
 *           -> linearization -> RLGR2 -> RFX_TILE_SIMPLE
 *           -> RFX_PROGRESSIVE wrapper.
 *
 * Wire structure (MS-RDPRFX 3.1.8):
 *   SYNC magic=0xCACCACCA version=0x0100
 *   CONTEXT ctxId=0 tileSize=64 flags=0
 *   FRAME_BEGIN frameIndex regionCount=1
 *   REGION rects, quants, tile_simple blocks
 *   FRAME_END
 */

#include "progressive.h"

#include <stdlib.h>
#include <string.h>

#define TILE_SIZE 64
#define TILE_PIXELS (TILE_SIZE * TILE_SIZE)

struct rdp_progressive {
	uint16_t width;
	uint16_t height;
	uint32_t frame_index;
	uint8_t *out_buf;
	size_t   out_cap;
	size_t   out_len;
	/* Per-tile scratch.  4096 INT16 = 8 KB per plane * 3 + dwt scratch. */
	int16_t  y_buf[TILE_PIXELS];
	int16_t  cb_buf[TILE_PIXELS];
	int16_t  cr_buf[TILE_PIXELS];
	int16_t  dwt_scratch[TILE_PIXELS];
};

/*
 * Convert a 64x64 BGR24 (top-down) tile to three INT16 planes in
 * 11.5 fixed-point YCbCr (per MS-RDPRFX 3.1.8.1.1, ITU-R BT.601).
 *
 * Coefficients scaled by << 15 and the per-pixel result shifted >> 10
 * so that the final values are scaled by << 5 (11.5 fixed-point).
 * For tiles smaller than 64x64 the right/bottom edges are filled
 * with replicated edge pixels.
 */
static void
tile_bgr_to_ycbcr(struct rdp_progressive *p,
		const uint8_t *bgr, size_t row_stride,
		uint16_t tx, uint16_t ty, uint16_t tw, uint16_t th)
{
	int16_t *y = p->y_buf;
	int16_t *cb = p->cb_buf;
	int16_t *cr = p->cr_buf;
	uint16_t i, j;

	for (j = 0; j < TILE_SIZE; j++) {
		uint16_t src_y = (uint16_t)(ty + (j < th ? j : th - 1));
		const uint8_t *row = bgr + (size_t)src_y * row_stride;
		for (i = 0; i < TILE_SIZE; i++) {
			uint16_t src_x = (uint16_t)(tx
				+ (i < tw ? i : tw - 1));
			const uint8_t *px = row + (size_t)src_x * 3;
			int32_t b = px[0];
			int32_t g = px[1];
			int32_t r = px[2];
			int32_t cy = (r *   9798 + g *  19235 + b *  3735) >> 10;
			int32_t ccb = (r * -5535 + g * -10868 + b * 16403) >> 10;
			int32_t ccr = (r * 16377 + g * -13714 + b * -2663) >> 10;
			cy -= 4096;
			if (cy < -4096) cy = -4096;
			if (cy >  4095) cy =  4095;
			if (ccb < -4096) ccb = -4096;
			if (ccb >  4095) ccb =  4095;
			if (ccr < -4096) ccr = -4096;
			if (ccr >  4095) ccr =  4095;
			*y++ = (int16_t)cy;
			*cb++ = (int16_t)ccb;
			*cr++ = (int16_t)ccr;
		}
	}
}

/*
 * CDF 9/7 forward DWT lifting scheme (per MS-RDPRFX 3.1.8.1.2).
 * Operates in place on a buffer of (subband_width*2)^2 INT16 samples.
 * Uses dwt[] as a temporary; after this call buffer[] holds
 * HL(0..N-1), LH(N..2N-1), HH(2N..3N-1), LL(3N..4N-1) where N =
 * subband_width^2.
 *
 * Algorithm: vertical pass first (writes L/H bands to dwt), then
 * horizontal pass on each band (writes sub-bands to buffer).
 */
static void
dwt_2d_encode_block(int16_t *buffer, int16_t *dwt,
		uint32_t subband_width)
{
	const uint32_t total_width = subband_width * 2;
	uint32_t x, n;
	uint32_t y;
	int16_t *ll, *hl, *lh, *hh;
	int16_t *l_src, *h_src;

	/* Vertical pass: 2 sub-bands L,H stored in dwt. */
	for (x = 0; x < total_width; x++) {
		for (n = 0; n < subband_width; n++) {
			uint32_t row = n * 2;
			int16_t *l = dwt + n * total_width + x;
			int16_t *h = l + subband_width * total_width;
			int16_t *src = buffer + row * total_width + x;
			int32_t hv;
			int32_t lv;
			int32_t next = (n < subband_width - 1)
				? src[2 * total_width] : src[0];
			hv = (src[total_width]
				- ((src[0] + next) >> 1)) >> 1;
			*h = (int16_t)hv;
			lv = src[0]
				+ (n == 0
				    ? *h
				    : ((*(h - total_width) + *h) >> 1));
			*l = (int16_t)lv;
		}
	}

	/* Horizontal pass: 4 sub-bands HL,LH,HH,LL written to buffer. */
	ll = buffer + 3 * subband_width * subband_width;
	hl = buffer;
	l_src = dwt;
	lh = buffer + subband_width * subband_width;
	hh = buffer + 2 * subband_width * subband_width;
	h_src = dwt + 2 * subband_width * subband_width;

	for (y = 0; y < subband_width; y++) {
		for (n = 0; n < subband_width; n++) {
			uint32_t col = n * 2;
			int16_t next = (int16_t)((n < subband_width - 1)
				? l_src[col + 2] : l_src[col]);
			int32_t hv = (l_src[col + 1]
				- ((l_src[col] + next) >> 1)) >> 1;
			hl[n] = (int16_t)hv;
			ll[n] = (int16_t)(l_src[col]
				+ (n == 0
				    ? hl[n]
				    : ((hl[n - 1] + hl[n]) >> 1)));
		}
		for (n = 0; n < subband_width; n++) {
			uint32_t col = n * 2;
			int16_t next = (int16_t)((n < subband_width - 1)
				? h_src[col + 2] : h_src[col]);
			int32_t hv = (h_src[col + 1]
				- ((h_src[col] + next) >> 1)) >> 1;
			hh[n] = (int16_t)hv;
			lh[n] = (int16_t)(h_src[col]
				+ (n == 0
				    ? hh[n]
				    : ((hh[n - 1] + hh[n]) >> 1)));
		}
		ll += subband_width;
		hl += subband_width;
		l_src += total_width;
		lh += subband_width;
		hh += subband_width;
		h_src += total_width;
	}
}

/*
 * Apply 3-level forward DWT to a 64x64 plane in place.
 * After this call the buffer layout is:
 *   offset    0..1023: HL1
 *   offset 1024..2047: LH1
 *   offset 2048..3071: HH1
 *   offset 3072..3327: HL2
 *   offset 3328..3583: LH2
 *   offset 3584..3839: HH2
 *   offset 3840..3903: HL3
 *   offset 3904..3967: LH3
 *   offset 3968..4031: HH3
 *   offset 4032..4095: LL3
 */
static void
dwt_2d_encode(int16_t *buffer, int16_t *scratch)
{
	dwt_2d_encode_block(buffer + 0,    scratch, 32);
	dwt_2d_encode_block(buffer + 3072, scratch, 16);
	dwt_2d_encode_block(buffer + 3840, scratch,  8);
}

/*
 * Standard "quality 100" quantization values (LL3, LH3, HL3, HH3,
 * LH2, HL2, HH2, LH1, HL1, HH1) per MS-RDPRFX.  Value 6 means no
 * sub-band quantization (only the implicit >>5 to undo the 11.5
 * fixed-point scale).
 */
static const uint8_t default_quant[10] = {
	6, 6, 6, 6, 6, 6, 6, 6, 6, 6
};

static void
quantize_block(int16_t *buf, size_t n, uint8_t factor)
{
	if (factor == 0) return;
	int16_t half = (int16_t)(1 << (factor - 1));
	size_t i;
	for (i = 0; i < n; i++)
		buf[i] = (int16_t)((buf[i] + half) >> factor);
}

/*
 * Quantize all 10 sub-bands per the quantization table, then apply a
 * final >>5 to the whole buffer to undo the 11.5 fixed-point scaling
 * introduced by the YCbCr conversion.  Quants 0..9 map to
 * LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1, HL1, HH1.
 */
static void
quantize_tile(int16_t *buffer, const uint8_t q[10])
{
	quantize_block(buffer +    0, 1024, (uint8_t)(q[8] - 6)); /* HL1 */
	quantize_block(buffer + 1024, 1024, (uint8_t)(q[7] - 6)); /* LH1 */
	quantize_block(buffer + 2048, 1024, (uint8_t)(q[9] - 6)); /* HH1 */
	quantize_block(buffer + 3072,  256, (uint8_t)(q[5] - 6)); /* HL2 */
	quantize_block(buffer + 3328,  256, (uint8_t)(q[4] - 6)); /* LH2 */
	quantize_block(buffer + 3584,  256, (uint8_t)(q[6] - 6)); /* HH2 */
	quantize_block(buffer + 3840,   64, (uint8_t)(q[2] - 6)); /* HL3 */
	quantize_block(buffer + 3904,   64, (uint8_t)(q[1] - 6)); /* LH3 */
	quantize_block(buffer + 3968,   64, (uint8_t)(q[3] - 6)); /* HH3 */
	quantize_block(buffer + 4032,   64, (uint8_t)(q[0] - 6)); /* LL3 */
	quantize_block(buffer,        4096, 5);
}

/*
 * Differential coding of the LL3 sub-band: each coefficient is
 * replaced by its difference from the previous one (in raster order).
 * Applied as a final step before entropy coding.
 */
static void
differential_encode_ll3(int16_t *buf)
{
	int16_t prev = buf[0];
	size_t i;
	for (i = 1; i < 64; i++) {
		int16_t cur = buf[i];
		buf[i] = (int16_t)(cur - prev);
		prev = cur;
	}
}

/*
 * Bit-level output stream.  Bits are written MSB first; bytes flushed
 * to `buf` as the accumulator fills.  Returns the number of bytes
 * written including any trailing partial byte after flush().
 */
struct bitstream {
	uint8_t *buf;
	size_t   cap;
	size_t   pos;     /* next byte to write */
	uint32_t acc;     /* high-order bits are the next to flush */
	int      bits;    /* count of valid bits in acc, 0..32 */
};

static void
bs_init(struct bitstream *bs, uint8_t *buf, size_t cap)
{
	bs->buf = buf;
	bs->cap = cap;
	bs->pos = 0;
	bs->acc = 0;
	bs->bits = 0;
}

static int
bs_write(struct bitstream *bs, uint32_t value, int nbits)
{
	if (nbits <= 0) return 0;
	value &= (uint32_t)((1ULL << nbits) - 1);
	bs->acc |= value << (32 - bs->bits - nbits);
	bs->bits += nbits;
	while (bs->bits >= 8) {
		if (bs->pos >= bs->cap) return -1;
		bs->buf[bs->pos++] = (uint8_t)(bs->acc >> 24);
		bs->acc <<= 8;
		bs->bits -= 8;
	}
	return 0;
}

static int
bs_flush(struct bitstream *bs)
{
	if (bs->bits > 0) {
		if (bs->pos >= bs->cap) return -1;
		bs->buf[bs->pos++] = (uint8_t)(bs->acc >> 24);
		bs->acc = 0;
		bs->bits = 0;
	}
	return 0;
}

/* RLGR adaptive parameters (per MS-RDPRFX 3.1.8.1.7.3). */
#define RLGR_KPMAX  80
#define RLGR_LSGR    3
#define RLGR_UP_GR   4
#define RLGR_DN_GR   6
#define RLGR_UQ_GR   3
#define RLGR_DQ_GR   3

static uint32_t
rlgr_update_param(uint32_t *param, int delta)
{
	if (delta < 0) {
		uint32_t u = (uint32_t)(-delta);
		*param = (u > *param) ? 0 : (*param - u);
	} else {
		*param += (uint32_t)delta;
		if (*param > RLGR_KPMAX) *param = RLGR_KPMAX;
	}
	return *param >> RLGR_LSGR;
}

static int
rlgr_min_bits(uint32_t v)
{
	int n = 0;
	while (v) { v >>= 1; n++; }
	return n;
}

static int
rlgr_code_gr(struct bitstream *bs, uint32_t *krp, uint32_t val)
{
	uint32_t kr = *krp >> RLGR_LSGR;
	uint32_t vk = val >> kr;
	uint32_t i;
	for (i = 0; i < vk; i++)
		if (bs_write(bs, 1, 1) < 0) return -1;
	if (bs_write(bs, 0, 1) < 0) return -1;
	if (kr > 0) {
		if (bs_write(bs, val & ((1u << kr) - 1), (int)kr) < 0)
			return -1;
	}
	if (vk == 0)
		(void)rlgr_update_param(krp, -2);
	else if (vk > 1)
		(void)rlgr_update_param(krp, (int)vk);
	return 0;
}

/*
 * RLGR1 entropy encoder per MS-RDPRFX 3.1.8.1.7.3.
 * Encodes `data` (data_size INT16 coefficients) into `buffer`.
 * Returns the number of bytes written, or -1 on overflow.
 */
static ssize_t
rlgr1_encode(const int16_t *data, size_t data_size,
		uint8_t *buffer, size_t buffer_size)
{
	struct bitstream bs;
	uint32_t kp = 1u << RLGR_LSGR;
	uint32_t krp = 1u << RLGR_LSGR;
	uint32_t k = kp >> RLGR_LSGR;
	size_t pos = 0;

	bs_init(&bs, buffer, buffer_size);

	while (pos < data_size) {
		int16_t input;
		if (k) {
			/* Run-length mode: count zeros up to next nonzero. */
			uint32_t zeros = 0;
			while (pos < data_size && data[pos] == 0) {
				zeros++;
				pos++;
			}
			while (1) {
				uint32_t runmax = 1u << k;
				if (zeros < runmax) break;
				if (bs_write(&bs, 0, 1) < 0) return -1;
				zeros -= runmax;
				k = rlgr_update_param(&kp, RLGR_UP_GR);
			}
			if (pos >= data_size) {
				/* Trailing run with no nonzero terminator:
				 * emit one terminating '1' bit plus k bits.
				 * Per FreeRDP: mstsc requires these bits. */
				if (bs_write(&bs, 1, 1) < 0) return -1;
				if (bs_write(&bs, zeros, (int)k) < 0)
					return -1;
				break;
			}
			input = data[pos++];
			if (bs_write(&bs, 1, 1) < 0) return -1;
			if (bs_write(&bs, zeros, (int)k) < 0) return -1;
			{
				uint32_t mag = (uint32_t)(input < 0
					? -(int32_t)input : input);
				uint32_t sign = (input < 0) ? 1u : 0u;
				if (bs_write(&bs, sign, 1) < 0) return -1;
				if (rlgr_code_gr(&bs, &krp,
					mag ? mag - 1 : 0) < 0) return -1;
			}
			k = rlgr_update_param(&kp, -RLGR_DN_GR);
		} else {
			/* Golomb-Rice mode (RLGR1 variant). */
			uint32_t twoMs;
			input = data[pos++];
			if (input < 0)
				twoMs = (uint32_t)((-(int32_t)input) * 2 - 1);
			else
				twoMs = (uint32_t)input * 2;
			if (rlgr_code_gr(&bs, &krp, twoMs) < 0) return -1;
			if (twoMs)
				k = rlgr_update_param(&kp, -RLGR_DQ_GR);
			else
				k = rlgr_update_param(&kp, RLGR_UQ_GR);
			(void)rlgr_min_bits;
		}
	}

	if (bs_flush(&bs) < 0) return -1;
	return (ssize_t)bs.pos;
}

struct rdp_progressive *
rdp_progressive_open(uint16_t width, uint16_t height)
{
	struct rdp_progressive *p = calloc(1, sizeof *p);
	if (p == NULL) return NULL;
	p->width = width;
	p->height = height;
	return p;
}

int
rdp_progressive_resize(struct rdp_progressive *p,
		uint16_t width, uint16_t height)
{
	if (p == NULL) return -1;
	p->width = width;
	p->height = height;
	return 0;
}

/*
 * Little-endian byte writers.
 */
static void put_u8(uint8_t **p, uint8_t v)  { *(*p)++ = v; }
static void put_u16(uint8_t **p, uint16_t v)
{
	(*p)[0] = (uint8_t)(v & 0xff);
	(*p)[1] = (uint8_t)((v >> 8) & 0xff);
	*p += 2;
}
static void put_u32(uint8_t **p, uint32_t v)
{
	(*p)[0] = (uint8_t)(v & 0xff);
	(*p)[1] = (uint8_t)((v >> 8) & 0xff);
	(*p)[2] = (uint8_t)((v >> 16) & 0xff);
	(*p)[3] = (uint8_t)((v >> 24) & 0xff);
	*p += 4;
}

/*
 * Pack a 10-nibble quant (LL3, LH3, HL3, HH3, LH2, HL2, HH2, LH1,
 * HL1, HH1 -- in our default_quant order) into the 5-byte RFX wire
 * layout (LL3|HL3, LH3|HH3, HL2|LH2, HH2|HL1, LH1|HH1).
 */
static void
put_quant(uint8_t **p, const uint8_t q[10])
{
	/* q index: 0=LL3 1=LH3 2=HL3 3=HH3 4=LH2 5=HL2 6=HH2 7=LH1 8=HL1 9=HH1 */
	put_u8(p, (uint8_t)((q[0] & 0xf) | ((q[2] & 0xf) << 4)));
	put_u8(p, (uint8_t)((q[1] & 0xf) | ((q[3] & 0xf) << 4)));
	put_u8(p, (uint8_t)((q[5] & 0xf) | ((q[4] & 0xf) << 4)));
	put_u8(p, (uint8_t)((q[6] & 0xf) | ((q[8] & 0xf) << 4)));
	put_u8(p, (uint8_t)((q[7] & 0xf) | ((q[9] & 0xf) << 4)));
}

/* RFX_TILE_SIMPLE block header (22 bytes incl. 6-byte block header). */
static int
write_tile_simple(uint8_t *out, size_t cap, size_t *off,
		uint16_t xIdx, uint16_t yIdx,
		const uint8_t *yData, size_t yLen,
		const uint8_t *cbData, size_t cbLen,
		const uint8_t *crData, size_t crLen)
{
	size_t need = 22 + yLen + cbLen + crLen;
	uint8_t *p;
	if (*off + need > cap) return -1;
	if (yLen > 0xffff || cbLen > 0xffff || crLen > 0xffff) return -1;
	p = out + *off;
	put_u16(&p, 0xCCC5);                      /* blockType */
	put_u32(&p, (uint32_t)need);              /* blockLen */
	put_u8(&p, 0);                            /* quantIdxY */
	put_u8(&p, 0);                            /* quantIdxCb */
	put_u8(&p, 0);                            /* quantIdxCr */
	put_u16(&p, xIdx);
	put_u16(&p, yIdx);
	put_u8(&p, 0);                            /* flags */
	put_u16(&p, (uint16_t)yLen);
	put_u16(&p, (uint16_t)cbLen);
	put_u16(&p, (uint16_t)crLen);
	put_u16(&p, 0);                           /* tailLen */
	memcpy(p, yData, yLen);  p += yLen;
	memcpy(p, cbData, cbLen); p += cbLen;
	memcpy(p, crData, crLen); p += crLen;
	*off = (size_t)(p - out);
	return 0;
}

/*
 * Encode one 64x64 tile.  Pipeline: BGR -> YCbCr -> DWT -> quantize
 * -> diff(LL3) -> RLGR1.  Writes a TILE_SIMPLE block into `out`.
 */
static int
encode_tile(struct rdp_progressive *p,
		const uint8_t *bgr, size_t row_stride,
		uint16_t tx_pix, uint16_t ty_pix,
		uint16_t tw, uint16_t th,
		uint16_t xIdx, uint16_t yIdx,
		uint8_t *out, size_t cap, size_t *off)
{
	uint8_t srl_y[8192], srl_cb[8192], srl_cr[8192];
	ssize_t yLen, cbLen, crLen;

	tile_bgr_to_ycbcr(p, bgr, row_stride, tx_pix, ty_pix, tw, th);

	dwt_2d_encode(p->y_buf, p->dwt_scratch);
	dwt_2d_encode(p->cb_buf, p->dwt_scratch);
	dwt_2d_encode(p->cr_buf, p->dwt_scratch);

	quantize_tile(p->y_buf, default_quant);
	quantize_tile(p->cb_buf, default_quant);
	quantize_tile(p->cr_buf, default_quant);

	differential_encode_ll3(p->y_buf + 4032);
	differential_encode_ll3(p->cb_buf + 4032);
	differential_encode_ll3(p->cr_buf + 4032);

	yLen  = rlgr1_encode(p->y_buf,  TILE_PIXELS, srl_y,  sizeof srl_y);
	cbLen = rlgr1_encode(p->cb_buf, TILE_PIXELS, srl_cb, sizeof srl_cb);
	crLen = rlgr1_encode(p->cr_buf, TILE_PIXELS, srl_cr, sizeof srl_cr);
	if (yLen < 0 || cbLen < 0 || crLen < 0) return -1;

	return write_tile_simple(out, cap, off, xIdx, yIdx,
		srl_y,  (size_t)yLen,
		srl_cb, (size_t)cbLen,
		srl_cr, (size_t)crLen);
}

int
rdp_progressive_encode(struct rdp_progressive *p,
		const uint8_t *bgr, uint16_t width, uint16_t height,
		const uint8_t **out, size_t *out_len)
{
	size_t cap, off, region_off, region_body_off;
	size_t row_stride;
	uint16_t tcols, trows, xi, yi;
	uint16_t numTiles;
	uint32_t tileDataSize;
	uint8_t *q;

	if (p == NULL || bgr == NULL || width == 0 || height == 0)
		return -1;

	tcols = (uint16_t)((width  + TILE_SIZE - 1) / TILE_SIZE);
	trows = (uint16_t)((height + TILE_SIZE - 1) / TILE_SIZE);
	numTiles = (uint16_t)(tcols * trows);

	/* Generous output sizing.  Worst case per tile is rare; alloc
	 * once and reuse next frame. */
	cap = 64 * 1024 + (size_t)numTiles * 8 * 1024;
	if (cap > p->out_cap) {
		uint8_t *nb = realloc(p->out_buf, cap);
		if (nb == NULL) return -1;
		p->out_buf = nb;
		p->out_cap = cap;
	}
	off = 0;
	row_stride = (size_t)width * 3;

	q = p->out_buf + off;
	put_u16(&q, 0xCCC0); put_u32(&q, 12);
	put_u32(&q, 0xCACCACCA); put_u16(&q, 0x0100);
	off += 12;

	q = p->out_buf + off;
	put_u16(&q, 0xCCC3); put_u32(&q, 10);
	put_u8(&q, 0);                        /* ctxId */
	put_u16(&q, 64);                      /* tileSize */
	put_u8(&q, 0);                        /* flags */
	off += 10;

	q = p->out_buf + off;
	put_u16(&q, 0xCCC1); put_u32(&q, 12);
	put_u32(&q, p->frame_index);
	put_u16(&q, 1);                       /* regionCount */
	off += 12;

	/* REGION block: header + (rects=1, quants=1, no progQuant), then
	 * the tile_simple sub-blocks.  blockLen and numTiles/tileDataSize
	 * are patched after tiles are written. */
	region_off = off;
	q = p->out_buf + off;
	put_u16(&q, 0xCCC4);                  /* blockType */
	put_u32(&q, 0);                       /* blockLen (patched) */
	put_u8(&q, 64);                       /* tileSize */
	put_u16(&q, 1);                       /* numRects */
	put_u8(&q, 1);                        /* numQuant */
	put_u8(&q, 0);                        /* numProgQuant */
	put_u8(&q, 0);                        /* flags */
	put_u16(&q, numTiles);                /* numTiles */
	put_u32(&q, 0);                       /* tileDataSize (patched) */
	/* single rect spanning the frame */
	put_u16(&q, 0); put_u16(&q, 0);
	put_u16(&q, width); put_u16(&q, height);
	/* single quant entry */
	put_quant(&q, default_quant);
	off = (size_t)(q - p->out_buf);
	region_body_off = off;

	tileDataSize = 0;
	for (yi = 0; yi < trows; yi++) {
		for (xi = 0; xi < tcols; xi++) {
			uint16_t tx = (uint16_t)(xi * TILE_SIZE);
			uint16_t ty = (uint16_t)(yi * TILE_SIZE);
			uint16_t tw = (uint16_t)(width  - tx);
			uint16_t th = (uint16_t)(height - ty);
			size_t prev = off;
			if (tw > TILE_SIZE) tw = TILE_SIZE;
			if (th > TILE_SIZE) th = TILE_SIZE;
			if (encode_tile(p, bgr, row_stride,
				tx, ty, tw, th, xi, yi,
				p->out_buf, p->out_cap, &off) != 0)
				return -1;
			tileDataSize += (uint32_t)(off - prev);
		}
	}

	/* Patch region blockLen and tileDataSize. */
	{
		uint32_t region_len = (uint32_t)(off - region_off);
		uint8_t *r = p->out_buf + region_off + 2;
		put_u32(&r, region_len);
		/*
		 * tileDataSize is at region_off + 14: blockType(2) + blockLen(4)
		 * + tileSize(1) + numRects(2) + numQuant(1) + numProgQuant(1)
		 * + flags(1) + numTiles(2) = 14.  The block header is 6 bytes,
		 * not 8.
		 */
		r = p->out_buf + region_off + 14;
		put_u32(&r, tileDataSize);
		(void)region_body_off;
	}

	/* FRAME_END. */
	if (off + 6 > p->out_cap) return -1;
	q = p->out_buf + off;
	put_u16(&q, 0xCCC2); put_u32(&q, 6);
	off += 6;

	p->frame_index++;
	p->out_len = off;
	*out = p->out_buf;
	*out_len = off;
	return 0;
}

void
rdp_progressive_close(struct rdp_progressive *p)
{
	if (p == NULL) return;
	free(p->out_buf);
	free(p);
}
