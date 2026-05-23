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
 * paint.c -- drawing helpers.
 */

#include "paint.h"
#include "font.h"

#include <string.h>

static int
clamp(int v, int lo, int hi)
{
	if (v < lo) return lo;
	if (v > hi) return hi;
	return v;
}

static int
clip_rect(const struct rdp_fb *fb, struct rdp_rect *r)
{
	int x0 = clamp(r->x, 0, fb->w);
	int y0 = clamp(r->y, 0, fb->h);
	int x1 = clamp(r->x + r->w, 0, fb->w);
	int y1 = clamp(r->y + r->h, 0, fb->h);
	r->x = x0;
	r->y = y0;
	r->w = x1 - x0;
	r->h = y1 - y0;
	return r->w > 0 && r->h > 0;
}

void
rdp_paint_fill(struct rdp_fb *fb, struct rdp_rect r,
		uint8_t b, uint8_t g, uint8_t rd)
{
	int yy, xx;
	if (!clip_rect(fb, &r)) return;
	for (yy = 0; yy < r.h; yy++) {
		uint8_t *row = fb->data + (size_t)(r.y + yy) * fb->w * 3
			+ (size_t)r.x * 3;
		for (xx = 0; xx < r.w; xx++) {
			row[xx * 3 + 0] = b;
			row[xx * 3 + 1] = g;
			row[xx * 3 + 2] = rd;
		}
	}
}

void
rdp_paint_rect_outline(struct rdp_fb *fb, struct rdp_rect r,
		uint8_t b, uint8_t g, uint8_t rd)
{
	struct rdp_rect top = { r.x, r.y, r.w, 1 };
	struct rdp_rect bot = { r.x, r.y + r.h - 1, r.w, 1 };
	struct rdp_rect left = { r.x, r.y, 1, r.h };
	struct rdp_rect right = { r.x + r.w - 1, r.y, 1, r.h };

	rdp_paint_fill(fb, top, b, g, rd);
	rdp_paint_fill(fb, bot, b, g, rd);
	rdp_paint_fill(fb, left, b, g, rd);
	rdp_paint_fill(fb, right, b, g, rd);
}

void
rdp_paint_glyph(struct rdp_fb *fb, int x, int y, uint32_t cp,
		uint8_t b, uint8_t g, uint8_t rd)
{
	int row, col;
	for (row = 0; row < RDP_FONT_HEIGHT; row++) {
		int py = y + row;
		uint8_t bits;
		if (py < 0 || py >= fb->h) continue;
		bits = rdp_font_row(cp, row);
		if (bits == 0) continue;
		for (col = 0; col < RDP_FONT_WIDTH; col++) {
			int px = x + col;
			uint8_t *p;
			if (px < 0 || px >= fb->w) continue;
			if ((bits & (0x80 >> col)) == 0) continue;
			p = fb->data + (size_t)py * fb->w * 3
				+ (size_t)px * 3;
			p[0] = b; p[1] = g; p[2] = rd;
		}
	}
}

void
rdp_paint_string(struct rdp_fb *fb, int x, int y,
		const char *s, uint8_t b, uint8_t g, uint8_t rd)
{
	while (*s != '\0') {
		rdp_paint_glyph(fb, x, y, (uint8_t)*s, b, g, rd);
		x += RDP_FONT_WIDTH;
		s++;
	}
}

void
rdp_rect_union(struct rdp_rect *acc, struct rdp_rect r)
{
	int x1, y1, ax1, ay1;
	if (r.w <= 0 || r.h <= 0) return;
	if (acc->w <= 0 || acc->h <= 0) { *acc = r; return; }
	x1 = r.x + r.w;
	y1 = r.y + r.h;
	ax1 = acc->x + acc->w;
	ay1 = acc->y + acc->h;
	if (r.x  < acc->x) acc->x = r.x;
	if (r.y  < acc->y) acc->y = r.y;
	if (x1   > ax1)    ax1 = x1;
	if (y1   > ay1)    ay1 = y1;
	acc->w = ax1 - acc->x;
	acc->h = ay1 - acc->y;
}

int
rdp_rect_empty(const struct rdp_rect *r)
{
	return r->w <= 0 || r->h <= 0;
}

void
rdp_rect_reset(struct rdp_rect *r)
{
	r->x = r->y = r->w = r->h = 0;
}
