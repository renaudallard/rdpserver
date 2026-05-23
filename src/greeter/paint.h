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
 * paint.h -- drawing helpers for the greeter framebuffer.
 *
 * Framebuffer layout is 24-bit BGR, top-down, w * 3 bytes per row.
 * (We pack the inverse-row ordering at PDU encode time in
 * fastpath.c, so callers think top-down.)
 */

#ifndef RDP_PAINT_H
#define RDP_PAINT_H

#include "../include/compat.h"
#include "../include/rdp_types.h"

#include <stddef.h>
#include <stdint.h>

struct rdp_fb {
	uint8_t  *data;        /* w * h * 3 bytes BGR top-down */
	uint16_t  w, h;
};

void rdp_paint_fill(struct rdp_fb *fb, struct rdp_rect r,
		uint8_t b, uint8_t g, uint8_t rd);
void rdp_paint_rect_outline(struct rdp_fb *fb, struct rdp_rect r,
		uint8_t b, uint8_t g, uint8_t rd);

/* Draw a single glyph at (x, y).  Bits in the font are foreground;
 * background pixels are skipped (so transparent over current bg). */
void rdp_paint_glyph(struct rdp_fb *fb, int x, int y, uint32_t cp,
		uint8_t b, uint8_t g, uint8_t rd);

/* Draw a NUL-terminated ASCII string left-to-right. */
void rdp_paint_string(struct rdp_fb *fb, int x, int y,
		const char *s, uint8_t b, uint8_t g, uint8_t rd);

/* Union helper for tracking dirty regions. */
void rdp_rect_union(struct rdp_rect *acc, struct rdp_rect r);
int  rdp_rect_empty(const struct rdp_rect *r);
void rdp_rect_reset(struct rdp_rect *r);

#endif /* RDP_PAINT_H */
