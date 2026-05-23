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
 * font.h -- embedded bitmap font for the greeter.
 *
 * Glyphs are 8 columns wide and RDP_FONT_HEIGHT rows tall.  Each row
 * is one byte; bit 7 (0x80) is the leftmost pixel.  Indices are
 * `code - 0x20`, covering printable ASCII (' ' through '~').
 *
 * Font is extracted from a public-domain PSF v1 console font; see
 * tools/mkfont.py and the generated src/greeter/font.c.
 */

#ifndef RDP_FONT_H
#define RDP_FONT_H

#include <stdint.h>

#define RDP_FONT_WIDTH       8
#define RDP_FONT_HEIGHT     16
#define RDP_FONT_NUM_GLYPHS 95   /* 0x20 .. 0x7E inclusive */

extern const uint8_t rdp_font_data[RDP_FONT_NUM_GLYPHS][RDP_FONT_HEIGHT];

/* Returns the glyph row pattern (8 bits packed MSB-first) for the
 * given printable-ASCII codepoint and row.  Codepoints outside the
 * supported range return an empty row (zero). */
static inline uint8_t
rdp_font_row(uint32_t cp, int row)
{
	if (cp < 0x20 || cp > 0x7E) return 0;
	if (row < 0 || row >= RDP_FONT_HEIGHT) return 0;
	return rdp_font_data[cp - 0x20][row];
}

#endif /* RDP_FONT_H */
