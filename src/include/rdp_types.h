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
 * rdp_types.h -- common value types used across the codebase.
 *
 * The wire engine, the backends, and the greeter all talk in terms
 * of these types.  Keep this header dependency-free: just stdint.h
 * and stddef.h, no transitive pulls.
 */

#ifndef RDP_TYPES_H
#define RDP_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* Inclusive-exclusive axis-aligned rectangle. */
struct rdp_rect {
	int32_t x;
	int32_t y;
	int32_t w;
	int32_t h;
};

/* Pixel format on the wire between the wire engine and a backend.
 * Always ARGB32 little-endian; backends do any conversion they need. */
struct rdp_pixmap {
	uint8_t        *data;     /* row 0 is top */
	uint32_t        stride;   /* bytes per row */
	struct rdp_rect bounds;   /* extent in pixels */
};

struct rdp_pixmap_view {
	const uint8_t  *data;
	uint32_t        stride;
	struct rdp_rect bounds;
	void           *handle;   /* opaque to caller; backend uses on release */
};

/* Display mode advertised by a backend. */
struct rdp_mode {
	uint32_t width;
	uint32_t height;
	uint8_t  bpp;         /* always 32 in v1; reserved for v2 */
	uint8_t  pad[3];
};

#endif /* RDP_TYPES_H */
