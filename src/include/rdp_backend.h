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
 * rdp_backend.h -- display backend abstraction (vtable).
 *
 * The wire engine produces RDP PDUs from damage rectangles supplied
 * by a backend, and injects input via the backend's ops.  Three
 * backends are anticipated:
 *
 *   x11_xvfb (v1)  spawns Xvfb, captures via XShm + XDamage,
 *                  injects via XTest.
 *   xrdpdev  (v1.x) a real Xorg DDX module so we don't pay the
 *                   Xvfb shadow penalty.  Same vtable.
 *   wayland  (v2)  embeds a Wayland compositor or talks PipeWire +
 *                  libei.
 *
 * Pixel format on the wire to the wire engine is ARGB32 little-endian
 * (so the most-significant byte is alpha, then red, then green, then
 * blue in memory order).  Backends do any needed conversion.
 */

#ifndef RDP_BACKEND_H
#define RDP_BACKEND_H

#include "rdp_types.h"

struct rdp_backend;
struct rdp_backend_ops;

struct rdp_backend_cfg {
	uint32_t width;
	uint32_t height;
	uint8_t  bpp;          /* 24 or 32 */
	char     display[64];  /* X DISPLAY string for X11 backends */
};

struct rdp_damage {
	uint32_t        nrects;
	struct rdp_rect rects[16];
};

struct rdp_cursor {
	uint16_t width;
	uint16_t height;
	uint16_t hot_x;
	uint16_t hot_y;
	const uint8_t *xor_mask;
	const uint8_t *and_mask;
};

struct rdp_clip_offer {
	uint32_t      formats;       /* bitmap of CF_TEXT, CF_UNICODETEXT */
	const uint8_t *probe;        /* optional preview */
	size_t        probe_len;
};

struct rdp_buf;

struct rdp_backend_ops {
	int  (*open)(struct rdp_backend *be, const struct rdp_backend_cfg *cfg);
	void (*close)(struct rdp_backend *be);

	int  (*get_modes)(struct rdp_backend *be,
			struct rdp_mode *out, size_t max, size_t *count);
	int  (*set_mode)(struct rdp_backend *be, const struct rdp_mode *m);

	int  (*pump)(struct rdp_backend *be, int timeout_ms,
			struct rdp_damage *out);
	int  (*acquire_region)(struct rdp_backend *be,
			const struct rdp_rect *r,
			struct rdp_pixmap_view *out);
	void (*release_region)(struct rdp_backend *be,
			struct rdp_pixmap_view *view);

	int  (*key)(struct rdp_backend *be, uint32_t rdp_scancode, int flags);
	int  (*pointer_motion)(struct rdp_backend *be, int x, int y);
	int  (*pointer_button)(struct rdp_backend *be, int btn, int down);
	int  (*pointer_wheel)(struct rdp_backend *be, int delta_v, int delta_h);

	int  (*cursor_get)(struct rdp_backend *be, struct rdp_cursor *out);

	int  (*clip_offer)(struct rdp_backend *be,
			const struct rdp_clip_offer *o);
	int  (*clip_fetch)(struct rdp_backend *be, uint32_t fmt,
			struct rdp_buf *out);

	int  (*pollfd)(struct rdp_backend *be);
};

struct rdp_backend {
	const struct rdp_backend_ops *ops;
	void                         *priv;
};

#endif /* RDP_BACKEND_H */
