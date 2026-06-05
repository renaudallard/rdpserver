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
#ifndef RDP_WAYLAND_COMP_H
#define RDP_WAYLAND_COMP_H

#include <stdint.h>

struct rdp_wl_comp;

/* A RemoteApp (RAIL) window geometry event drained from the compositor.
 * op 0 = create/update (geometry and title valid), op 1 = delete.  title is
 * UTF-8, NUL terminated. */
struct rdp_wl_window_event {
	int      op;
	uint32_t window_id;
	int32_t  x, y;
	uint32_t w, h;
	char     title[256];
};

/* lcid is the client's keyboard layout (Windows LCID); it selects the xkb
 * keymap the compositor advertises to session apps.  0 = US. */
struct rdp_wl_comp *rdp_wl_comp_create(int width, int height, uint32_t lcid);
const char *rdp_wl_comp_get_socket(struct rdp_wl_comp *c);
int rdp_wl_comp_dispatch(struct rdp_wl_comp *c, int timeout_ms);
int rdp_wl_comp_get_framebuffer(struct rdp_wl_comp *c,
    uint8_t **pixels, int *w, int *h, int *stride);
void rdp_wl_comp_inject_key(struct rdp_wl_comp *c,
    uint32_t keycode, int pressed);
void rdp_wl_comp_inject_pointer(struct rdp_wl_comp *c,
    int x, int y, uint32_t buttons, int motion);
/* Inject one touch contact.  phase: 0 = down, 1 = motion, 2 = up.
 * Call rdp_wl_comp_touch_frame once after a batch of contacts. */
void rdp_wl_comp_inject_touch(struct rdp_wl_comp *c, int32_t id,
    int x, int y, int phase);
void rdp_wl_comp_touch_frame(struct rdp_wl_comp *c);
int rdp_wl_comp_is_dirty(struct rdp_wl_comp *c);
void rdp_wl_comp_clear_dirty(struct rdp_wl_comp *c);
void rdp_wl_comp_resize(struct rdp_wl_comp *c, int w, int h);
/* RemoteApp (RAIL) per-window mode: when on, the compositor lets each
 * toplevel keep its natural size, renders it at its own position, and queues
 * window geometry events for the session to forward. */
void rdp_wl_comp_set_rail(struct rdp_wl_comp *c, int on);
/* Dequeue one pending RAIL window event into ev.  Returns 1 if an event was
 * dequeued, 0 if the queue is empty. */
int rdp_wl_comp_poll_window_event(struct rdp_wl_comp *c,
    struct rdp_wl_window_event *ev);
void rdp_wl_comp_destroy(struct rdp_wl_comp *c);

#endif
