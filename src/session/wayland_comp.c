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
 * wayland_comp.c -- minimal wlroots headless compositor for rdp-session.
 */

#include "wayland_comp.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#if HAVE_WLROOTS

#define WLR_USE_UNSTABLE
#include <wlr/backend.h>
#include <wlr/backend/headless.h>
#include <wlr/render/allocator.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/types/wlr_compositor.h>
#include <wlr/types/wlr_data_device.h>
#include <wlr/types/wlr_output.h>
#include <wlr/types/wlr_output_layout.h>
#include <wlr/types/wlr_seat.h>
#include <wlr/types/wlr_subcompositor.h>
#include <wlr/types/wlr_xdg_shell.h>
#include <wlr/util/log.h>

#include <linux/input-event-codes.h>
#include <pixman.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <xkbcommon/xkbcommon.h>

struct rdp_wl_comp {
	struct wl_display          *display;
	struct wlr_backend         *backend;
	struct wlr_renderer        *renderer;
	struct wlr_allocator       *allocator;
	struct wlr_output          *output;
	struct wlr_output_layout   *output_layout;
	struct wlr_compositor      *compositor;
	struct wlr_xdg_shell       *xdg_shell;
	struct wlr_seat            *seat;
	struct wlr_keyboard        *keyboard;
	const char                 *socket;

	uint8_t                    *fb;
	int                         fb_w, fb_h, fb_stride;
	int                         fb_dirty;

	struct wl_listener          new_xdg_toplevel;
	struct wl_listener          output_frame;

	struct wl_list              toplevels;

	/* RemoteApp (RAIL) per-window mode and the geometry event ring the
	 * session drains.  The ring is a fixed power-of-two slot buffer; a
	 * full ring drops the newest event rather than overflowing. */
	int                         rail_mode;
	struct rdp_wl_window_event  evq[32];
	unsigned                    evq_head, evq_tail;
	uint32_t                    next_window_id;
};

struct rdp_wl_toplevel {
	struct wlr_xdg_toplevel    *xdg;
	struct rdp_wl_comp         *comp;
	struct wl_listener          map;
	struct wl_listener          unmap;
	struct wl_listener          destroy;
	struct wl_list              link;

	/* RAIL per-window state.  window_id is the stable RAIL id; x,y is the
	 * cascade position on the virtual desktop; last_w/last_h track the last
	 * reported size; create_sent gates the first create and the delete. */
	uint32_t                    window_id;
	int32_t                     x, y;
	uint32_t                    last_w, last_h;
	int                         create_sent;
};

#define RDP_WL_EVQ_SLOTS \
	((unsigned)(sizeof(((struct rdp_wl_comp *)0)->evq) / \
	    sizeof(((struct rdp_wl_comp *)0)->evq[0])))

static uint32_t
now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

/* Push one RAIL window event onto the ring.  op 0 fills the geometry and
 * title from the toplevel; op 1 (delete) carries only the window id.  Returns
 * 1 when queued, 0 when the ring is full so the caller can retry rather than
 * mark the event delivered. */
static int
queue_window_event(struct rdp_wl_comp *c, int op, struct rdp_wl_toplevel *tl)
{
	unsigned next = (c->evq_tail + 1) % RDP_WL_EVQ_SLOTS;
	struct rdp_wl_window_event *ev;

	if (next == c->evq_head) return 0;   /* ring full, drop */
	ev = &c->evq[c->evq_tail];
	memset(ev, 0, sizeof *ev);
	ev->op = op;
	ev->window_id = tl->window_id;
	if (op == 0) {
		const char *title = tl->xdg != NULL ? tl->xdg->title : NULL;
		ev->x = tl->x;
		ev->y = tl->y;
		ev->w = tl->last_w;
		ev->h = tl->last_h;
		(void)strlcpy(ev->title, title != NULL ? title : "",
		    sizeof ev->title);
	}
	c->evq_tail = next;
	return 1;
}

static void
render_surface(struct rdp_wl_comp *c, struct rdp_wl_toplevel *tl)
{
	struct wlr_surface *surface;
	struct wlr_client_buffer *cbuf;
	void *data;
	uint32_t fmt;
	size_t stride;

	if (tl == NULL || tl->xdg == NULL) return;
	surface = tl->xdg->base->surface;
	if (surface == NULL || !surface->mapped) return;
	if (c->fb == NULL) return;
	cbuf = surface->buffer;
	if (cbuf == NULL) return;

	if (wlr_buffer_begin_data_ptr_access(&cbuf->base,
	    WLR_BUFFER_DATA_PTR_ACCESS_READ, &data, &fmt, &stride)) {
		int buf_w = (int)cbuf->base.width;
		int buf_h = (int)cbuf->base.height;
		int dst_x = 0, dst_y = 0;
		int copy_w, copy_h, row;

		if (c->rail_mode) {
			/* Place the window at its cascade origin and clip to
			 * the framebuffer so the copy never writes outside
			 * c->fb (a wrong clip here is a heap overflow). */
			dst_x = tl->x;
			dst_y = tl->y;
			if (dst_x >= c->fb_w || dst_y >= c->fb_h ||
			    dst_x < 0 || dst_y < 0)
				goto out_release;
			copy_w = buf_w;
			copy_h = buf_h;
			/* Clamp in subtraction form: the guard above keeps
			 * 0 <= dst_x < fb_w and 0 <= dst_y < fb_h, so these
			 * differences stay in range and cannot overflow the
			 * way dst_x + copy_w could for a huge buf_w. */
			if (copy_w > c->fb_w - dst_x)
				copy_w = c->fb_w - dst_x;
			if (copy_h > c->fb_h - dst_y)
				copy_h = c->fb_h - dst_y;
		} else {
			/* Flattened: copy the toplevel at the origin. */
			copy_w = c->fb_w < buf_w ? c->fb_w : buf_w;
			copy_h = c->fb_h < buf_h ? c->fb_h : buf_h;
		}

		for (row = 0; row < copy_h; row++) {
			memcpy(c->fb +
			    (size_t)(dst_y + row) * c->fb_stride +
			    (size_t)dst_x * 4,
			    (uint8_t *)data + (size_t)row * stride,
			    (size_t)copy_w * 4);
		}
		c->fb_dirty = 1;

		if (c->rail_mode && copy_w > 0 && copy_h > 0) {
			/* Report a create on the first frame, an update when
			 * the natural size changed. */
			if (!tl->create_sent ||
			    (uint32_t)buf_w != tl->last_w ||
			    (uint32_t)buf_h != tl->last_h) {
				uint32_t prev_w = tl->last_w;
				uint32_t prev_h = tl->last_h;
				tl->last_w = (uint32_t)buf_w;
				tl->last_h = (uint32_t)buf_h;
				/* Only mark delivered once the event is queued.
				 * If the ring is full, revert the size so the
				 * create/update is retried on a later frame and
				 * create_sent stays clear, which prevents an
				 * orphan delete for a window the client never
				 * received a create for. */
				if (queue_window_event(c, 0, tl)) {
					tl->create_sent = 1;
				} else {
					tl->last_w = prev_w;
					tl->last_h = prev_h;
				}
			}
		}
out_release:
		wlr_buffer_end_data_ptr_access(&cbuf->base);
	}

	wlr_surface_send_frame_done(surface,
	    &(struct timespec){0, 0});
}

static void
on_output_frame(struct wl_listener *listener, void *data)
{
	struct rdp_wl_comp *c = wl_container_of(listener, c, output_frame);
	struct wlr_output *out = c->output;
	struct wlr_output_state state;

	(void)data;
	wlr_output_state_init(&state);

	struct rdp_wl_toplevel *tl;
	wl_list_for_each(tl, &c->toplevels, link)
		render_surface(c, tl);

	wlr_output_commit_state(out, &state);
	wlr_output_state_finish(&state);
}

static void
on_toplevel_map(struct wl_listener *listener, void *data)
{
	(void)data;
	struct rdp_wl_toplevel *tl = wl_container_of(listener, tl, map);
	struct wlr_keyboard *kb = wlr_seat_get_keyboard(tl->comp->seat);
	if (kb != NULL)
		wlr_seat_keyboard_enter(tl->comp->seat,
		    tl->xdg->base->surface,
		    kb->keycodes, kb->num_keycodes, &kb->modifiers);
}

static void
on_toplevel_unmap(struct wl_listener *listener, void *data)
{
	(void)data;
	struct rdp_wl_toplevel *tl = wl_container_of(listener, tl, unmap);
	if (tl->comp->rail_mode && tl->create_sent) {
		queue_window_event(tl->comp, 1, tl);
		tl->create_sent = 0;
	}
}

static void
on_toplevel_destroy(struct wl_listener *listener, void *data)
{
	(void)data;
	struct rdp_wl_toplevel *tl = wl_container_of(listener, tl, destroy);
	/* Queue the delete before freeing; the ring copies window_id by
	 * value so the freed toplevel is never dereferenced later. */
	if (tl->comp->rail_mode && tl->create_sent)
		queue_window_event(tl->comp, 1, tl);
	wl_list_remove(&tl->map.link);
	wl_list_remove(&tl->unmap.link);
	wl_list_remove(&tl->destroy.link);
	wl_list_remove(&tl->link);
	free(tl);
}

static void
on_new_xdg_toplevel(struct wl_listener *listener, void *data)
{
	struct rdp_wl_comp *c = wl_container_of(listener, c, new_xdg_toplevel);
	struct wlr_xdg_toplevel *xdg = data;
	struct rdp_wl_toplevel *tl;

	tl = calloc(1, sizeof *tl);
	if (tl == NULL) return;
	tl->xdg = xdg;
	tl->comp = c;

	tl->map.notify = on_toplevel_map;
	wl_signal_add(&xdg->base->surface->events.map, &tl->map);
	tl->unmap.notify = on_toplevel_unmap;
	wl_signal_add(&xdg->base->surface->events.unmap, &tl->unmap);
	tl->destroy.notify = on_toplevel_destroy;
	wl_signal_add(&xdg->events.destroy, &tl->destroy);

	wl_list_insert(&c->toplevels, &tl->link);
	if (c->rail_mode) {
		/* RAIL: give the window a stable id and a cascade position on
		 * the virtual desktop, and let the client pick its natural
		 * size (set_size 0,0) instead of fullscreen. */
		tl->window_id = ++c->next_window_id;
		tl->x = 40 + (int32_t)((tl->window_id * 30) % 400);
		tl->y = 40 + (int32_t)((tl->window_id * 30) % 300);
		wlr_xdg_toplevel_set_size(xdg, 0, 0);
	} else {
		wlr_xdg_toplevel_set_size(xdg, c->fb_w, c->fb_h);
	}
	wlr_xdg_toplevel_set_activated(xdg, true);
}

struct rdp_wl_comp *
rdp_wl_comp_create(int width, int height)
{
	struct rdp_wl_comp *c;

	wlr_log_init(WLR_ERROR, NULL);

	c = calloc(1, sizeof *c);
	if (c == NULL) return NULL;
	wl_list_init(&c->toplevels);

	c->display = wl_display_create();
	if (c->display == NULL) goto fail;

	c->backend = wlr_headless_backend_create(
	    wl_display_get_event_loop(c->display));
	if (c->backend == NULL) goto fail;

	c->renderer = wlr_renderer_autocreate(c->backend);
	if (c->renderer == NULL) goto fail;
	wlr_renderer_init_wl_display(c->renderer, c->display);

	c->allocator = wlr_allocator_autocreate(c->backend, c->renderer);
	if (c->allocator == NULL) goto fail;

	c->compositor = wlr_compositor_create(c->display, 5, c->renderer);
	wlr_subcompositor_create(c->display);
	wlr_data_device_manager_create(c->display);

	c->output_layout = wlr_output_layout_create(c->display);

	c->xdg_shell = wlr_xdg_shell_create(c->display, 3);
	c->new_xdg_toplevel.notify = on_new_xdg_toplevel;
	wl_signal_add(&c->xdg_shell->events.new_toplevel,
	    &c->new_xdg_toplevel);

	c->seat = wlr_seat_create(c->display, "seat0");
	wlr_seat_set_capabilities(c->seat,
	    WL_SEAT_CAPABILITY_POINTER | WL_SEAT_CAPABILITY_KEYBOARD
	    | WL_SEAT_CAPABILITY_TOUCH);

	c->output = wlr_headless_add_output(c->backend, width, height);
	if (c->output == NULL) goto fail;

	struct wlr_output_state ostate;
	wlr_output_state_init(&ostate);
	wlr_output_state_set_enabled(&ostate, true);
	wlr_output_commit_state(c->output, &ostate);
	wlr_output_state_finish(&ostate);

	wlr_output_layout_add_auto(c->output_layout, c->output);

	c->output_frame.notify = on_output_frame;
	wl_signal_add(&c->output->events.frame, &c->output_frame);

	c->fb_w = width;
	c->fb_h = height;
	c->fb_stride = width * 4;
	c->fb = calloc(1, (size_t)c->fb_stride * height);
	if (c->fb == NULL) goto fail;

	if (!wlr_backend_start(c->backend)) {
		rdp_err("wlroots: backend start failed");
		goto fail;
	}

	c->socket = wl_display_add_socket_auto(c->display);
	if (c->socket == NULL) goto fail;

	rdp_info("wayland: compositor on %s (%dx%d)", c->socket, width, height);
	return c;

fail:
	rdp_wl_comp_destroy(c);
	return NULL;
}

const char *
rdp_wl_comp_get_socket(struct rdp_wl_comp *c)
{
	return c != NULL ? c->socket : NULL;
}

int
rdp_wl_comp_dispatch(struct rdp_wl_comp *c, int timeout_ms)
{
	if (c == NULL) return -1;
	wl_display_flush_clients(c->display);
	int rc = wl_event_loop_dispatch(
	    wl_display_get_event_loop(c->display), timeout_ms);
	wl_display_flush_clients(c->display);
	return rc;
}

int
rdp_wl_comp_get_framebuffer(struct rdp_wl_comp *c,
    uint8_t **pixels, int *w, int *h, int *stride)
{
	if (c == NULL || c->fb == NULL) return -1;
	*pixels = c->fb;
	*w = c->fb_w;
	*h = c->fb_h;
	*stride = c->fb_stride;
	return 0;
}

void
rdp_wl_comp_inject_key(struct rdp_wl_comp *c,
    uint32_t keycode, int pressed)
{
	if (c == NULL || c->seat == NULL) return;
	wlr_seat_keyboard_notify_key(c->seat, now_ms(), keycode,
	    pressed ? WL_KEYBOARD_KEY_STATE_PRESSED
	    : WL_KEYBOARD_KEY_STATE_RELEASED);
}

void
rdp_wl_comp_inject_pointer(struct rdp_wl_comp *c,
    int x, int y, uint32_t buttons, int motion)
{
	if (c == NULL || c->seat == NULL) return;
	if (motion)
		wlr_seat_pointer_notify_motion(c->seat, now_ms(),
		    (double)x, (double)y);
	if (buttons & 1)
		wlr_seat_pointer_notify_button(c->seat, now_ms(),
		    BTN_LEFT, WL_POINTER_BUTTON_STATE_PRESSED);
	if (buttons & 2)
		wlr_seat_pointer_notify_button(c->seat, now_ms(),
		    BTN_RIGHT, WL_POINTER_BUTTON_STATE_PRESSED);
}

void
rdp_wl_comp_inject_touch(struct rdp_wl_comp *c, int32_t id, int x, int y,
    int phase)
{
	/* phase: 0 = down, 1 = motion, 2 = up.  Targets the keyboard-focused
	 * surface, as the pointer path does; the flattened compositor renders
	 * its toplevels at the origin, so a contact's desktop coordinates
	 * serve as surface-local coordinates. */
	struct wlr_surface *surf;

	if (c == NULL || c->seat == NULL) return;
	if (phase == 2) {
		wlr_seat_touch_notify_up(c->seat, now_ms(), id);
		return;
	}
	surf = c->seat->keyboard_state.focused_surface;
	if (surf == NULL) return;
	if (phase == 0)
		wlr_seat_touch_notify_down(c->seat, surf, now_ms(), id,
		    (double)x, (double)y);
	else
		wlr_seat_touch_notify_motion(c->seat, now_ms(), id,
		    (double)x, (double)y);
}

void
rdp_wl_comp_touch_frame(struct rdp_wl_comp *c)
{
	if (c != NULL && c->seat != NULL)
		wlr_seat_touch_notify_frame(c->seat);
}

int
rdp_wl_comp_is_dirty(struct rdp_wl_comp *c)
{
	return c != NULL && c->fb_dirty;
}

void
rdp_wl_comp_clear_dirty(struct rdp_wl_comp *c)
{
	if (c != NULL) c->fb_dirty = 0;
}

void
rdp_wl_comp_set_rail(struct rdp_wl_comp *c, int on)
{
	struct rdp_wl_toplevel *tl;

	if (c == NULL) return;
	c->rail_mode = on ? 1 : 0;
	if (!on) return;
	/* RAIL turns on after activation, so the startup terminal has usually
	 * already mapped in flattened mode with window_id 0, position (0,0)
	 * and a fullscreen buffer.  Bring every such toplevel into per-window
	 * state the same way a fresh one gets it, so its first create order
	 * carries a real id, a cascade position and its natural size instead
	 * of a whole-desktop window at the origin. */
	wl_list_for_each(tl, &c->toplevels, link) {
		if (tl->window_id != 0)
			continue;
		tl->window_id = ++c->next_window_id;
		tl->x = 40 + (int32_t)((tl->window_id * 30) % 400);
		tl->y = 40 + (int32_t)((tl->window_id * 30) % 300);
		if (tl->xdg != NULL)
			wlr_xdg_toplevel_set_size(tl->xdg, 0, 0);
	}
}

int
rdp_wl_comp_poll_window_event(struct rdp_wl_comp *c,
    struct rdp_wl_window_event *ev)
{
	if (c == NULL || ev == NULL) return 0;
	if (c->evq_head == c->evq_tail) return 0;   /* empty */
	*ev = c->evq[c->evq_head];
	c->evq_head = (c->evq_head + 1) % RDP_WL_EVQ_SLOTS;
	return 1;
}

void
rdp_wl_comp_resize(struct rdp_wl_comp *c, int w, int h)
{
	if (c == NULL || c->output == NULL) return;

	free(c->fb);
	c->fb_w = w;
	c->fb_h = h;
	c->fb_stride = w * 4;
	c->fb = calloc(1, (size_t)c->fb_stride * h);

	struct wlr_output_state state;
	wlr_output_state_init(&state);
	wlr_output_state_set_custom_mode(&state, w, h, 0);
	wlr_output_commit_state(c->output, &state);
	wlr_output_state_finish(&state);

	/* In RAIL mode each window keeps its natural size, so only the
	 * flattened mode resizes its toplevels to the new desktop. */
	if (!c->rail_mode) {
		struct rdp_wl_toplevel *tl;
		wl_list_for_each(tl, &c->toplevels, link)
			wlr_xdg_toplevel_set_size(tl->xdg, w, h);
	}
}

void
rdp_wl_comp_destroy(struct rdp_wl_comp *c)
{
	if (c == NULL) return;
	free(c->fb);
	if (c->display != NULL)
		wl_display_destroy_clients(c->display);
	if (c->display != NULL)
		wl_display_destroy(c->display);
	free(c);
}

#else /* !HAVE_WLROOTS */

struct rdp_wl_comp *rdp_wl_comp_create(int w, int h)
{ (void)w; (void)h; return NULL; }
const char *rdp_wl_comp_get_socket(struct rdp_wl_comp *c)
{ (void)c; return NULL; }
int rdp_wl_comp_dispatch(struct rdp_wl_comp *c, int t)
{ (void)c; (void)t; return -1; }
int rdp_wl_comp_get_framebuffer(struct rdp_wl_comp *c,
    uint8_t **p, int *w, int *h, int *s)
{ (void)c; (void)p; (void)w; (void)h; (void)s; return -1; }
void rdp_wl_comp_inject_key(struct rdp_wl_comp *c, uint32_t k, int p)
{ (void)c; (void)k; (void)p; }
void rdp_wl_comp_inject_pointer(struct rdp_wl_comp *c,
    int x, int y, uint32_t b, int m)
{ (void)c; (void)x; (void)y; (void)b; (void)m; }
int rdp_wl_comp_is_dirty(struct rdp_wl_comp *c) { (void)c; return 0; }
void rdp_wl_comp_clear_dirty(struct rdp_wl_comp *c) { (void)c; }
void rdp_wl_comp_resize(struct rdp_wl_comp *c, int w, int h)
{ (void)c; (void)w; (void)h; }
void rdp_wl_comp_set_rail(struct rdp_wl_comp *c, int on)
{ (void)c; (void)on; }
int rdp_wl_comp_poll_window_event(struct rdp_wl_comp *c,
    struct rdp_wl_window_event *ev)
{ (void)c; (void)ev; return 0; }
void rdp_wl_comp_destroy(struct rdp_wl_comp *c) { (void)c; }

#endif
