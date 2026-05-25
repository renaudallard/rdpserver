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
};

struct rdp_wl_toplevel {
	struct wlr_xdg_toplevel    *xdg;
	struct rdp_wl_comp         *comp;
	struct wl_listener          map;
	struct wl_listener          unmap;
	struct wl_listener          destroy;
	struct wl_list              link;
};

static uint32_t
now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void
render_surface(struct rdp_wl_comp *c, struct wlr_surface *surface)
{
	struct wlr_client_buffer *cbuf;
	void *data;
	uint32_t fmt;
	size_t stride;

	if (surface == NULL || !surface->mapped) return;
	if (c->fb == NULL) return;
	cbuf = surface->buffer;
	if (cbuf == NULL) return;

	if (wlr_buffer_begin_data_ptr_access(&cbuf->base,
	    WLR_BUFFER_DATA_PTR_ACCESS_READ, &data, &fmt, &stride)) {
		int copy_h = c->fb_h < (int)cbuf->base.height
		    ? c->fb_h : (int)cbuf->base.height;
		int copy_w = c->fb_w < (int)cbuf->base.width
		    ? c->fb_w : (int)cbuf->base.width;
		int row;
		for (row = 0; row < copy_h; row++) {
			memcpy(c->fb + (size_t)row * c->fb_stride,
			    (uint8_t *)data + (size_t)row * stride,
			    (size_t)copy_w * 4);
		}
		wlr_buffer_end_data_ptr_access(&cbuf->base);
		c->fb_dirty = 1;
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
		render_surface(c, tl->xdg->base->surface);

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
	(void)data; (void)listener;
}

static void
on_toplevel_destroy(struct wl_listener *listener, void *data)
{
	(void)data;
	struct rdp_wl_toplevel *tl = wl_container_of(listener, tl, destroy);
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
	wlr_xdg_toplevel_set_size(xdg, c->fb_w, c->fb_h);
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
	    WL_SEAT_CAPABILITY_POINTER | WL_SEAT_CAPABILITY_KEYBOARD);

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

	struct rdp_wl_toplevel *tl;
	wl_list_for_each(tl, &c->toplevels, link)
		wlr_xdg_toplevel_set_size(tl->xdg, w, h);
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
void rdp_wl_comp_destroy(struct rdp_wl_comp *c) { (void)c; }

#endif
