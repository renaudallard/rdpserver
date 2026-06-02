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
 * greeter.c -- login UI state machine and event loop.
 *
 * Layout
 *
 *   +----------------------------- desktop -----------------------------+
 *   |                                                                   |
 *   |                                                                   |
 *   |              +--------------- panel ---------------+              |
 *   |              |                                     |              |
 *   |              |              rdpserver              |              |
 *   |              |                                     |              |
 *   |              |  Username  +-----------------+      |              |
 *   |              |            |                 |      |              |
 *   |              |  Password  +-----------------+      |              |
 *   |              |                                     |              |
 *   |              |              [   Login   ]          |              |
 *   |              |                                     |              |
 *   |              |  status line                        |              |
 *   |              +-------------------------------------+              |
 *   |                                                                   |
 *   +-------------------------------------------------------------------+
 *
 * The screen is painted into a CPU framebuffer; on each tick we push
 * any modified region as a single bitmap update (multi-tile if the
 * rect is wider than what one update can carry).
 */

#include "greeter.h"

#include "../include/rdp_log.h"
#include "../common/io.h"
#include "../sec/tls.h"
#include "../wire/tpkt.h"
#include "../wire/fastpath.h"
#include "font.h"
#include "keymap.h"
#include "paint.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define UNAME_MAX 64
#define PASS_MAX  256

enum field {
	F_USER = 0,
	F_PASS = 1,
	F_BTN  = 2,
};

enum state {
	GS_IDLE,
	GS_SUBMITTING,
	GS_FAIL,
	GS_OK,
};

struct ui {
	struct rdp_rect panel;
	struct rdp_rect title;
	struct rdp_rect lbl_user, lbl_pass;
	struct rdp_rect fld_user, fld_pass;
	struct rdp_rect btn;
	struct rdp_rect status;
};

struct g {
	struct rdp_fb fb;
	struct ui     ui;

	char    user[UNAME_MAX];
	char    pass[PASS_MAX];
	uint8_t user_len;
	uint16_t pass_len;

	int     focus;
	int     shift;
	enum state state;

	struct rdp_keymap kbd;

	struct rdp_rect dirty;

	const char *status_msg;
};

#define COL_BG_B  0x14
#define COL_BG_G  0x14
#define COL_BG_R  0x14
#define COL_PANEL_B  0x2a
#define COL_PANEL_G  0x2a
#define COL_PANEL_R  0x2a
#define COL_FIELD_B  0x10
#define COL_FIELD_G  0x10
#define COL_FIELD_R  0x10
#define COL_BORDER_B 0x88
#define COL_BORDER_G 0x88
#define COL_BORDER_R 0x88
#define COL_FOCUS_B  0xff
#define COL_FOCUS_G  0x9d
#define COL_FOCUS_R  0x00
#define COL_TEXT_B   0xeb
#define COL_TEXT_G   0xeb
#define COL_TEXT_R   0xeb
#define COL_DIM_B    0x88
#define COL_DIM_G    0x88
#define COL_DIM_R    0x88
#define COL_OK_B     0x40
#define COL_OK_G     0xc0
#define COL_OK_R     0x40
#define COL_FAIL_B   0x40
#define COL_FAIL_G   0x40
#define COL_FAIL_R   0xff

static void
layout(struct ui *u, uint16_t w, uint16_t h)
{
	int pw = 480, ph = 280;
	int px = (w - pw) / 2;
	int py = (h - ph) / 2;

	u->panel  = (struct rdp_rect){ px, py, pw, ph };
	u->title  = (struct rdp_rect){ px + 16, py + 16,
		pw - 32, RDP_FONT_HEIGHT };
	u->lbl_user = (struct rdp_rect){ px + 32, py + 80,
		96, RDP_FONT_HEIGHT };
	u->fld_user = (struct rdp_rect){ px + 32 + 96, py + 76,
		pw - 32 - 96 - 32, RDP_FONT_HEIGHT + 10 };
	u->lbl_pass = (struct rdp_rect){ px + 32, py + 130,
		96, RDP_FONT_HEIGHT };
	u->fld_pass = (struct rdp_rect){ px + 32 + 96, py + 126,
		pw - 32 - 96 - 32, RDP_FONT_HEIGHT + 10 };
	u->btn    = (struct rdp_rect){ px + (pw - 120) / 2, py + 180,
		120, RDP_FONT_HEIGHT + 14 };
	u->status = (struct rdp_rect){ px + 16, py + ph - 32,
		pw - 32, RDP_FONT_HEIGHT };
}

static void
paint_field(struct g *g, struct rdp_rect r, const char *content,
		int show_bullets, int focused)
{
	int len, i;
	int tx = r.x + 6, ty = r.y + 5;

	rdp_paint_fill(&g->fb, r, COL_FIELD_B, COL_FIELD_G, COL_FIELD_R);
	if (focused) {
		rdp_paint_rect_outline(&g->fb, r,
			COL_FOCUS_B, COL_FOCUS_G, COL_FOCUS_R);
	} else {
		rdp_paint_rect_outline(&g->fb, r,
			COL_BORDER_B, COL_BORDER_G, COL_BORDER_R);
	}
	len = (int)strlen(content);
	for (i = 0; i < len; i++) {
		uint32_t cp = show_bullets ? '*' : (uint8_t)content[i];
		if (tx + RDP_FONT_WIDTH > r.x + r.w - 4) break;
		rdp_paint_glyph(&g->fb, tx, ty, cp,
			COL_TEXT_B, COL_TEXT_G, COL_TEXT_R);
		tx += RDP_FONT_WIDTH;
	}
	/* Blinking cursor as a simple thin rectangle at the end of the
	 * current input.  (We re-paint on each event, so it always
	 * lands where the next character would go.) */
	if (focused) {
		struct rdp_rect cur = { tx + 1, ty, 1, RDP_FONT_HEIGHT };
		rdp_paint_fill(&g->fb, cur,
			COL_TEXT_B, COL_TEXT_G, COL_TEXT_R);
	}
	rdp_rect_union(&g->dirty, r);
}

static void
paint_button(struct g *g)
{
	struct rdp_rect r = g->ui.btn;
	const char *label = "Login";
	int focused = (g->focus == F_BTN);
	int submitting = (g->state == GS_SUBMITTING);
	int tx, ty;

	rdp_paint_fill(&g->fb, r,
		submitting ? COL_DIM_B : COL_PANEL_B,
		submitting ? COL_DIM_G : COL_PANEL_G,
		submitting ? COL_DIM_R : COL_PANEL_R);
	rdp_paint_rect_outline(&g->fb, r,
		focused ? COL_FOCUS_B : COL_BORDER_B,
		focused ? COL_FOCUS_G : COL_BORDER_G,
		focused ? COL_FOCUS_R : COL_BORDER_R);
	tx = r.x + (r.w - (int)strlen(label) * RDP_FONT_WIDTH) / 2;
	ty = r.y + (r.h - RDP_FONT_HEIGHT) / 2;
	rdp_paint_string(&g->fb, tx, ty, label,
		COL_TEXT_B, COL_TEXT_G, COL_TEXT_R);
	rdp_rect_union(&g->dirty, r);
}

static void
paint_status(struct g *g)
{
	struct rdp_rect r = g->ui.status;
	uint8_t b = COL_DIM_B, gg = COL_DIM_G, rd = COL_DIM_R;
	rdp_paint_fill(&g->fb, r, COL_PANEL_B, COL_PANEL_G, COL_PANEL_R);
	if (g->state == GS_OK)   { b = COL_OK_B;   gg = COL_OK_G;   rd = COL_OK_R; }
	if (g->state == GS_FAIL) { b = COL_FAIL_B; gg = COL_FAIL_G; rd = COL_FAIL_R; }
	if (g->status_msg)
		rdp_paint_string(&g->fb, r.x, r.y, g->status_msg, b, gg, rd);
	rdp_rect_union(&g->dirty, r);
}

static void
paint_all(struct g *g)
{
	struct rdp_rect screen = { 0, 0, g->fb.w, g->fb.h };
	rdp_paint_fill(&g->fb, screen, COL_BG_B, COL_BG_G, COL_BG_R);
	rdp_paint_fill(&g->fb, g->ui.panel,
		COL_PANEL_B, COL_PANEL_G, COL_PANEL_R);
	rdp_paint_rect_outline(&g->fb, g->ui.panel,
		COL_BORDER_B, COL_BORDER_G, COL_BORDER_R);
	rdp_paint_string(&g->fb, g->ui.title.x, g->ui.title.y,
		"rdpserver", COL_TEXT_B, COL_TEXT_G, COL_TEXT_R);
	rdp_paint_string(&g->fb, g->ui.lbl_user.x, g->ui.lbl_user.y,
		"Username", COL_TEXT_B, COL_TEXT_G, COL_TEXT_R);
	rdp_paint_string(&g->fb, g->ui.lbl_pass.x, g->ui.lbl_pass.y,
		"Password", COL_TEXT_B, COL_TEXT_G, COL_TEXT_R);
	paint_field(g, g->ui.fld_user, g->user, 0, g->focus == F_USER);
	{
		char dots[PASS_MAX + 1];
		uint16_t i;
		for (i = 0; i < g->pass_len && i < PASS_MAX; i++)
			dots[i] = '*';
		dots[i] = '\0';
		paint_field(g, g->ui.fld_pass, dots, 0, g->focus == F_PASS);
	}
	paint_button(g);
	paint_status(g);
	g->dirty = screen;
}

/* Push every tile that intersects the dirty rect to the client as a
 * single fast-path bitmap update, then clear the dirty rect. */
static int
push_dirty(struct g *g, struct rdp_tls *t)
{
	const int TILE = 64;
	uint8_t pkt[0x4000];
	uint8_t tilebuf[TILE * TILE * 3];
	struct rdp_rect d = g->dirty;
	int x0, y0, x1, y1, y, x;

	if (rdp_rect_empty(&d)) return 0;
	x0 = (d.x / TILE) * TILE;
	y0 = (d.y / TILE) * TILE;
	x1 = ((d.x + d.w + TILE - 1) / TILE) * TILE;
	y1 = ((d.y + d.h + TILE - 1) / TILE) * TILE;
	if (x1 > g->fb.w) x1 = g->fb.w;
	if (y1 > g->fb.h) y1 = g->fb.h;

	for (y = y0; y < y1; y += TILE) {
		int th = (y + TILE > g->fb.h ? g->fb.h - y : TILE);
		for (x = x0; x < x1; x += TILE) {
			int tw = (x + TILE > g->fb.w ? g->fb.w - x : TILE);
			ssize_t n;
			int row;
			for (row = 0; row < th; row++) {
				memcpy(tilebuf + (size_t)row * tw * 3,
					g->fb.data
					+ ((size_t)(y + row) * g->fb.w
						+ (size_t)x) * 3,
					(size_t)tw * 3);
			}
			n = rdp_fp_build_bitmap_update(pkt, sizeof pkt,
				(uint16_t)x, (uint16_t)y,
				(uint16_t)tw, (uint16_t)th,
				tilebuf, (size_t)tw * 3);
			if (n < 0) return -1;
			if (rdp_tls_write_full(t, pkt, (size_t)n)
			    != (ssize_t)n)
				return -1;
		}
	}
	rdp_rect_reset(&g->dirty);
	return 0;
}

static void
input_char(struct g *g, char c)
{
	if (g->focus == F_USER) {
		if (c == RDP_KEY_BACKSPACE) {
			if (g->user_len > 0)
				g->user[--g->user_len] = '\0';
		} else if (c >= 0x20 && c <= 0x7e
		    && g->user_len + 1 < UNAME_MAX) {
			g->user[g->user_len++] = c;
			g->user[g->user_len] = '\0';
		}
	} else if (g->focus == F_PASS) {
		if (c == RDP_KEY_BACKSPACE) {
			if (g->pass_len > 0)
				g->pass[--g->pass_len] = '\0';
		} else if (c >= 0x20 && c <= 0x7e
		    && g->pass_len + 1 < PASS_MAX) {
			g->pass[g->pass_len++] = c;
			g->pass[g->pass_len] = '\0';
		}
	}
}

struct evctx {
	struct g           *g;
	rdp_greeter_auth_fn auth;
	void               *auth_ctx;
	int                 want_exit;
	int                 submit;
};

static void
on_input(void *ctx, const struct rdp_fp_input_event *ev)
{
	struct evctx *e = ctx;
	struct g *g = e->g;

	if (ev->type == RDP_FP_INPUT_SCANCODE) {
		int release = (ev->flags & 0x01) != 0;
		uint8_t sc = (uint8_t)ev->keycode;

		if (sc == 0x2a || sc == 0x36) {  /* L/R Shift */
			g->shift = !release;
			return;
		}
		if (release) return;

		char c = rdp_keymap_lookup(&g->kbd, sc, ev->flags, g->shift);
		if (c == 0) return;
		if (c == RDP_KEY_ESC) { e->want_exit = 1; return; }
		if (c == RDP_KEY_TAB) {
			g->focus = (g->focus + 1) % 3;
			return;
		}
		if (c == RDP_KEY_ENTER) {
			if (g->focus == F_USER) g->focus = F_PASS;
			else                    e->submit = 1;
			return;
		}
		input_char(g, c);
	} else if (ev->type == RDP_FP_INPUT_UNICODE) {
		int release = (ev->flags & 0x01) != 0;
		uint16_t u = ev->keycode;
		if (release) return;
		if (u >= 0x20 && u <= 0x7e)
			input_char(g, (char)u);
	}
}

static int
stub_auth(const char *user, const char *password, void *ctx)
{
	(void)ctx;
	if (user == NULL || user[0] == '\0') return -1;
	if (password == NULL || password[0] == '\0') return -1;
	return 0;
}

static int
read_one_pdu(struct rdp_tls *t, uint8_t *buf, size_t cap, size_t *len_out)
{
	uint8_t lead;
	ssize_t r;

	r = rdp_tls_read(t, &lead, 1);
	if (r <= 0) return -1;
	buf[0] = lead;
	if (lead == 0x03) {
		/* TPKT.  Read remainder of header + body. */
		struct rdp_tpkt h;
		r = rdp_tls_read_full(t, buf + 1, 3);
		if (r != 3) return -1;
		if (rdp_tpkt_parse_hdr(&h, buf) < 0) return -1;
		if (h.length > cap) return -1;
		r = rdp_tls_read_full(t, buf + 4, (size_t)h.length - 4);
		if (r < 0) return -1;
		*len_out = h.length;
		return 1;  /* TPKT (e.g. MCS disconnect) */
	}
	/* Fast-path input.  Read 1 byte of length, then maybe a second. */
	r = rdp_tls_read_full(t, buf + 1, 1);
	if (r != 1) return -1;
	if ((buf[1] & 0x80) == 0) {
		size_t total = buf[1];
		if (total > cap) return -1;
		if (total > 2) {
			r = rdp_tls_read_full(t, buf + 2, total - 2);
			if (r < 0) return -1;
		}
		*len_out = total;
	} else {
		size_t total;
		r = rdp_tls_read_full(t, buf + 2, 1);
		if (r < 0) return -1;
		total = ((size_t)(buf[1] & 0x7f) << 8) | buf[2];
		if (total > cap) return -1;
		if (total > 3) {
			r = rdp_tls_read_full(t, buf + 3, total - 3);
			if (r < 0) return -1;
		}
		*len_out = total;
	}
	return 0;  /* fast-path input */
}

int
rdp_greeter_run(struct rdp_tls *t,
		uint16_t desktop_w, uint16_t desktop_h, uint32_t lcid,
		rdp_greeter_auth_fn auth, void *auth_ctx,
		struct rdp_greeter_result *out)
{
	struct g state;
	int rc = -1;
	size_t fb_bytes;

	if (auth == NULL) auth = stub_auth;

	memset(&state, 0, sizeof state);
	rdp_keymap_for_lcid(lcid, &state.kbd);
	fb_bytes = (size_t)desktop_w * desktop_h * 3;
	state.fb.data = malloc(fb_bytes);
	if (state.fb.data == NULL) return -1;
	state.fb.w = desktop_w;
	state.fb.h = desktop_h;
	state.focus = F_USER;
	state.state = GS_IDLE;
	state.status_msg = "Enter your credentials";
	layout(&state.ui, desktop_w, desktop_h);

	paint_all(&state);
	if (push_dirty(&state, t) != 0) goto out;

	for (;;) {
		uint8_t buf[0x4000];
		size_t pkt_len;
		struct evctx ec = { &state, auth, auth_ctx, 0, 0 };

		int r = read_one_pdu(t, buf, sizeof buf, &pkt_len);
		if (r < 0) goto out;
		if (r == 1) {
			/* TPKT-wrapped PDU.  Look for MCS Disconnect. */
			if (pkt_len >= 8 && buf[7] == 0x20) goto out;
			continue;
		}
		if (rdp_fp_parse_input(buf, pkt_len,
			on_input, &ec, NULL) < 0) {
			rdp_warn("greeter: malformed fast-path input");
			continue;
		}

		if (ec.want_exit) { rc = -1; goto out; }

		/* Re-render based on possibly-modified state. */
		paint_all(&state);

		if (ec.submit) {
			state.state = GS_SUBMITTING;
			state.status_msg = "Authenticating...";
			paint_status(&state);
			paint_button(&state);
			if (push_dirty(&state, t) != 0) goto out;

			if (auth(state.user, state.pass, auth_ctx) == 0) {
				state.state = GS_OK;
				state.status_msg = "Login successful";
				if (out != NULL) {
					out->ok = 1;
					strncpy(out->username, state.user,
						sizeof out->username - 1);
					out->username[sizeof out->username - 1] = '\0';
				}
				paint_status(&state);
				(void)push_dirty(&state, t);
				rc = 0;
				goto out;
			} else {
				state.state = GS_FAIL;
				state.status_msg = "Authentication failed";
				/* Wipe password buffer on every failure. */
				explicit_bzero(state.pass, sizeof state.pass);
				state.pass_len = 0;
				state.focus = F_PASS;
				paint_all(&state);
			}
		}

		if (push_dirty(&state, t) != 0) goto out;
	}

out:
	explicit_bzero(state.pass, sizeof state.pass);
	free(state.fb.data);
	return rc;
}
