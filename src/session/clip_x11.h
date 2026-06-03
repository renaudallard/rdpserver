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
 * clip_x11.h -- bridge between the X11 CLIPBOARD selection and the
 * backend CLIPRDR channel.
 *
 * Owned and driven by rdp_session.c.  The session's main loop
 * pumps X events through `rdp_clip_handle_xevent` and backend
 * CLIP messages through `rdp_clip_handle_be_msg`.
 */

#ifndef RDP_CLIP_X11_H
#define RDP_CLIP_X11_H

#include <X11/Xlib.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct rdp_clip {
	Display *dpy;
	int      be_fd;
	Window   owner_win;          /* InputOnly proxy window */
	Window   root;

	Atom     a_clipboard;
	Atom     a_targets;
	Atom     a_utf8_string;
	Atom     a_string;
	Atom     a_text;
	Atom     a_compound_text;
	Atom     a_timestamp;
	Atom     a_incr;            /* INCR transfer marker type */
	Atom     a_property;         /* our scratch property name */

	/* Incremental (INCR) read in progress: a remote owner is feeding us
	 * a large selection one chunk per PropertyNotify.  Accumulate here
	 * until a zero-length chunk marks the end, bounded by CLIP_X11_MAX. */
	int      incr_active;
	int      incr_discard;     /* over budget: drain chunks, keep none */
	uint8_t *incr_buf;
	size_t   incr_len;

	/* Cached content offered by the X side (from xterm copy etc.). */
	char    *x_text;
	size_t   x_text_len;
	int      x_fetch_pending;

	/* Cached content offered by the RDP client.  When set we own
	 * the CLIPBOARD selection; serve external SelectionRequests
	 * from this buffer. */
	char    *rdp_text;
	size_t   rdp_text_len;
	int      rdp_data_pending;   /* SelectionRequest deferred */

	/* If `rdp_data_pending`, remember the SelectionRequest so we
	 * can answer it when CLIP_DATA arrives. */
	Window   defer_requestor;
	Atom     defer_property;
	Atom     defer_target;
	Time     defer_time;
};

int  rdp_clip_init(struct rdp_clip *c, Display *dpy, int be_fd);
void rdp_clip_close(struct rdp_clip *c);

/* Called by the session main loop whenever an X event has arrived.
 * Returns 1 if the event was consumed by the clipboard machinery,
 * 0 otherwise so the caller can route it elsewhere. */
int  rdp_clip_handle_xevent(struct rdp_clip *c, XEvent *ev);

/* Called by the session main loop for each inbound backend CLIP_*
 * message.  `payload[0..len)` is the message body (no header). */
void rdp_clip_handle_be_msg(struct rdp_clip *c, uint32_t type,
		const uint8_t *payload, size_t len);

#endif /* RDP_CLIP_X11_H */
