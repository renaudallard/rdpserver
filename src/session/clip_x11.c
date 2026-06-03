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
 * clip_x11.c -- X11 selection <-> CLIPRDR bridge.
 *
 * Two directions:
 *
 *  X -> RDP   On XFixesSelectionNotify (owner change on CLIPBOARD,
 *             not us), call XConvertSelection asking for
 *             UTF8_STRING into our scratch property.  When the
 *             SelectionNotify arrives, read the property, cache
 *             the bytes, and send a CLIP_OFFER (eventually
 *             CLIP_DATA when the worker asks for it).
 *
 *  RDP -> X   On CLIP_OFFER from the worker, become the CLIPBOARD
 *             selection owner.  When another X client sends us a
 *             SelectionRequest, either answer immediately (for
 *             TARGETS/TIMESTAMP) or defer until CLIP_DATA arrives.
 */

#include "clip_x11.h"

#include "../include/rdp_log.h"
#include "../backend/proto.h"
#include "../backend/proto_api.h"

#include <X11/Xatom.h>
#include <X11/extensions/Xfixes.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHUNK 0x4000

/* Upper bound on a single clipboard transfer in either direction.  Matches
 * the backend's 4 MiB max payload and bounds memory against a hostile or
 * runaway selection owner. */
#define CLIP_X11_MAX (4u * 1024u * 1024u)

static int xfixes_event_base = 0;

int
rdp_clip_init(struct rdp_clip *c, Display *dpy, int be_fd)
{
	int err_base = 0;
	XSetWindowAttributes wa;

	memset(c, 0, sizeof *c);
	c->dpy = dpy;
	c->be_fd = be_fd;
	c->root = DefaultRootWindow(dpy);

	c->a_clipboard     = XInternAtom(dpy, "CLIPBOARD", False);
	c->a_targets       = XInternAtom(dpy, "TARGETS", False);
	c->a_utf8_string   = XInternAtom(dpy, "UTF8_STRING", False);
	c->a_string        = XA_STRING;
	c->a_text          = XInternAtom(dpy, "TEXT", False);
	c->a_compound_text = XInternAtom(dpy, "COMPOUND_TEXT", False);
	c->a_timestamp     = XInternAtom(dpy, "TIMESTAMP", False);
	c->a_incr          = XInternAtom(dpy, "INCR", False);
	c->a_property      = XInternAtom(dpy, "_RDP_CLIP_DATA", False);

	memset(&wa, 0, sizeof wa);
	wa.event_mask = PropertyChangeMask;
	c->owner_win = XCreateWindow(dpy, c->root, -10, -10, 1, 1, 0,
		0, InputOnly, CopyFromParent, CWEventMask, &wa);

	if (!XFixesQueryExtension(dpy, &xfixes_event_base, &err_base)) {
		rdp_warn("clip: XFixes extension missing");
		return -1;
	}
	XFixesSelectSelectionInput(dpy, c->root, c->a_clipboard,
		XFixesSetSelectionOwnerNotifyMask
		| XFixesSelectionWindowDestroyNotifyMask
		| XFixesSelectionClientCloseNotifyMask);
	XFlush(dpy);
	rdp_debug("clip: ready (owner_win=0x%lx)", (unsigned long)c->owner_win);
	return 0;
}

void
rdp_clip_close(struct rdp_clip *c)
{
	if (c->dpy != NULL && c->owner_win != 0)
		XDestroyWindow(c->dpy, c->owner_win);
	free(c->x_text);
	free(c->rdp_text);
	free(c->incr_buf);
	memset(c, 0, sizeof *c);
}

static void
clip_incr_reset(struct rdp_clip *c)
{
	free(c->incr_buf);
	c->incr_buf = NULL;
	c->incr_len = 0;
	c->incr_active = 0;
	c->incr_discard = 0;
}

/* Return a property's type without consuming it (a zero-length read). */
static Atom
peek_property_type(struct rdp_clip *c, Window win, Atom prop)
{
	Atom type = None;
	int fmt;
	unsigned long nitems = 0, bytes_after = 0;
	unsigned char *chunk = NULL;

	if (XGetWindowProperty(c->dpy, win, prop, 0, 0, False,
		AnyPropertyType, &type, &fmt, &nitems, &bytes_after,
		&chunk) != Success)
		return None;
	if (chunk != NULL)
		XFree(chunk);
	return type;
}

/* Read the whole current value of a format-8 property into a malloc'd,
 * NUL-terminated buffer, looping over bytes_after so a value larger than
 * CHUNK is not truncated; caller frees.  Does NOT delete the property.
 * Returns NULL with *len_out = 0 on a non-8 format, an empty value, an
 * oversize value (capped at CLIP_X11_MAX), or allocation failure. */
static uint8_t *
read_property_bytes(struct rdp_clip *c, Window win, Atom prop, size_t *len_out)
{
	uint8_t *out = NULL;
	size_t out_len = 0;
	long offset = 0;   /* in 32-bit units, as XGetWindowProperty expects */

	*len_out = 0;
	for (;;) {
		Atom type;
		int fmt;
		unsigned long nitems = 0, bytes_after = 0;
		unsigned char *chunk = NULL;
		uint8_t *nb;

		if (XGetWindowProperty(c->dpy, win, prop, offset,
			(long)(CHUNK / 4), False, AnyPropertyType,
			&type, &fmt, &nitems, &bytes_after, &chunk) != Success)
			break;
		if (fmt != 8 || nitems == 0 || chunk == NULL) {
			if (chunk != NULL)
				XFree(chunk);
			break;
		}
		if (out_len + nitems > CLIP_X11_MAX) {
			XFree(chunk);
			break;   /* refuse oversize; drop the partial read */
		}
		nb = realloc(out, out_len + nitems + 1);
		if (nb == NULL) {
			XFree(chunk);
			free(out);
			out = NULL;
			out_len = 0;
			break;
		}
		out = nb;
		memcpy(out + out_len, chunk, nitems);
		out_len += nitems;
		offset += (long)(nitems / 4);
		XFree(chunk);
		if (bytes_after == 0)
			break;
	}
	if (out != NULL) {
		out[out_len] = '\0';
		*len_out = out_len;
	}
	return out;
}

/* Cache freshly-fetched X selection bytes and tell the worker the X side
 * now holds clipboard content.  Takes ownership of `data`. */
static void
deliver_x_selection(struct rdp_clip *c, uint8_t *data, size_t len)
{
	struct rdp_be_clip_offer offer = { RDP_BE_CLIP_FMT_TEXT };

	if (data == NULL || len == 0) {
		free(data);
		return;
	}
	free(c->x_text);
	c->x_text = (char *)data;
	c->x_text_len = len;
	rdp_debug("clip: cached X selection, %zu bytes", len);
	(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_OFFER, &offer, sizeof offer);
}

static void
on_xfixes_selection_notify(struct rdp_clip *c, XEvent *ev)
{
	XFixesSelectionNotifyEvent *xe = (XFixesSelectionNotifyEvent *)ev;
	if (xe->selection != c->a_clipboard) return;
	if (xe->owner == c->owner_win) return;
	if (xe->owner == None) {
		rdp_debug("clip: CLIPBOARD owner cleared");
		return;
	}
	rdp_debug("clip: CLIPBOARD owner changed to 0x%lx; fetching",
		(unsigned long)xe->owner);
	clip_incr_reset(c);   /* abandon any in-progress incremental fetch */
	c->x_fetch_pending = 1;
	XConvertSelection(c->dpy, c->a_clipboard, c->a_utf8_string,
		c->a_property, c->owner_win, xe->timestamp);
	XFlush(c->dpy);
}

/* One INCR chunk has arrived in our scratch property (PropertyNotify with
 * a new value).  Append it; a zero-length chunk marks the end. */
static void
on_incr_property(struct rdp_clip *c)
{
	uint8_t *chunk;
	size_t clen;
	uint8_t *nb;

	chunk = read_property_bytes(c, c->owner_win, c->a_property, &clen);
	/* Deleting the property tells the owner to send the next chunk. */
	XDeleteProperty(c->dpy, c->owner_win, c->a_property);
	XFlush(c->dpy);

	if (chunk == NULL || clen == 0) {
		/* Terminator: deliver the assembled value, unless we gave up
		 * mid-transfer and were only draining the owner to its end. */
		uint8_t *all = c->incr_discard ? NULL : c->incr_buf;
		size_t alllen = c->incr_discard ? 0 : c->incr_len;
		free(chunk);
		c->incr_buf = NULL;
		c->incr_len = 0;
		c->incr_active = 0;
		c->incr_discard = 0;
		c->x_fetch_pending = 0;
		deliver_x_selection(c, all, alllen);
		return;
	}
	/* Once over budget (or after an allocation failure) we keep acking
	 * each chunk so the owner's INCR handshake does not wedge, but throw
	 * the data away and deliver nothing at the terminator. */
	if (c->incr_discard) {
		free(chunk);
		return;
	}
	if (c->incr_len + clen > CLIP_X11_MAX) {
		free(chunk);
		free(c->incr_buf);
		c->incr_buf = NULL;
		c->incr_len = 0;
		c->incr_discard = 1;
		return;
	}
	nb = realloc(c->incr_buf, c->incr_len + clen);
	if (nb == NULL) {
		free(chunk);
		free(c->incr_buf);
		c->incr_buf = NULL;
		c->incr_len = 0;
		c->incr_discard = 1;
		return;
	}
	c->incr_buf = nb;
	memcpy(c->incr_buf + c->incr_len, chunk, clen);
	c->incr_len += clen;
	free(chunk);
}

static void
on_selection_notify(struct rdp_clip *c, XEvent *ev)
{
	XSelectionEvent *se = &ev->xselection;
	uint8_t *data;
	size_t len;

	if (se->selection != c->a_clipboard) return;
	if (se->property == None) {
		rdp_debug("clip: SelectionNotify with property None");
		c->x_fetch_pending = 0;
		return;
	}
	/* A large value is delivered incrementally: the property carries the
	 * INCR marker and the data follows one chunk per PropertyNotify.
	 * Deleting the property signals the owner to begin. */
	if (peek_property_type(c, c->owner_win, se->property) == c->a_incr) {
		clip_incr_reset(c);
		c->incr_active = 1;
		XDeleteProperty(c->dpy, c->owner_win, se->property);
		XFlush(c->dpy);
		return;
	}
	c->x_fetch_pending = 0;
	data = read_property_bytes(c, c->owner_win, se->property, &len);
	XDeleteProperty(c->dpy, c->owner_win, se->property);
	XFlush(c->dpy);
	deliver_x_selection(c, data, len);
}

/* Set a format-8 property in CHUNK-sized pieces (Replace then Append) so a
 * value larger than the X server's maximum request size is still delivered;
 * the server assembles the whole property before the requestor reads it. */
static void
put_property_chunked(struct rdp_clip *c, Window win, Atom prop, Atom type,
		const unsigned char *data, size_t len)
{
	size_t off = 0;
	int mode = PropModeReplace;

	do {
		size_t chunk = len - off;
		if (chunk > CHUNK)
			chunk = CHUNK;
		XChangeProperty(c->dpy, win, prop, type, 8, mode,
			data + off, (int)chunk);
		mode = PropModeAppend;
		off += chunk;
	} while (off < len);
}

static void
answer_selection_request(struct rdp_clip *c, Window requestor,
		Atom property, Atom selection, Atom target, Time t,
		const void *data, size_t len)
{
	XEvent ev;
	memset(&ev, 0, sizeof ev);
	ev.xselection.type      = SelectionNotify;
	ev.xselection.requestor = requestor;
	ev.xselection.selection = selection;
	ev.xselection.target    = target;
	ev.xselection.time      = t;
	if (data != NULL && len > 0) {
		put_property_chunked(c, requestor, property, target,
			(const unsigned char *)data, len);
		ev.xselection.property = property;
	} else {
		ev.xselection.property = None;
	}
	XSendEvent(c->dpy, requestor, False, NoEventMask, &ev);
	XFlush(c->dpy);
}

static void
on_selection_request(struct rdp_clip *c, XEvent *ev)
{
	XSelectionRequestEvent *re = &ev->xselectionrequest;
	if (re->selection != c->a_clipboard)
		return;

	if (re->target == c->a_targets) {
		Atom targets[4];
		int n = 0;
		targets[n++] = c->a_targets;
		targets[n++] = c->a_utf8_string;
		targets[n++] = c->a_string;
		targets[n++] = c->a_text;
		XChangeProperty(c->dpy, re->requestor, re->property,
			XA_ATOM, 32, PropModeReplace,
			(unsigned char *)targets, n);
		{
			XEvent reply;
			memset(&reply, 0, sizeof reply);
			reply.xselection.type      = SelectionNotify;
			reply.xselection.requestor = re->requestor;
			reply.xselection.selection = re->selection;
			reply.xselection.target    = re->target;
			reply.xselection.property  = re->property;
			reply.xselection.time      = re->time;
			XSendEvent(c->dpy, re->requestor, False,
				NoEventMask, &reply);
			XFlush(c->dpy);
		}
		return;
	}
	if (re->target == c->a_timestamp) {
		Time tt = CurrentTime;
		XChangeProperty(c->dpy, re->requestor, re->property,
			XA_INTEGER, 32, PropModeReplace,
			(unsigned char *)&tt, 1);
		answer_selection_request(c, re->requestor,
			re->property, re->selection, re->target,
			re->time, NULL, 0);
		return;
	}
	if (re->target == c->a_utf8_string
	    || re->target == c->a_string
	    || re->target == c->a_text
	    || re->target == c->a_compound_text) {
		if (c->rdp_text != NULL && c->rdp_text_len > 0) {
			answer_selection_request(c, re->requestor,
				re->property, re->selection, re->target,
				re->time, c->rdp_text, c->rdp_text_len);
			return;
		}
		/* Defer until CLIP_DATA arrives.  Replace any previous
		 * deferral; only the most recent requestor gets the
		 * data when it comes in.  Lifetime-wise this is fine:
		 * Selection conversions are one-shot. */
		c->defer_requestor = re->requestor;
		c->defer_property  = re->property;
		c->defer_target    = re->target;
		c->defer_time      = re->time;
		c->rdp_data_pending = 1;
		{
			struct rdp_be_clip_request req = {
				RDP_BE_CLIP_FMT_TEXT };
			(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_REQUEST,
				&req, sizeof req);
		}
		return;
	}
	/* Unknown target: send refusal. */
	answer_selection_request(c, re->requestor, re->property,
		re->selection, re->target, re->time, NULL, 0);
}

int
rdp_clip_handle_xevent(struct rdp_clip *c, XEvent *ev)
{
	if (ev->type == xfixes_event_base + XFixesSelectionNotify) {
		on_xfixes_selection_notify(c, ev);
		return 1;
	}
	if (ev->type == SelectionNotify) {
		on_selection_notify(c, ev);
		return 1;
	}
	if (ev->type == PropertyNotify) {
		XPropertyEvent *pe = &ev->xproperty;
		if (c->incr_active && pe->window == c->owner_win
		    && pe->atom == c->a_property
		    && pe->state == PropertyNewValue) {
			on_incr_property(c);
			return 1;
		}
		return 0;
	}
	if (ev->type == SelectionRequest) {
		on_selection_request(c, ev);
		return 1;
	}
	if (ev->type == SelectionClear) {
		XSelectionClearEvent *sc = &ev->xselectionclear;
		if (sc->selection == c->a_clipboard) {
			free(c->rdp_text);
			c->rdp_text = NULL;
			c->rdp_text_len = 0;
		}
		return 1;
	}
	return 0;
}

void
rdp_clip_handle_be_msg(struct rdp_clip *c, uint32_t type,
		const uint8_t *payload, size_t len)
{
	switch (type) {
	case RDP_BE_CLIP_OFFER:
		/* The RDP client just announced it has clipboard content.
		 * Claim CLIPBOARD; future SelectionRequests will trigger
		 * a CLIP_REQUEST -> CLIP_DATA round-trip. */
		XSetSelectionOwner(c->dpy, c->a_clipboard,
			c->owner_win, CurrentTime);
		XFlush(c->dpy);
		free(c->rdp_text);
		c->rdp_text = NULL;
		c->rdp_text_len = 0;
		rdp_debug("clip: claimed CLIPBOARD on offer");
		break;
	case RDP_BE_CLIP_REQUEST:
		/* The worker (on behalf of the RDP client) asks for the
		 * X clipboard content.  Reply with our cached x_text. */
		(void)payload; (void)len;
		{
			struct rdp_be_clip_data_hdr h;
			uint8_t *buf;
			size_t  buf_len = sizeof h + (c->x_text ? c->x_text_len : 0);

			h.format = RDP_BE_CLIP_FMT_TEXT;
			h.status = (c->x_text != NULL) ? 0 : 1;
			buf = malloc(buf_len);
			if (buf == NULL) break;
			memcpy(buf, &h, sizeof h);
			if (c->x_text != NULL && c->x_text_len > 0)
				memcpy(buf + sizeof h, c->x_text, c->x_text_len);
			(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_DATA,
				buf, buf_len);
			free(buf);
		}
		break;
	case RDP_BE_CLIP_DATA: {
		struct rdp_be_clip_data_hdr h;
		if (len < sizeof h) break;
		memcpy(&h, payload, sizeof h);
		free(c->rdp_text);
		c->rdp_text = NULL;
		c->rdp_text_len = 0;
		if (h.status == 0 && len > sizeof h) {
			c->rdp_text_len = len - sizeof h;
			c->rdp_text = malloc(c->rdp_text_len + 1);
			if (c->rdp_text != NULL) {
				memcpy(c->rdp_text,
					payload + sizeof h,
					c->rdp_text_len);
				c->rdp_text[c->rdp_text_len] = '\0';
			} else {
				c->rdp_text_len = 0;
			}
		}
		if (c->rdp_data_pending) {
			c->rdp_data_pending = 0;
			if (c->rdp_text != NULL && c->rdp_text_len > 0) {
				answer_selection_request(c,
					c->defer_requestor,
					c->defer_property,
					c->a_clipboard,
					c->defer_target,
					c->defer_time,
					c->rdp_text, c->rdp_text_len);
			} else {
				answer_selection_request(c,
					c->defer_requestor,
					c->defer_property,
					c->a_clipboard,
					c->defer_target,
					c->defer_time,
					NULL, 0);
			}
		}
		break;
	}
	}
}
