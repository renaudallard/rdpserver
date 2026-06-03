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
 * Two directions, several formats (plain text and text/html; the worker
 * maps these to the matching CLIPRDR formats):
 *
 *  X -> RDP   On XFixesSelectionNotify (owner change on CLIPBOARD, not us)
 *             convert the TARGETS atom to learn which formats the owner
 *             exposes, and announce the matching set with a CLIP_OFFER.
 *             When the worker asks for one with a CLIP_REQUEST, convert
 *             that target, read the property (looping / INCR for large
 *             values), and return the bytes with a CLIP_DATA.
 *
 *  RDP -> X   On CLIP_OFFER from the worker, become the CLIPBOARD owner and
 *             remember the offered formats.  Answer TARGETS/TIMESTAMP
 *             SelectionRequests directly; for a data target, ask the worker
 *             (CLIP_REQUEST) and answer once CLIP_DATA arrives.
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
	c->a_text_html     = XInternAtom(dpy, "text/html", False);
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
	free(c->incr_buf);
	memset(c, 0, sizeof *c);
}

/* --- format <-> X target mapping --- */

static Atom
target_for_fmt(struct rdp_clip *c, uint32_t fmt)
{
	switch (fmt) {
	case RDP_BE_CLIP_FMT_TEXT:
		return c->a_utf8_string;
	case RDP_BE_CLIP_FMT_HTML:
		return c->a_text_html;
	}
	return None;
}

static uint32_t
fmt_for_target(struct rdp_clip *c, Atom target)
{
	if (target == c->a_utf8_string || target == c->a_string
	    || target == c->a_text || target == c->a_compound_text)
		return RDP_BE_CLIP_FMT_TEXT;
	if (target == c->a_text_html)
		return RDP_BE_CLIP_FMT_HTML;
	return 0;
}

/* --- backend senders --- */

static void
send_clip_offer(struct rdp_clip *c, uint32_t bitmap)
{
	struct rdp_be_clip_offer offer;
	offer.formats = bitmap;
	(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_OFFER, &offer, sizeof offer);
}

static void
send_clip_request(struct rdp_clip *c, uint32_t fmt)
{
	struct rdp_be_clip_request req;
	req.format = fmt;
	(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_REQUEST, &req, sizeof req);
}

/* Send CLIP_DATA back to the worker.  A NULL `data` reports failure. */
static void
send_clip_data(struct rdp_clip *c, uint32_t fmt, const uint8_t *data,
		size_t len)
{
	struct rdp_be_clip_data_hdr h;
	uint8_t *buf;
	size_t buf_len = sizeof h + (data != NULL ? len : 0);

	h.format = fmt;
	h.status = (data != NULL) ? 0 : 1;
	buf = malloc(buf_len);
	if (buf == NULL)
		return;
	memcpy(buf, &h, sizeof h);
	if (data != NULL && len > 0)
		memcpy(buf + sizeof h, data, len);
	(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_DATA, buf, buf_len);
	free(buf);
}

/* --- property helpers --- */

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

/* --- X -> RDP: fetch from the X selection owner --- */

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
	rdp_debug("clip: CLIPBOARD owner changed to 0x%lx; probing targets",
		(unsigned long)xe->owner);
	clip_incr_reset(c);   /* abandon any in-progress incremental fetch */
	c->x_fetch_fmt = 0;   /* 0 = the TARGETS probe */
	XConvertSelection(c->dpy, c->a_clipboard, c->a_targets,
		c->a_property, c->owner_win, xe->timestamp);
	XFlush(c->dpy);
}

/* The TARGETS conversion landed: learn the owner's formats and offer the
 * matching set to the worker. */
static void
on_targets_notify(struct rdp_clip *c, Atom prop)
{
	Atom type;
	int fmt;
	unsigned long nitems = 0, bytes_after = 0, i;
	unsigned char *data = NULL;
	uint32_t bitmap = 0;

	if (XGetWindowProperty(c->dpy, c->owner_win, prop, 0, 1024, True,
		XA_ATOM, &type, &fmt, &nitems, &bytes_after, &data) == Success
	    && data != NULL && fmt == 32) {
		Atom *atoms = (Atom *)(void *)data;
		for (i = 0; i < nitems; i++)
			bitmap |= fmt_for_target(c, atoms[i]);
	}
	if (data != NULL)
		XFree(data);
	/* Some minimal owners do not implement TARGETS; assume plain text. */
	if (bitmap == 0)
		bitmap = RDP_BE_CLIP_FMT_TEXT;
	send_clip_offer(c, bitmap);
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
		/* Terminator: hand the assembled value to the worker, unless we
		 * gave up mid-transfer and were only draining the owner. */
		uint8_t *all = c->incr_discard ? NULL : c->incr_buf;
		size_t alllen = c->incr_discard ? 0 : c->incr_len;
		uint32_t fmt = c->x_fetch_fmt;
		free(chunk);
		c->incr_buf = NULL;
		c->incr_len = 0;
		c->incr_active = 0;
		c->incr_discard = 0;
		send_clip_data(c, fmt, all, alllen);
		free(all);
		return;
	}
	/* Once over budget (or after an allocation failure) we keep acking
	 * each chunk so the owner's INCR handshake does not wedge, but throw
	 * the data away and report failure at the terminator. */
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
		/* The owner refused the conversion.  If this was the initial
		 * TARGETS probe, assume plain text is available (many minimal
		 * owners do not implement TARGETS). */
		if (se->target == c->a_targets)
			send_clip_offer(c, RDP_BE_CLIP_FMT_TEXT);
		else
			send_clip_data(c, c->x_fetch_fmt, NULL, 0);
		return;
	}
	if (se->target == c->a_targets) {
		on_targets_notify(c, se->property);
		return;
	}
	/* A data conversion.  A large value is delivered incrementally: the
	 * property carries the INCR marker and the data follows one chunk per
	 * PropertyNotify; deleting it signals the owner to begin. */
	if (peek_property_type(c, c->owner_win, se->property) == c->a_incr) {
		clip_incr_reset(c);
		c->incr_active = 1;
		XDeleteProperty(c->dpy, c->owner_win, se->property);
		XFlush(c->dpy);
		return;
	}
	/* Tag the reply by the converted target rather than the shared
	 * x_fetch_fmt, so an owner change that restarted the TARGETS probe
	 * (x_fetch_fmt = 0) mid-fetch cannot mislabel this data. */
	{
		uint32_t fmt = fmt_for_target(c, se->target);
		if (fmt == 0)
			fmt = c->x_fetch_fmt;
		data = read_property_bytes(c, c->owner_win, se->property, &len);
		XDeleteProperty(c->dpy, c->owner_win, se->property);
		XFlush(c->dpy);
		send_clip_data(c, fmt, data, len);
		free(data);
	}
}

/* --- RDP -> X: serve the RDP client's clipboard to local apps --- */

static void
on_selection_request(struct rdp_clip *c, XEvent *ev)
{
	XSelectionRequestEvent *re = &ev->xselectionrequest;
	uint32_t fmt;

	if (re->selection != c->a_clipboard)
		return;

	if (re->target == c->a_targets) {
		Atom targets[8];
		int n = 0;
		targets[n++] = c->a_targets;
		targets[n++] = c->a_timestamp;
		if (c->rdp_offered & RDP_BE_CLIP_FMT_TEXT) {
			targets[n++] = c->a_utf8_string;
			targets[n++] = c->a_string;
			targets[n++] = c->a_text;
		}
		if (c->rdp_offered & RDP_BE_CLIP_FMT_HTML)
			targets[n++] = c->a_text_html;
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
	fmt = fmt_for_target(c, re->target);
	if (fmt != 0 && (c->rdp_offered & fmt) && !c->rdp_data_pending) {
		/* Ask the worker for this format and answer when CLIP_DATA
		 * arrives.  Only one request is outstanding at a time: the
		 * worker decodes the response by the format it last requested,
		 * and we hold a single deferred requestor.  A second overlapping
		 * conversion is refused rather than risk a format mismatch; the
		 * requestor can retry once the first completes. */
		c->defer_requestor = re->requestor;
		c->defer_property  = re->property;
		c->defer_target    = re->target;
		c->defer_time      = re->time;
		c->defer_fmt       = fmt;
		c->rdp_data_pending = 1;
		send_clip_request(c, fmt);
		return;
	}
	/* Unknown, un-offered, or busy: refuse. */
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
			c->rdp_offered = 0;
			c->rdp_data_pending = 0;
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
	case RDP_BE_CLIP_OFFER: {
		/* The RDP client announced clipboard content; claim CLIPBOARD
		 * and remember which formats to advertise to local apps. */
		struct rdp_be_clip_offer o;
		o.formats = RDP_BE_CLIP_FMT_TEXT;
		if (len >= sizeof o)
			memcpy(&o, payload, sizeof o);
		c->rdp_offered = o.formats;
		c->rdp_data_pending = 0;
		XSetSelectionOwner(c->dpy, c->a_clipboard,
			c->owner_win, CurrentTime);
		XFlush(c->dpy);
		rdp_debug("clip: claimed CLIPBOARD (formats 0x%x)",
			c->rdp_offered);
		break;
	}
	case RDP_BE_CLIP_REQUEST: {
		/* The worker wants one format from the X selection owner. */
		struct rdp_be_clip_request rq;
		Atom tgt;
		rq.format = RDP_BE_CLIP_FMT_TEXT;
		if (len >= sizeof rq)
			memcpy(&rq, payload, sizeof rq);
		tgt = target_for_fmt(c, rq.format);
		if (tgt == None) {
			send_clip_data(c, rq.format, NULL, 0);
			break;
		}
		clip_incr_reset(c);
		c->x_fetch_fmt = rq.format;
		XConvertSelection(c->dpy, c->a_clipboard, tgt,
			c->a_property, c->owner_win, CurrentTime);
		XFlush(c->dpy);
		break;
	}
	case RDP_BE_CLIP_DATA: {
		/* The worker returned the data for a deferred SelectionRequest. */
		struct rdp_be_clip_data_hdr h;
		const uint8_t *data = NULL;
		size_t dlen = 0;

		if (len < sizeof h)
			break;
		memcpy(&h, payload, sizeof h);
		if (h.status == 0 && len > sizeof h) {
			data = payload + sizeof h;
			dlen = len - sizeof h;
		}
		if (c->rdp_data_pending) {
			c->rdp_data_pending = 0;
			answer_selection_request(c, c->defer_requestor,
				c->defer_property, c->a_clipboard,
				c->defer_target, c->defer_time, data, dlen);
		}
		break;
	}
	}
}
