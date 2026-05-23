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
	memset(c, 0, sizeof *c);
}

static char *
read_text_property(struct rdp_clip *c, Window win, Atom prop, size_t *len_out)
{
	Atom actual_type;
	int actual_format;
	unsigned long nitems = 0, bytes_after = 0;
	unsigned char *data = NULL;
	char *out = NULL;

	if (XGetWindowProperty(c->dpy, win, prop, 0, (long)CHUNK,
		True /* delete */, AnyPropertyType,
		&actual_type, &actual_format,
		&nitems, &bytes_after, &data) != Success)
		return NULL;
	if (data == NULL) {
		*len_out = 0;
		return NULL;
	}
	if (actual_format == 8 && nitems > 0) {
		out = malloc(nitems + 1);
		if (out != NULL) {
			memcpy(out, data, nitems);
			out[nitems] = '\0';
			*len_out = nitems;
		}
	}
	XFree(data);
	return out;
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
	c->x_fetch_pending = 1;
	XConvertSelection(c->dpy, c->a_clipboard, c->a_utf8_string,
		c->a_property, c->owner_win, xe->timestamp);
	XFlush(c->dpy);
}

static void
on_selection_notify(struct rdp_clip *c, XEvent *ev)
{
	XSelectionEvent *se = &ev->xselection;
	char *text;
	size_t len;

	if (se->selection != c->a_clipboard) return;
	c->x_fetch_pending = 0;
	if (se->property == None) {
		rdp_debug("clip: SelectionNotify with property None");
		return;
	}
	text = read_text_property(c, c->owner_win, se->property, &len);
	if (text == NULL || len == 0) {
		free(text);
		return;
	}
	free(c->x_text);
	c->x_text = text;
	c->x_text_len = len;
	rdp_debug("clip: cached X text, %zu bytes", len);

	{
		struct rdp_be_clip_offer offer = { RDP_BE_CLIP_FMT_TEXT };
		(void)rdp_be_send(c->be_fd, RDP_BE_CLIP_OFFER,
			&offer, sizeof offer);
	}
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
		XChangeProperty(c->dpy, requestor, property, target, 8,
			PropModeReplace, data, (int)len);
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
