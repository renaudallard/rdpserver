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
	Atom     a_text_html;       /* text/html target */
	Atom     a_image_bmp;       /* image/bmp target */
	Atom     a_image_xbmp;      /* image/x-bmp target (alias) */
	Atom     a_uri_list;        /* text/uri-list target (file copy) */
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

	/* X -> RDP: the semantic format (RDP_BE_CLIP_FMT_*) currently being
	 * fetched from the X selection owner; 0 means the initial TARGETS
	 * probe that learns which formats the owner exposes. */
	uint32_t x_fetch_fmt;

	/* RDP -> X: formats the RDP client offers (bitmap), advertised to
	 * local apps as selection targets while we own CLIPBOARD. */
	uint32_t rdp_offered;

	/* A SelectionRequest deferred until the worker returns CLIP_DATA. */
	int      rdp_data_pending;
	uint32_t defer_fmt;
	Window   defer_requestor;
	Atom     defer_property;
	Atom     defer_target;
	Time     defer_time;

	/* X -> RDP file copy: the absolute local paths backing the
	 * FileGroupDescriptorW blob we last built for the worker.  A
	 * subsequent CLIP_FILE_REQUEST selects one by lindex and we read the
	 * bytes from here.  Reset on every owner change / SelectionClear. */
	char   **file_paths;
	size_t   file_count;

	/* RDP -> X file paste (file copied in the RDP client, pasted into a
	 * local app).  When a local app asks for text/uri-list we request the
	 * FileGroupDescriptorW from the worker, eagerly download every file's
	 * bytes into a private temp dir, then answer the deferred
	 * SelectionRequest with a text/uri-list of file:// URIs under that dir.
	 *
	 * dl_active marks a download in progress.  dl_descs holds the parsed
	 * (and path-sanitized) destination entries; dl_n is their count.
	 * dl_idx is the entry being downloaded, dl_fd its open fd (-1 if none),
	 * dl_off the bytes written so far, dl_size its declared size, and
	 * dl_stream the stream_id of the FILE_REQUEST in flight.  dl_tmpdir is
	 * the mkdtemp scratch directory (NULL when none); it is removed
	 * recursively on reset and on close.  The deferred SelectionRequest is
	 * held in the existing defer_* slot. */
	int      dl_active;
	struct rdp_clip_dlent *dl_descs;
	size_t   dl_n;
	size_t   dl_idx;
	int      dl_fd;
	uint64_t dl_off;
	uint64_t dl_size;
	uint32_t dl_stream;
	char    *dl_tmpdir;
};

/* One entry of an in-progress RDP -> X file paste: the sanitized absolute
 * destination path under the temp dir, the declared size, whether it is a
 * directory (created with mkdir, no bytes downloaded), and the lindex it
 * occupies in the client's FileGroupDescriptorW (needed to request its bytes).
 * top_level is set for an entry whose sanitized path has a single component,
 * so only those go into the answering text/uri-list. */
struct rdp_clip_dlent {
	char    *path;       /* absolute path under dl_tmpdir */
	uint64_t size;
	int      is_dir;
	int      top_level;
	uint32_t lindex;
};

/* Largest number of files carried in one clipboard file-copy offer. */
#define RDP_CLIP_MAX_FILES 64u

int  rdp_clip_init(struct rdp_clip *c, Display *dpy, int be_fd);
void rdp_clip_close(struct rdp_clip *c);

/*
 * Sanitize an attacker-controlled FileGroupDescriptorW file name into a
 * relative path that is guaranteed to stay under a base directory.  `name`
 * is the UTF-8 name from the client (its path separators may be backslashes).
 * On success writes a clean, slash-separated relative path (no leading slash,
 * no "." or ".." component, no empty component, no embedded NUL) into out
 * (capacity out_cap including the terminating NUL) and returns 0.  Returns -1
 * if the name is empty, absolute, contains a traversal or empty component, or
 * does not fit, in which case the caller must skip the entry.  Exposed for
 * unit testing.
 */
int  rdp_clip_sanitize_name(const char *name, char *out, size_t out_cap);

/* Called by the session main loop whenever an X event has arrived.
 * Returns 1 if the event was consumed by the clipboard machinery,
 * 0 otherwise so the caller can route it elsewhere. */
int  rdp_clip_handle_xevent(struct rdp_clip *c, XEvent *ev);

/* Called by the session main loop for each inbound backend CLIP_*
 * message.  `payload[0..len)` is the message body (no header). */
void rdp_clip_handle_be_msg(struct rdp_clip *c, uint32_t type,
		const uint8_t *payload, size_t len);

#endif /* RDP_CLIP_X11_H */
