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
 * clip_x11_live.c -- live validation of the X11 clipboard bridge
 * (src/session/clip_x11.c) against a REAL X server (Xvfb) using the
 * REAL xclip as the cooperating X client.  NOT part of the default
 * regress: it spawns Xvfb, so it is built and run by hand:
 *
 *   make regress/integ/clip_x11_live
 *   ./regress/integ/clip_x11_live
 *
 * What it does.  It links clip_x11.c with a tiny harness that plays the
 * role of the rdp_session main loop and the backend worker at once:
 *
 *   - A socketpair stands in for the session<->worker backend socket.
 *     sv[1] is clip's c->be_fd; sv[0] is the harness's worker end.
 *     clip writes sv[1] -> harness reads sv[0]; harness writes sv[0] ->
 *     drive loop reads sv[1].
 *   - The drive loop polls the X connection fd (ConnectionNumber(dpy))
 *     and sv[1].  On X readable it pumps XNextEvent + rdp_clip_handle_xevent;
 *     on sv[1] readable it pumps rdp_be_recv + rdp_clip_handle_be_msg.
 *   - Control logic uses sv[0]: rdp_be_send(sv[0],...) pushes a CLIP_*
 *     message to the session; rdp_be_recv(sv[0],...) observes what clip
 *     emitted.
 *
 * The cooperating X client is the real xclip:
 *   - `xclip -selection clipboard -i` (fed text) becomes the CLIPBOARD
 *     owner -> exercises the X -> RDP path (read_property_bytes and, at
 *     ~1 MiB, its bytes_after multi-chunk loop).
 *   - `xclip -selection clipboard -o` requests CLIPBOARD from clip ->
 *     exercises the RDP -> X path (put_property_chunked) for small and
 *     ~1 MiB text.
 *
 * xclip does NOT switch to INCR even at 1 MiB on this server (BIG-REQUESTS
 * ships the whole value in one request), so a dedicated case (E) uses our
 * own minimal ICCCM INCR selection owner to drive clip's INCR reader
 * (on_incr_property / the PropertyNotify path) across many chunks.
 *
 * The point is the size-robustness paths no unit test covers: the
 * bytes_after read loop, the INCR incremental reader, and the chunked
 * PropModeAppend write, in BOTH directions for small AND ~1 MiB text.
 *
 * Cases (each prints pass/fail):
 *   A  X -> RDP, small text ("hello clipboard") via xclip -i.
 *   B  X -> RDP, ~1 MiB text via xclip -i (bytes_after loop).
 *   C  RDP -> X, small text; xclip -o reads it back.
 *   D  RDP -> X, ~1 MiB text; xclip -o reads it back (put_property_chunked).
 *   E  X -> RDP, 256 KiB via a forced INCR transfer (INCR reader).
 *   F  X -> RDP, HTML; an xclip -t text/html owner offers the HTML target,
 *      clip emits CLIP_OFFER with the HTML bit and returns the raw fragment.
 *   G  RDP -> X, HTML; clip claims CLIPBOARD advertising HTML, xclip -t
 *      text/html -o pulls the raw fragment back.
 *   H  X -> RDP, image; an xclip -t image/bmp owner offers the image/bmp
 *      target carrying a small BMP, clip emits CLIP_OFFER with the IMAGE bit
 *      and returns the BMP bytes unchanged.
 *   I  RDP -> X, image; clip claims CLIPBOARD advertising IMAGE, xclip -t
 *      image/bmp -o pulls the BMP bytes back unchanged.
 */

#include "../../src/session/clip_x11.h"
#include "../../src/backend/proto.h"
#include "../../src/backend/proto_api.h"

#include "../../src/include/rdp_log.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <X11/Xlib.h>
#include <X11/Xatom.h>

/* The big-text size.  At ~1 MiB an X selection exceeds a single
 * XGetWindowProperty chunk, so this exercises the bytes_after loop;
 * many owners (xclip among them) switch to INCR above their internal
 * threshold, which exercises the INCR reader too. */
#define BIG_LEN   1000000u
#define BIG_FILL  'A'

/*
 * A small but VALID 2x2 24bpp BMP, used by the image (image/bmp) cases H/I.
 * Only that the 70 bytes round-trip unchanged matters; the pixels are
 * arbitrary.  Layout:
 *   14-byte BITMAPFILEHEADER: 'B','M', bfSize=70, reserved=0, bfOffBits=54.
 *   40-byte BITMAPINFOHEADER: biSize=40, biWidth=2, biHeight=2, biPlanes=1,
 *     biBitCount=24, remaining fields 0.
 *   16-byte pixel array: two bottom-up rows, each 6 bytes BGR + 2 pad.
 * All multi-byte header fields are little-endian (BMP on-disk order).
 */
static const uint8_t bmp_2x2[70] = {
	/* BITMAPFILEHEADER */
	0x42, 0x4d,             /* 'B','M' */
	0x46, 0x00, 0x00, 0x00, /* bfSize = 70 */
	0x00, 0x00,             /* bfReserved1 */
	0x00, 0x00,             /* bfReserved2 */
	0x36, 0x00, 0x00, 0x00, /* bfOffBits = 54 */
	/* BITMAPINFOHEADER */
	0x28, 0x00, 0x00, 0x00, /* biSize = 40 */
	0x02, 0x00, 0x00, 0x00, /* biWidth = 2 */
	0x02, 0x00, 0x00, 0x00, /* biHeight = 2 */
	0x01, 0x00,             /* biPlanes = 1 */
	0x18, 0x00,             /* biBitCount = 24 */
	0x00, 0x00, 0x00, 0x00, /* biCompression = 0 (BI_RGB) */
	0x00, 0x00, 0x00, 0x00, /* biSizeImage = 0 */
	0x00, 0x00, 0x00, 0x00, /* biXPelsPerMeter = 0 */
	0x00, 0x00, 0x00, 0x00, /* biYPelsPerMeter = 0 */
	0x00, 0x00, 0x00, 0x00, /* biClrUsed = 0 */
	0x00, 0x00, 0x00, 0x00, /* biClrImportant = 0 */
	/* pixel array: row 0 (bottom) then row 1 (top), each 6 BGR + 2 pad */
	0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
};

/* ---- globals shared by the drive loop ---- */

static Display      *g_dpy;
static struct rdp_clip g_clip;
static int           g_sv0 = -1;   /* harness/worker end */
static int           g_sv1 = -1;   /* clip's be_fd */
static int           g_xfd = -1;   /* ConnectionNumber(dpy) */
static const char   *g_display;    /* ":91" etc., for xclip children */

static int g_fail = 0;

#define FAILF(...) do { \
	(void)fprintf(stderr, "  FAIL: " __VA_ARGS__); \
	(void)fprintf(stderr, "\n"); \
	g_fail = 1; \
} while (0)

/* monotonic milliseconds */
static long
now_ms(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Pump exactly one round of X events and one round of backend messages
 * arriving on sv[1] (clip's input).  Non-blocking on sv[1].  Returns the
 * number of items handled. */
static int
pump_once(void)
{
	int handled = 0;

	/* Drain all queued/pending X events. */
	while (XPending(g_dpy) > 0) {
		XEvent ev;
		XNextEvent(g_dpy, &ev);
		(void)rdp_clip_handle_xevent(&g_clip, &ev);
		handled++;
	}

	/* Drain backend messages destined for clip (sv[1]).  rdp_be_recv
	 * blocks, so only call it when a full message is readable.  We peek
	 * with a non-blocking poll; rdp_be_recv then reads one whole frame. */
	for (;;) {
		struct pollfd p;
		uint32_t type = 0;
		uint8_t buf[BIG_LEN + 1024];
		ssize_t n;

		p.fd = g_sv1;
		p.events = POLLIN;
		p.revents = 0;
		if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN))
			break;
		n = rdp_be_recv(g_sv1, &type, buf, sizeof buf);
		if (n < 0) {
			FAILF("rdp_be_recv(sv1): %s", strerror(errno));
			break;
		}
		if (n == 0)
			break;   /* peer closed */
		rdp_clip_handle_be_msg(&g_clip, type, buf, (size_t)n);
		handled++;
	}
	return handled;
}

/* Pump the drive loop until predicate() returns nonzero or timeout_ms
 * elapses.  Blocks in poll() on the X fd + sv1 so we are not busy-looping.
 * Returns 1 if the predicate held, 0 on timeout. */
static int
drive_until(int (*pred)(void *), void *arg, int timeout_ms)
{
	long deadline = now_ms() + timeout_ms;

	for (;;) {
		struct pollfd p[2];
		long remain;

		pump_once();
		if (pred != NULL && pred(arg))
			return 1;
		remain = deadline - now_ms();
		if (remain <= 0)
			return pred == NULL ? 1 : (pred(arg) ? 1 : 0);

		/* Flush so any XSendEvent/XChangeProperty we issued reaches the
		 * server, then block until either fd is readable. */
		XFlush(g_dpy);
		p[0].fd = g_xfd;
		p[0].events = POLLIN;
		p[0].revents = 0;
		p[1].fd = g_sv1;
		p[1].events = POLLIN;
		p[1].revents = 0;
		(void)poll(p, 2, remain > 100 ? 100 : (int)remain);
	}
}

/* Read one backend message that clip emitted (arrives on sv[0]) within
 * timeout_ms, while continuing to pump the drive loop so clip can make
 * progress.  On success fills *type_out and copies up to cap bytes into
 * out, returning the true payload length; returns -1 on timeout. */
static ssize_t
expect_be_msg(uint32_t *type_out, uint8_t *out, size_t cap, int timeout_ms)
{
	long deadline = now_ms() + timeout_ms;

	for (;;) {
		struct pollfd p;
		long remain;

		pump_once();

		p.fd = g_sv0;
		p.events = POLLIN;
		p.revents = 0;
		if (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) {
			ssize_t n = rdp_be_recv(g_sv0, type_out, out, cap);
			if (n < 0) {
				FAILF("rdp_be_recv(sv0): %s", strerror(errno));
				return -1;
			}
			return n;
		}
		remain = deadline - now_ms();
		if (remain <= 0)
			return -1;
		XFlush(g_dpy);
		{
			struct pollfd q[2];
			q[0].fd = g_xfd;
			q[0].events = POLLIN;
			q[0].revents = 0;
			q[1].fd = g_sv1;
			q[1].events = POLLIN;
			q[1].revents = 0;
			(void)poll(q, 2, remain > 50 ? 50 : (int)remain);
		}
	}
}

/* ---- Xvfb lifecycle ---- */

static pid_t g_xvfb_pid = -1;

static int
spawn_xvfb(const char *display)
{
	pid_t pid = fork();
	if (pid < 0) {
		(void)fprintf(stderr, "fork Xvfb: %s\n", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		/* Quiet the child; Xvfb is chatty on stderr. */
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			(void)dup2(devnull, STDOUT_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
			if (devnull > 2)
				(void)close(devnull);
		}
		execl(XVFB_PATH, "Xvfb", display, "-screen", "0",
			"1024x768x24", "-nolisten", "tcp", (char *)NULL);
		_exit(127);
	}
	g_xvfb_pid = pid;
	return 0;
}

/* Wait until XOpenDisplay succeeds (Xvfb is up) or a deadline passes. */
static Display *
open_display_retry(const char *display, int timeout_ms)
{
	long deadline = now_ms() + timeout_ms;
	for (;;) {
		Display *d = XOpenDisplay(display);
		if (d != NULL)
			return d;
		if (now_ms() >= deadline)
			return NULL;
		{
			struct timespec ts = { 0, 100 * 1000 * 1000 };
			(void)nanosleep(&ts, NULL);
		}
	}
}

static void
kill_xvfb(void)
{
	if (g_xvfb_pid > 0) {
		(void)kill(g_xvfb_pid, SIGTERM);
		(void)waitpid(g_xvfb_pid, NULL, 0);
		g_xvfb_pid = -1;
	}
}

/* ---- xclip helpers ---- */

/*
 * Run `xclip -i` to put `data` (len bytes) on the CLIPBOARD as UTF8_STRING.
 * xclip forks and the background process holds the selection until someone
 * takes it.  We feed the data on its stdin and wait for the foreground
 * process to exit (the daemon detaches).  Returns the daemon pid we should
 * reap at the end, or -1 on error.
 */
static pid_t
xclip_set(const uint8_t *data, size_t len)
{
	int in[2];
	pid_t pid;

	if (pipe(in) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		(void)close(in[0]);
		(void)close(in[1]);
		return -1;
	}
	if (pid == 0) {
		(void)dup2(in[0], STDIN_FILENO);
		(void)close(in[0]);
		(void)close(in[1]);
		{
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) {
				(void)dup2(devnull, STDERR_FILENO);
				if (devnull > 2)
					(void)close(devnull);
			}
		}
		execl("/usr/bin/xclip", "xclip", "-display", g_display,
			"-selection", "clipboard", "-t", "UTF8_STRING",
			"-i", (char *)NULL);
		_exit(127);
	}
	(void)close(in[0]);
	/* Write all the data; xclip reads stdin to EOF before forking the
	 * background selection holder. */
	{
		size_t off = 0;
		while (off < len) {
			ssize_t w = write(in[1], data + off, len - off);
			if (w <= 0) {
				if (w < 0 && errno == EINTR)
					continue;
				break;
			}
			off += (size_t)w;
		}
	}
	(void)close(in[1]);
	return pid;
}

/*
 * Run `xclip -t text/html -i` to put `data` (len bytes) on the CLIPBOARD
 * offering the text/html target.  xclip 0.13's TARGETS reply for such an
 * owner is exactly {TARGETS, text/html} (verified live), so clip_x11's
 * fmt_for_target maps it to the HTML bit only.  Same fork/feed/detach shape
 * as xclip_set; returns the daemon pid to reap, or -1 on error.
 */
static pid_t
xclip_set_html(const uint8_t *data, size_t len)
{
	int in[2];
	pid_t pid;

	if (pipe(in) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		(void)close(in[0]);
		(void)close(in[1]);
		return -1;
	}
	if (pid == 0) {
		(void)dup2(in[0], STDIN_FILENO);
		(void)close(in[0]);
		(void)close(in[1]);
		{
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) {
				(void)dup2(devnull, STDERR_FILENO);
				if (devnull > 2)
					(void)close(devnull);
			}
		}
		execl("/usr/bin/xclip", "xclip", "-display", g_display,
			"-selection", "clipboard", "-t", "text/html",
			"-i", (char *)NULL);
		_exit(127);
	}
	(void)close(in[0]);
	{
		size_t off = 0;
		while (off < len) {
			ssize_t w = write(in[1], data + off, len - off);
			if (w <= 0) {
				if (w < 0 && errno == EINTR)
					continue;
				break;
			}
			off += (size_t)w;
		}
	}
	(void)close(in[1]);
	return pid;
}

/*
 * Run `xclip -t image/bmp -i` to put `data` (len bytes) on the CLIPBOARD
 * offering the image/bmp target.  xclip 0.13's TARGETS reply for such an owner
 * is exactly {TARGETS, image/bmp} (verified live), so clip_x11's
 * fmt_for_target maps it to the IMAGE bit only.  Same fork/feed/detach shape
 * as xclip_set; returns the daemon pid to reap, or -1 on error.
 */
static pid_t
xclip_set_image(const uint8_t *data, size_t len)
{
	int in[2];
	pid_t pid;

	if (pipe(in) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		(void)close(in[0]);
		(void)close(in[1]);
		return -1;
	}
	if (pid == 0) {
		(void)dup2(in[0], STDIN_FILENO);
		(void)close(in[0]);
		(void)close(in[1]);
		{
			int devnull = open("/dev/null", O_WRONLY);
			if (devnull >= 0) {
				(void)dup2(devnull, STDERR_FILENO);
				if (devnull > 2)
					(void)close(devnull);
			}
		}
		execl("/usr/bin/xclip", "xclip", "-display", g_display,
			"-selection", "clipboard", "-t", "image/bmp",
			"-i", (char *)NULL);
		_exit(127);
	}
	(void)close(in[0]);
	{
		size_t off = 0;
		while (off < len) {
			ssize_t w = write(in[1], data + off, len - off);
			if (w <= 0) {
				if (w < 0 && errno == EINTR)
					continue;
				break;
			}
			off += (size_t)w;
		}
	}
	(void)close(in[1]);
	return pid;
}

/*
 * A minimal ICCCM INCR selection owner, run in a forked child with its own
 * X connection.  xclip does NOT switch to INCR even at 1 MiB on this server
 * (BIG-REQUESTS lets it ship the whole value in one XChangeProperty), so to
 * give the INCR reader (on_incr_property / the PropertyNotify path in
 * clip_x11.c) real coverage we drive the protocol ourselves:
 *
 *   1. Claim CLIPBOARD.
 *   2. On SelectionRequest for UTF8_STRING, set the requestor's property to
 *      type INCR (format 32, lower-bound size), select PropertyChangeMask on
 *      the requestor, and send SelectionNotify.  This is what makes
 *      clip_x11.c take its INCR branch.
 *   3. The requestor (clip) deletes the property to start; we then write the
 *      data one `chunk`-sized PropModeReplace at a time, each after the
 *      requestor deletes the previous one (PropertyNotify, state Delete).
 *   4. A final zero-length write terminates the transfer.
 *
 * `chunk` is deliberately small so several INCR rounds occur, exercising the
 * accumulate-and-realloc loop in on_incr_property.  The child exits after one
 * completed transfer.
 *
 * Synchronization: two pipes remove the start-up and teardown races.
 *   ready_fd: the child writes one byte only AFTER it owns CLIPBOARD, so the
 *     parent waits for it before driving clip's XConvertSelection (otherwise
 *     the conversion can race ahead of the server registering the owner, or
 *     race the prior owner - clip still owns CLIPBOARD from the preceding
 *     RDP->X case).
 *   done_fd: after serving the INCR transfer the child blocks reading this fd
 *     and only exits once the parent has the CLIP_OFFER in hand and writes (or
 *     closes) it.  Without this the child's exit could flip the owner to None
 *     before clip finished reading the data, dropping the offer.
 */
static pid_t
incr_owner(const uint8_t *data, size_t len, size_t chunk,
		const int ready_pipe[2], const int done_pipe[2])
{
	pid_t pid = fork();
	Display *d;
	Window w;
	Atom clip, utf8, targets, incr_atom;
	int ready_fd, done_fd;

	if (pid < 0)
		return -1;
	if (pid != 0)
		return pid;

	/* ---- child ---- */
	/* Keep the ends we use; close the parent's so the parent's later
	 * close of done_pipe[1] actually reaches us as EOF. */
	ready_fd = ready_pipe[1];
	done_fd  = done_pipe[0];
	(void)close(ready_pipe[0]);
	(void)close(done_pipe[1]);

	d = XOpenDisplay(g_display);
	if (d == NULL)
		_exit(2);
	w = XCreateSimpleWindow(d, DefaultRootWindow(d), 0, 0, 1, 1, 0, 0, 0);
	clip      = XInternAtom(d, "CLIPBOARD", False);
	utf8      = XInternAtom(d, "UTF8_STRING", False);
	targets   = XInternAtom(d, "TARGETS", False);
	incr_atom = XInternAtom(d, "INCR", False);

	XSetSelectionOwner(d, clip, w, CurrentTime);
	/* Round-trip so the server has registered us as owner before the
	 * parent's XConvertSelection (which the parent issues the moment it
	 * sees the XFixes owner-change) can race ahead of us. */
	XSync(d, False);
	if (XGetSelectionOwner(d, clip) != w)
		_exit(3);

	/* Tell the parent we own CLIPBOARD; only now may it drive the loop. */
	{
		char b = 1;
		while (write(ready_fd, &b, 1) < 0 && errno == EINTR)
			;
		(void)close(ready_fd);
	}

	for (;;) {
		XEvent e;
		XNextEvent(d, &e);
		if (e.type == SelectionClear)
			_exit(0);
		if (e.type != SelectionRequest)
			continue;
		{
			XSelectionRequestEvent *re = &e.xselectionrequest;
			XEvent note;
			Window req = re->requestor;
			Atom prop = re->property != None ? re->property : re->target;

			memset(&note, 0, sizeof note);
			note.xselection.type      = SelectionNotify;
			note.xselection.requestor = req;
			note.xselection.selection = re->selection;
			note.xselection.target    = re->target;
			note.xselection.time      = re->time;
			note.xselection.property  = prop;

			if (re->target == targets) {
				Atom tl[2];
				tl[0] = targets;
				tl[1] = utf8;
				XChangeProperty(d, req, prop, XA_ATOM, 32,
					PropModeReplace,
					(unsigned char *)tl, 2);
				XSendEvent(d, req, False, NoEventMask, &note);
				XFlush(d);
				continue;
			}
			if (re->target != utf8) {
				note.xselection.property = None;
				XSendEvent(d, req, False, NoEventMask, &note);
				XFlush(d);
				continue;
			}

			/* INCR start: watch the requestor's property deletes,
			 * advertise INCR, then feed chunks. */
			XSelectInput(d, req, PropertyChangeMask);
			{
				unsigned long total = (unsigned long)len;
				XChangeProperty(d, req, prop, incr_atom, 32,
					PropModeReplace,
					(unsigned char *)&total, 1);
			}
			XSendEvent(d, req, False, NoEventMask, &note);
			XFlush(d);

			/* Now stream chunks, one per requestor-delete. */
			{
				size_t off = 0;
				int done = 0;
				while (!done) {
					XEvent pe;
					XNextEvent(d, &pe);
					if (pe.type != PropertyNotify)
						continue;
					if (pe.xproperty.window != req
					    || pe.xproperty.atom != prop
					    || pe.xproperty.state
						!= PropertyDelete)
						continue;
					if (off >= len) {
						/* terminator: zero-length */
						unsigned char term = 0;
						XChangeProperty(d, req, prop,
							utf8, 8,
							PropModeReplace,
							&term, 0);
						XFlush(d);
						done = 1;
					} else {
						size_t n = len - off;
						if (n > chunk)
							n = chunk;
						XChangeProperty(d, req, prop,
							utf8, 8,
							PropModeReplace,
							data + off, (int)n);
						XFlush(d);
						off += n;
					}
				}
			}
			/*
			 * The transfer is complete, but we must NOT exit yet:
			 * exiting closes the X connection, which destroys our
			 * window and flips the CLIPBOARD owner to None.  If that
			 * owner-None reaches clip before it has finished reading
			 * the final INCR chunk and offered the data, the test
			 * races.  Stay owner until the parent has the CLIP_OFFER
			 * in hand and writes the "done" byte (or closes the fd).
			 */
			{
				char b;
				XSync(d, False);   /* push everything to server */
				while (read(done_fd, &b, 1) < 0 && errno == EINTR)
					;
			}
			_exit(0);
		}
	}
}

/* ---- predicates for drive_until ---- */

/* Predicate: clip has emitted at least one backend message on sv[0]. */
static int
pred_sv0_readable(void *arg)
{
	struct pollfd p;
	(void)arg;
	p.fd = g_sv0;
	p.events = POLLIN;
	p.revents = 0;
	return poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
}

/* ---- the test cases ---- */

/* Send a CLIP_REQUEST(fmt) to the session and collect the CLIP_DATA reply,
 * returning the payload (after the 8-byte data header) via out/out_len.  The
 * reply's header format must equal the requested fmt.  Returns 0 on success. */
static int
request_and_read_data_fmt(uint32_t fmt, uint8_t **out, size_t *out_len,
		int timeout_ms)
{
	struct rdp_be_clip_request req;
	static uint8_t buf[BIG_LEN + 1024];
	uint32_t type = 0;
	ssize_t n;
	struct rdp_be_clip_data_hdr h;

	req.format = fmt;
	*out = NULL;
	*out_len = 0;

	if (rdp_be_send(g_sv0, RDP_BE_CLIP_REQUEST, &req, sizeof req) != 0) {
		FAILF("send CLIP_REQUEST: %s", strerror(errno));
		return -1;
	}
	n = expect_be_msg(&type, buf, sizeof buf, timeout_ms);
	if (n < 0) {
		FAILF("no CLIP_DATA within %d ms", timeout_ms);
		return -1;
	}
	if (type != RDP_BE_CLIP_DATA) {
		FAILF("expected CLIP_DATA, got type %u", type);
		return -1;
	}
	if ((size_t)n < sizeof h) {
		FAILF("CLIP_DATA too short (%zd bytes)", n);
		return -1;
	}
	memcpy(&h, buf, sizeof h);
	if (h.status != 0) {
		FAILF("CLIP_DATA status %u (expected 0/ok)", h.status);
		return -1;
	}
	if (h.format != fmt) {
		FAILF("CLIP_DATA format 0x%x (expected 0x%x)", h.format, fmt);
		return -1;
	}
	*out_len = (size_t)n - sizeof h;
	*out = malloc(*out_len + 1);
	if (*out == NULL) {
		FAILF("oom");
		return -1;
	}
	memcpy(*out, buf + sizeof h, *out_len);
	(*out)[*out_len] = '\0';
	return 0;
}

/* Verify a buffer is `len` bytes all equal to fill. */
static int
all_fill(const uint8_t *p, size_t len, uint8_t fill)
{
	size_t i;
	for (i = 0; i < len; i++)
		if (p[i] != fill)
			return 0;
	return 1;
}

/* X -> RDP.  Put `data` on CLIPBOARD via xclip -i, expect clip to emit a
 * CLIP_OFFER, then request the data and verify the round-trip bytes. */
static void
test_x_to_rdp(const char *name, const uint8_t *data, size_t len)
{
	pid_t holder;
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	uint8_t *got = NULL;
	size_t got_len = 0;

	(void)printf("%s: X -> RDP, %zu bytes\n", name, len);

	holder = xclip_set(data, len);
	if (holder < 0) {
		FAILF("xclip -i spawn failed");
		return;
	}

	/* xclip taking the selection fires XFixesSelectionNotify; clip then
	 * fetches and emits CLIP_OFFER.  Pump until the offer shows on sv0. */
	if (!drive_until(pred_sv0_readable, NULL, 5000)) {
		FAILF("no CLIP_OFFER after xclip -i");
		goto reap;
	}
	n = rdp_be_recv(g_sv0, &type, small, sizeof small);
	if (n < 0) {
		FAILF("recv CLIP_OFFER: %s", strerror(errno));
		goto reap;
	}
	if (type != RDP_BE_CLIP_OFFER) {
		FAILF("expected CLIP_OFFER, got type %u", type);
		goto reap;
	}
	(void)printf("  got CLIP_OFFER\n");

	/* Now ask for the data. */
	if (request_and_read_data_fmt(RDP_BE_CLIP_FMT_TEXT, &got, &got_len,
		8000) != 0)
		goto reap;

	if (got_len != len) {
		FAILF("length mismatch: got %zu, expected %zu", got_len, len);
		free(got);
		goto reap;
	}
	if (len > 0 && data[0] == BIG_FILL && len == BIG_LEN) {
		if (!all_fill(got, got_len, BIG_FILL))
			FAILF("large data corrupted (not all 0x%02x)", BIG_FILL);
		else
			(void)printf("  CLIP_DATA len %zu, all 0x%02x ok\n",
				got_len, BIG_FILL);
	} else {
		if (memcmp(got, data, len) != 0)
			FAILF("data mismatch");
		else
			(void)printf("  CLIP_DATA len %zu matches ('%.*s')\n",
				got_len, (int)(len > 40 ? 40 : len),
				(const char *)got);
	}
	free(got);

reap:
	/* Release the selection holder so the next test starts clean. */
	if (holder > 0) {
		(void)kill(holder, SIGTERM);
		(void)waitpid(holder, NULL, 0);
		/* Let clip see the owner-cleared event. */
		(void)drive_until(NULL, NULL, 200);
	}
}

/* X -> RDP via a forced INCR transfer.  Uses our own INCR selection owner
 * (xclip will not use INCR on this server even at 1 MiB) so the INCR reader
 * in clip_x11.c is exercised across several chunks.  `data` uses a position
 * dependent byte pattern so reassembly order is verified, not just length. */
static void
test_x_to_rdp_incr(const char *name, const uint8_t *data, size_t len,
		size_t chunk)
{
	pid_t owner;
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	uint8_t *got = NULL;
	size_t got_len = 0;
	int rp[2];      /* child -> parent: "I own CLIPBOARD" */
	int dp[2];      /* parent -> child: "you may exit now" */

	(void)printf("%s: X -> RDP via INCR, %zu bytes in %zu-byte chunks\n",
		name, len, chunk);

	if (pipe(rp) != 0) {
		FAILF("pipe: %s", strerror(errno));
		return;
	}
	if (pipe(dp) != 0) {
		FAILF("pipe: %s", strerror(errno));
		(void)close(rp[0]);
		(void)close(rp[1]);
		return;
	}
	owner = incr_owner(data, len, chunk, rp, dp);
	if (owner < 0) {
		FAILF("incr_owner spawn failed");
		(void)close(rp[0]);
		(void)close(rp[1]);
		(void)close(dp[0]);
		(void)close(dp[1]);
		return;
	}
	(void)close(rp[1]);   /* parent keeps the ready read end */
	(void)close(dp[0]);   /* parent keeps the done write end */

	/* Wait until the child confirms it owns CLIPBOARD, pumping the loop so
	 * clip can process the resulting XFixes owner-change cleanly.  This
	 * removes the start-up race between the child's XSetSelectionOwner and
	 * the parent driving clip's XConvertSelection. */
	{
		long deadline = now_ms() + 5000;
		int ready = 0;
		while (now_ms() < deadline) {
			struct pollfd p;
			char b;
			pump_once();
			p.fd = rp[0];
			p.events = POLLIN;
			p.revents = 0;
			if (poll(&p, 1, 50) > 0 && (p.revents & POLLIN)) {
				if (read(rp[0], &b, 1) == 1)
					ready = 1;
				break;
			}
		}
		(void)close(rp[0]);
		if (!ready) {
			FAILF("INCR owner never signalled ready");
			goto reap;
		}
	}

	if (!drive_until(pred_sv0_readable, NULL, 6000)) {
		FAILF("no CLIP_OFFER after INCR owner claimed CLIPBOARD");
		goto reap;
	}
	n = rdp_be_recv(g_sv0, &type, small, sizeof small);
	if (n < 0) {
		FAILF("recv CLIP_OFFER: %s", strerror(errno));
		goto reap;
	}
	if (type != RDP_BE_CLIP_OFFER) {
		FAILF("expected CLIP_OFFER, got type %u", type);
		goto reap;
	}
	(void)printf("  got CLIP_OFFER (INCR transfer assembled)\n");

	/* clip has the data cached now; let the owner child exit.  The byte is
	 * best-effort: even if it is lost, the reap path closes dp[1], which
	 * the child sees as EOF and exits on. */
	{
		char b = 1;
		ssize_t wr = write(dp[1], &b, 1);
		(void)wr;
	}

	if (request_and_read_data_fmt(RDP_BE_CLIP_FMT_TEXT, &got, &got_len,
		8000) != 0)
		goto reap;

	if (got_len != len) {
		FAILF("INCR length mismatch: got %zu, expected %zu",
			got_len, len);
		free(got);
		goto reap;
	}
	if (memcmp(got, data, len) != 0) {
		FAILF("INCR data mismatch (reassembly order wrong?)");
	} else {
		(void)printf("  CLIP_DATA len %zu, byte pattern matches ok\n",
			got_len);
	}
	free(got);

reap:
	/* Closing the done pipe unblocks the child wherever it waits (EOF on
	 * the done read), so it exits cleanly on every path, including the
	 * error paths that never wrote the "done" byte. */
	(void)close(dp[1]);
	if (owner > 0) {
		int st = 0;
		pid_t wr = waitpid(owner, &st, WNOHANG);
		if (wr == 0) {
			/* Not yet exited (e.g. it failed before serving and is
			 * blocked in XNextEvent): nudge it. */
			(void)kill(owner, SIGTERM);
			(void)waitpid(owner, &st, 0);
		}
	}
	(void)drive_until(NULL, NULL, 200);
}

/* RDP -> X.  Offer from the RDP side (clip claims CLIPBOARD), then run
 * xclip -o; clip defers, emits CLIP_REQUEST, we answer with CLIP_DATA, and
 * xclip's stdout must equal the data. */
static void
test_rdp_to_x(const char *name, const uint8_t *data, size_t len)
{
	struct rdp_be_clip_offer offer = { RDP_BE_CLIP_FMT_TEXT };
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	uint8_t *got = NULL;
	size_t got_len = 0;
	int gr;

	(void)printf("%s: RDP -> X, %zu bytes\n", name, len);

	/* 1. RDP client announces it has clipboard content. */
	if (rdp_be_send(g_sv0, RDP_BE_CLIP_OFFER, &offer, sizeof offer) != 0) {
		FAILF("send CLIP_OFFER: %s", strerror(errno));
		return;
	}
	/* Pump so clip processes the offer and claims CLIPBOARD. */
	(void)drive_until(NULL, NULL, 300);

	/*
	 * 2. Start xclip -o.  It sends a SelectionRequest to clip, which
	 *    defers and emits CLIP_REQUEST.  We must service the loop while
	 *    xclip runs (xclip_get does that), but xclip_get also needs us to
	 *    answer the CLIP_REQUEST with CLIP_DATA mid-flight.  So: fork
	 *    xclip via xclip_get's machinery is not enough on its own; we wire
	 *    the CLIP_REQUEST->CLIP_DATA exchange into the same pump by
	 *    arranging that pump_once observes the request on sv0.  Simplest:
	 *    do it in two phases - first detect the CLIP_REQUEST, answer it,
	 *    then collect xclip output.  But xclip blocks until answered, so
	 *    we interleave: launch xclip, then in a loop pump + check sv0 for
	 *    CLIP_REQUEST + answer + read xclip stdout.
	 *
	 * We implement that interleaving inline here rather than in xclip_get
	 * so the answer happens at the right time.
	 */
	{
		int op[2];
		pid_t pid;
		uint8_t *buf = NULL;
		size_t cap = 0, used = 0;
		long deadline = now_ms() + 8000;
		int eof = 0, answered = 0, status;

		if (pipe(op) != 0) {
			FAILF("pipe: %s", strerror(errno));
			return;
		}
		pid = fork();
		if (pid < 0) {
			FAILF("fork xclip -o: %s", strerror(errno));
			(void)close(op[0]);
			(void)close(op[1]);
			return;
		}
		if (pid == 0) {
			(void)dup2(op[1], STDOUT_FILENO);
			(void)close(op[0]);
			(void)close(op[1]);
			{
				int dn = open("/dev/null", O_WRONLY);
				if (dn >= 0) {
					(void)dup2(dn, STDERR_FILENO);
					if (dn > 2)
						(void)close(dn);
				}
			}
			execl("/usr/bin/xclip", "xclip", "-display",
				g_display, "-selection", "clipboard",
				"-t", "UTF8_STRING", "-o", (char *)NULL);
			_exit(127);
		}
		(void)close(op[1]);
		(void)fcntl(op[0], F_SETFL, O_NONBLOCK);

		while (!eof && now_ms() < deadline) {
			struct pollfd p[3];

			pump_once();

			/* Has clip deferred and emitted CLIP_REQUEST? */
			if (!answered && pred_sv0_readable(NULL)) {
				n = rdp_be_recv(g_sv0, &type, small, sizeof small);
				if (n < 0) {
					FAILF("recv CLIP_REQUEST: %s",
						strerror(errno));
					eof = 1;
					break;
				}
				if (type != RDP_BE_CLIP_REQUEST) {
					FAILF("expected CLIP_REQUEST, got %u",
						type);
					eof = 1;
					break;
				}
				(void)printf("  got CLIP_REQUEST; "
					"answering with CLIP_DATA\n");
				/* Build CLIP_DATA: header + bytes. */
				{
					size_t blen =
						sizeof(struct rdp_be_clip_data_hdr)
						+ len;
					uint8_t *db = malloc(blen);
					struct rdp_be_clip_data_hdr h;
					h.format = RDP_BE_CLIP_FMT_TEXT;
					h.status = 0;
					if (db == NULL) {
						FAILF("oom");
						eof = 1;
						break;
					}
					memcpy(db, &h, sizeof h);
					memcpy(db + sizeof h, data, len);
					if (rdp_be_send(g_sv0,
						RDP_BE_CLIP_DATA, db, blen)
						!= 0)
						FAILF("send CLIP_DATA: %s",
							strerror(errno));
					free(db);
				}
				answered = 1;
			}

			XFlush(g_dpy);
			p[0].fd = g_xfd;
			p[0].events = POLLIN;
			p[0].revents = 0;
			p[1].fd = g_sv1;
			p[1].events = POLLIN;
			p[1].revents = 0;
			p[2].fd = op[0];
			p[2].events = POLLIN;
			p[2].revents = 0;
			(void)poll(p, 3, 50);

			if (p[2].revents & (POLLIN | POLLHUP)) {
				for (;;) {
					ssize_t r;
					if (used + 65536 > cap) {
						size_t nc = cap == 0
							? 65536 : cap * 2;
						uint8_t *nb =
							realloc(buf, nc);
						if (nb == NULL) {
							free(buf);
							buf = NULL;
							eof = 1;
							break;
						}
						buf = nb;
						cap = nc;
					}
					r = read(op[0], buf + used,
						cap - used);
					if (r > 0) {
						used += (size_t)r;
						continue;
					}
					if (r == 0) {
						eof = 1;
						break;
					}
					if (errno == EAGAIN
						|| errno == EWOULDBLOCK)
						break;
					if (errno == EINTR)
						continue;
					eof = 1;
					break;
				}
			}
		}
		(void)close(op[0]);
		(void)waitpid(pid, &status, 0);

		got = buf;
		got_len = used;
		gr = (eof && (buf != NULL || used == 0)) ? 0 : -1;
		if (!answered)
			FAILF("clip never emitted CLIP_REQUEST");
	}

	if (gr != 0) {
		FAILF("xclip -o produced no output (timeout?)");
		free(got);
		return;
	}
	if (got_len != len) {
		FAILF("xclip -o length mismatch: got %zu, expected %zu",
			got_len, len);
		free(got);
		return;
	}
	if (len == BIG_LEN && data[0] == BIG_FILL) {
		if (!all_fill(got, got_len, BIG_FILL))
			FAILF("xclip -o large data corrupted");
		else
			(void)printf("  xclip -o len %zu, all 0x%02x ok\n",
				got_len, BIG_FILL);
	} else {
		if (memcmp(got, data, len) != 0)
			FAILF("xclip -o data mismatch");
		else
			(void)printf("  xclip -o len %zu matches ('%.*s')\n",
				got_len, (int)(len > 40 ? 40 : len),
				(const char *)got);
	}
	free(got);

	/* Drop our CLIPBOARD ownership before the next test: a fresh xclip -i
	 * will reclaim it, but make sure clip's rdp_text is cleared. */
	(void)drive_until(NULL, NULL, 100);
}

/* F.  X -> RDP, HTML.  An xclip -t text/html owner offers the text/html
 * target carrying `html` (len bytes).  clip must probe TARGETS, emit a
 * CLIP_OFFER whose bitmap has the HTML bit set (and, since this owner lists
 * only TARGETS + text/html, ONLY the HTML bit), then on CLIP_REQUEST{HTML}
 * convert the text/html target and return CLIP_DATA{HTML} equal to the raw
 * fragment.  Mirrors test_x_to_rdp but on the HTML format. */
static void
test_x_to_rdp_html(const char *name, const uint8_t *html, size_t len)
{
	pid_t holder;
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	struct rdp_be_clip_offer off;
	uint8_t *got = NULL;
	size_t got_len = 0;

	(void)printf("%s: X -> RDP, HTML, %zu bytes\n", name, len);

	holder = xclip_set_html(html, len);
	if (holder < 0) {
		FAILF("xclip -t text/html -i spawn failed");
		return;
	}

	if (!drive_until(pred_sv0_readable, NULL, 5000)) {
		FAILF("no CLIP_OFFER after xclip -t text/html -i");
		goto reap;
	}
	n = rdp_be_recv(g_sv0, &type, small, sizeof small);
	if (n < 0) {
		FAILF("recv CLIP_OFFER: %s", strerror(errno));
		goto reap;
	}
	if (type != RDP_BE_CLIP_OFFER) {
		FAILF("expected CLIP_OFFER, got type %u", type);
		goto reap;
	}
	if ((size_t)n < sizeof off) {
		FAILF("CLIP_OFFER too short (%zd bytes)", n);
		goto reap;
	}
	memcpy(&off, small, sizeof off);
	if (!(off.formats & RDP_BE_CLIP_FMT_HTML)) {
		FAILF("CLIP_OFFER bitmap 0x%x missing HTML bit 0x%x",
			off.formats, RDP_BE_CLIP_FMT_HTML);
		goto reap;
	}
	(void)printf("  got CLIP_OFFER, formats 0x%x (HTML bit set)\n",
		off.formats);

	/* Ask for the HTML format specifically. */
	if (request_and_read_data_fmt(RDP_BE_CLIP_FMT_HTML, &got, &got_len,
		8000) != 0)
		goto reap;

	if (got_len != len) {
		FAILF("HTML length mismatch: got %zu, expected %zu",
			got_len, len);
		free(got);
		goto reap;
	}
	if (memcmp(got, html, len) != 0) {
		FAILF("HTML data mismatch: got '%.*s' expected '%.*s'",
			(int)got_len, (const char *)got,
			(int)len, (const char *)html);
		free(got);
		goto reap;
	}
	(void)printf("  CLIP_DATA{HTML} len %zu matches ('%.*s')\n",
		got_len, (int)got_len, (const char *)got);
	free(got);

reap:
	if (holder > 0) {
		(void)kill(holder, SIGTERM);
		(void)waitpid(holder, NULL, 0);
		(void)drive_until(NULL, NULL, 200);
	}
}

/* G.  RDP -> X, HTML.  The RDP side offers TEXT|HTML; clip claims CLIPBOARD
 * and must advertise text/html in its TARGETS reply.  xclip -t text/html -o
 * requests the text/html target, clip defers and emits CLIP_REQUEST{HTML},
 * the harness answers CLIP_DATA{HTML, status=0, html}, and xclip's stdout
 * must equal the fragment.  Mirrors test_rdp_to_x but on the HTML format and
 * with a TEXT|HTML offer. */
static void
test_rdp_to_x_html(const char *name, const uint8_t *html, size_t len)
{
	struct rdp_be_clip_offer offer;
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	uint8_t *got = NULL;
	size_t got_len = 0;
	int gr;

	(void)printf("%s: RDP -> X, HTML, %zu bytes\n", name, len);

	/* 1. RDP client announces TEXT and HTML content. */
	offer.formats = RDP_BE_CLIP_FMT_TEXT | RDP_BE_CLIP_FMT_HTML;
	if (rdp_be_send(g_sv0, RDP_BE_CLIP_OFFER, &offer, sizeof offer) != 0) {
		FAILF("send CLIP_OFFER: %s", strerror(errno));
		return;
	}
	(void)drive_until(NULL, NULL, 300);

	/*
	 * 2. Start xclip -t text/html -o.  It first converts TARGETS (clip
	 *    answers directly, listing text/html since HTML was offered) then
	 *    converts text/html, which clip defers via CLIP_REQUEST{HTML}.  We
	 *    interleave: pump the loop, answer the request with CLIP_DATA{HTML},
	 *    and collect xclip's stdout - the same structure as test_rdp_to_x.
	 */
	{
		int op[2];
		pid_t pid;
		uint8_t *buf = NULL;
		size_t cap = 0, used = 0;
		long deadline = now_ms() + 8000;
		int eof = 0, answered = 0, status;

		if (pipe(op) != 0) {
			FAILF("pipe: %s", strerror(errno));
			return;
		}
		pid = fork();
		if (pid < 0) {
			FAILF("fork xclip -o: %s", strerror(errno));
			(void)close(op[0]);
			(void)close(op[1]);
			return;
		}
		if (pid == 0) {
			(void)dup2(op[1], STDOUT_FILENO);
			(void)close(op[0]);
			(void)close(op[1]);
			{
				int dn = open("/dev/null", O_WRONLY);
				if (dn >= 0) {
					(void)dup2(dn, STDERR_FILENO);
					if (dn > 2)
						(void)close(dn);
				}
			}
			execl("/usr/bin/xclip", "xclip", "-display",
				g_display, "-selection", "clipboard",
				"-t", "text/html", "-o", (char *)NULL);
			_exit(127);
		}
		(void)close(op[1]);
		(void)fcntl(op[0], F_SETFL, O_NONBLOCK);

		while (!eof && now_ms() < deadline) {
			struct pollfd p[3];

			pump_once();

			if (!answered && pred_sv0_readable(NULL)) {
				n = rdp_be_recv(g_sv0, &type, small,
					sizeof small);
				if (n < 0) {
					FAILF("recv CLIP_REQUEST: %s",
						strerror(errno));
					eof = 1;
					break;
				}
				if (type != RDP_BE_CLIP_REQUEST) {
					FAILF("expected CLIP_REQUEST, got %u",
						type);
					eof = 1;
					break;
				}
				if ((size_t)n
					< sizeof(struct rdp_be_clip_request)) {
					FAILF("CLIP_REQUEST too short");
					eof = 1;
					break;
				}
				{
					struct rdp_be_clip_request rq;
					memcpy(&rq, small, sizeof rq);
					if (rq.format != RDP_BE_CLIP_FMT_HTML) {
						FAILF("CLIP_REQUEST format "
							"0x%x (expected HTML "
							"0x%x)", rq.format,
							RDP_BE_CLIP_FMT_HTML);
						eof = 1;
						break;
					}
				}
				(void)printf("  got CLIP_REQUEST{HTML}; "
					"answering with CLIP_DATA{HTML}\n");
				{
					size_t blen =
						sizeof(struct rdp_be_clip_data_hdr)
						+ len;
					uint8_t *db = malloc(blen);
					struct rdp_be_clip_data_hdr h;
					h.format = RDP_BE_CLIP_FMT_HTML;
					h.status = 0;
					if (db == NULL) {
						FAILF("oom");
						eof = 1;
						break;
					}
					memcpy(db, &h, sizeof h);
					memcpy(db + sizeof h, html, len);
					if (rdp_be_send(g_sv0,
						RDP_BE_CLIP_DATA, db, blen)
						!= 0)
						FAILF("send CLIP_DATA: %s",
							strerror(errno));
					free(db);
				}
				answered = 1;
			}

			XFlush(g_dpy);
			p[0].fd = g_xfd;
			p[0].events = POLLIN;
			p[0].revents = 0;
			p[1].fd = g_sv1;
			p[1].events = POLLIN;
			p[1].revents = 0;
			p[2].fd = op[0];
			p[2].events = POLLIN;
			p[2].revents = 0;
			(void)poll(p, 3, 50);

			if (p[2].revents & (POLLIN | POLLHUP)) {
				for (;;) {
					ssize_t r;
					if (used + 65536 > cap) {
						size_t nc = cap == 0
							? 65536 : cap * 2;
						uint8_t *nb =
							realloc(buf, nc);
						if (nb == NULL) {
							free(buf);
							buf = NULL;
							eof = 1;
							break;
						}
						buf = nb;
						cap = nc;
					}
					r = read(op[0], buf + used,
						cap - used);
					if (r > 0) {
						used += (size_t)r;
						continue;
					}
					if (r == 0) {
						eof = 1;
						break;
					}
					if (errno == EAGAIN
						|| errno == EWOULDBLOCK)
						break;
					if (errno == EINTR)
						continue;
					eof = 1;
					break;
				}
			}
		}
		(void)close(op[0]);
		(void)waitpid(pid, &status, 0);

		got = buf;
		got_len = used;
		gr = (eof && (buf != NULL || used == 0)) ? 0 : -1;
		if (!answered)
			FAILF("clip never emitted CLIP_REQUEST{HTML}");
	}

	if (gr != 0) {
		FAILF("xclip -t text/html -o produced no output (timeout?)");
		free(got);
		return;
	}
	if (got_len != len) {
		FAILF("xclip -o HTML length mismatch: got %zu, expected %zu",
			got_len, len);
		free(got);
		return;
	}
	if (memcmp(got, html, len) != 0)
		FAILF("xclip -o HTML data mismatch: got '%.*s' expected '%.*s'",
			(int)got_len, (const char *)got,
			(int)len, (const char *)html);
	else
		(void)printf("  xclip -t text/html -o len %zu matches "
			"('%.*s')\n", got_len, (int)got_len,
			(const char *)got);
	free(got);

	(void)drive_until(NULL, NULL, 100);
}

/* H.  X -> RDP, image.  An xclip -t image/bmp owner offers the image/bmp
 * target carrying `bmp` (len bytes).  clip must probe TARGETS, emit a
 * CLIP_OFFER whose bitmap has the IMAGE bit set (and, since this owner lists
 * only TARGETS + image/bmp, ONLY the IMAGE bit), then on CLIP_REQUEST{IMAGE}
 * convert the image/bmp target and return CLIP_DATA{IMAGE} equal byte-for-byte
 * to the BMP stream.  Mirrors test_x_to_rdp_html on the IMAGE format. */
static void
test_x_to_rdp_image(const char *name, const uint8_t *bmp, size_t len)
{
	pid_t holder;
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	struct rdp_be_clip_offer off;
	uint8_t *got = NULL;
	size_t got_len = 0;

	(void)printf("%s: X -> RDP, image, %zu bytes\n", name, len);

	holder = xclip_set_image(bmp, len);
	if (holder < 0) {
		FAILF("xclip -t image/bmp -i spawn failed");
		return;
	}

	if (!drive_until(pred_sv0_readable, NULL, 5000)) {
		FAILF("no CLIP_OFFER after xclip -t image/bmp -i");
		goto reap;
	}
	n = rdp_be_recv(g_sv0, &type, small, sizeof small);
	if (n < 0) {
		FAILF("recv CLIP_OFFER: %s", strerror(errno));
		goto reap;
	}
	if (type != RDP_BE_CLIP_OFFER) {
		FAILF("expected CLIP_OFFER, got type %u", type);
		goto reap;
	}
	if ((size_t)n < sizeof off) {
		FAILF("CLIP_OFFER too short (%zd bytes)", n);
		goto reap;
	}
	memcpy(&off, small, sizeof off);
	if (!(off.formats & RDP_BE_CLIP_FMT_IMAGE)) {
		FAILF("CLIP_OFFER bitmap 0x%x missing IMAGE bit 0x%x",
			off.formats, RDP_BE_CLIP_FMT_IMAGE);
		goto reap;
	}
	(void)printf("  got CLIP_OFFER, formats 0x%x (IMAGE bit set)\n",
		off.formats);

	/* Ask for the IMAGE format specifically. */
	if (request_and_read_data_fmt(RDP_BE_CLIP_FMT_IMAGE, &got, &got_len,
		8000) != 0)
		goto reap;

	if (got_len != len) {
		FAILF("image length mismatch: got %zu, expected %zu",
			got_len, len);
		free(got);
		goto reap;
	}
	if (memcmp(got, bmp, len) != 0) {
		FAILF("image data mismatch (BMP bytes differ)");
		free(got);
		goto reap;
	}
	(void)printf("  CLIP_DATA{IMAGE} len %zu matches (BMP byte-for-byte)\n",
		got_len);
	free(got);

reap:
	if (holder > 0) {
		(void)kill(holder, SIGTERM);
		(void)waitpid(holder, NULL, 0);
		(void)drive_until(NULL, NULL, 200);
	}
}

/* I.  RDP -> X, image.  The RDP side offers TEXT|IMAGE; clip claims CLIPBOARD
 * and must advertise image/bmp in its TARGETS reply.  xclip -t image/bmp -o
 * requests the image/bmp target, clip defers and emits CLIP_REQUEST{IMAGE},
 * the harness answers CLIP_DATA{IMAGE, status=0, bmp}, and xclip's stdout must
 * equal the BMP stream byte-for-byte.  Mirrors test_rdp_to_x_html on the IMAGE
 * format with a TEXT|IMAGE offer. */
static void
test_rdp_to_x_image(const char *name, const uint8_t *bmp, size_t len)
{
	struct rdp_be_clip_offer offer;
	uint32_t type = 0;
	uint8_t small[256];
	ssize_t n;
	uint8_t *got = NULL;
	size_t got_len = 0;
	int gr;

	(void)printf("%s: RDP -> X, image, %zu bytes\n", name, len);

	/* 1. RDP client announces TEXT and IMAGE content. */
	offer.formats = RDP_BE_CLIP_FMT_TEXT | RDP_BE_CLIP_FMT_IMAGE;
	if (rdp_be_send(g_sv0, RDP_BE_CLIP_OFFER, &offer, sizeof offer) != 0) {
		FAILF("send CLIP_OFFER: %s", strerror(errno));
		return;
	}
	(void)drive_until(NULL, NULL, 300);

	/*
	 * 2. Start xclip -t image/bmp -o.  It first converts TARGETS (clip
	 *    answers directly, listing image/bmp since IMAGE was offered) then
	 *    converts image/bmp, which clip defers via CLIP_REQUEST{IMAGE}.  We
	 *    interleave: pump the loop, answer the request with CLIP_DATA{IMAGE},
	 *    and collect xclip's stdout - the same structure as test_rdp_to_x_html.
	 */
	{
		int op[2];
		pid_t pid;
		uint8_t *buf = NULL;
		size_t cap = 0, used = 0;
		long deadline = now_ms() + 8000;
		int eof = 0, answered = 0, status;

		if (pipe(op) != 0) {
			FAILF("pipe: %s", strerror(errno));
			return;
		}
		pid = fork();
		if (pid < 0) {
			FAILF("fork xclip -o: %s", strerror(errno));
			(void)close(op[0]);
			(void)close(op[1]);
			return;
		}
		if (pid == 0) {
			(void)dup2(op[1], STDOUT_FILENO);
			(void)close(op[0]);
			(void)close(op[1]);
			{
				int dn = open("/dev/null", O_WRONLY);
				if (dn >= 0) {
					(void)dup2(dn, STDERR_FILENO);
					if (dn > 2)
						(void)close(dn);
				}
			}
			execl("/usr/bin/xclip", "xclip", "-display",
				g_display, "-selection", "clipboard",
				"-t", "image/bmp", "-o", (char *)NULL);
			_exit(127);
		}
		(void)close(op[1]);
		(void)fcntl(op[0], F_SETFL, O_NONBLOCK);

		while (!eof && now_ms() < deadline) {
			struct pollfd p[3];

			pump_once();

			if (!answered && pred_sv0_readable(NULL)) {
				n = rdp_be_recv(g_sv0, &type, small,
					sizeof small);
				if (n < 0) {
					FAILF("recv CLIP_REQUEST: %s",
						strerror(errno));
					eof = 1;
					break;
				}
				if (type != RDP_BE_CLIP_REQUEST) {
					FAILF("expected CLIP_REQUEST, got %u",
						type);
					eof = 1;
					break;
				}
				if ((size_t)n
					< sizeof(struct rdp_be_clip_request)) {
					FAILF("CLIP_REQUEST too short");
					eof = 1;
					break;
				}
				{
					struct rdp_be_clip_request rq;
					memcpy(&rq, small, sizeof rq);
					if (rq.format != RDP_BE_CLIP_FMT_IMAGE) {
						FAILF("CLIP_REQUEST format "
							"0x%x (expected IMAGE "
							"0x%x)", rq.format,
							RDP_BE_CLIP_FMT_IMAGE);
						eof = 1;
						break;
					}
				}
				(void)printf("  got CLIP_REQUEST{IMAGE}; "
					"answering with CLIP_DATA{IMAGE}\n");
				{
					size_t blen =
						sizeof(struct rdp_be_clip_data_hdr)
						+ len;
					uint8_t *db = malloc(blen);
					struct rdp_be_clip_data_hdr h;
					h.format = RDP_BE_CLIP_FMT_IMAGE;
					h.status = 0;
					if (db == NULL) {
						FAILF("oom");
						eof = 1;
						break;
					}
					memcpy(db, &h, sizeof h);
					memcpy(db + sizeof h, bmp, len);
					if (rdp_be_send(g_sv0,
						RDP_BE_CLIP_DATA, db, blen)
						!= 0)
						FAILF("send CLIP_DATA: %s",
							strerror(errno));
					free(db);
				}
				answered = 1;
			}

			XFlush(g_dpy);
			p[0].fd = g_xfd;
			p[0].events = POLLIN;
			p[0].revents = 0;
			p[1].fd = g_sv1;
			p[1].events = POLLIN;
			p[1].revents = 0;
			p[2].fd = op[0];
			p[2].events = POLLIN;
			p[2].revents = 0;
			(void)poll(p, 3, 50);

			if (p[2].revents & (POLLIN | POLLHUP)) {
				for (;;) {
					ssize_t r;
					if (used + 65536 > cap) {
						size_t nc = cap == 0
							? 65536 : cap * 2;
						uint8_t *nb =
							realloc(buf, nc);
						if (nb == NULL) {
							free(buf);
							buf = NULL;
							eof = 1;
							break;
						}
						buf = nb;
						cap = nc;
					}
					r = read(op[0], buf + used,
						cap - used);
					if (r > 0) {
						used += (size_t)r;
						continue;
					}
					if (r == 0) {
						eof = 1;
						break;
					}
					if (errno == EAGAIN
						|| errno == EWOULDBLOCK)
						break;
					if (errno == EINTR)
						continue;
					eof = 1;
					break;
				}
			}
		}
		(void)close(op[0]);
		(void)waitpid(pid, &status, 0);

		got = buf;
		got_len = used;
		gr = (eof && (buf != NULL || used == 0)) ? 0 : -1;
		if (!answered)
			FAILF("clip never emitted CLIP_REQUEST{IMAGE}");
	}

	if (gr != 0) {
		FAILF("xclip -t image/bmp -o produced no output (timeout?)");
		free(got);
		return;
	}
	if (got_len != len) {
		FAILF("xclip -o image length mismatch: got %zu, expected %zu",
			got_len, len);
		free(got);
		return;
	}
	if (memcmp(got, bmp, len) != 0)
		FAILF("xclip -o image data mismatch (BMP bytes differ)");
	else
		(void)printf("  xclip -t image/bmp -o len %zu matches "
			"(BMP byte-for-byte)\n", got_len);
	free(got);

	(void)drive_until(NULL, NULL, 100);
}

int
main(void)
{
	int sv[2];
	struct rdp_log_cfg logcfg;
	uint8_t *big;

	(void)setvbuf(stdout, NULL, _IONBF, 0);
	(void)printf("clip_x11_live:\n");

	/* Quiet logging unless RDP_CLIP_LIVE_DEBUG is set; write to stderr. */
	memset(&logcfg, 0, sizeof logcfg);
	logcfg.ident = "clip_x11_live";
	logcfg.foreground = 1;
	logcfg.level = getenv("RDP_CLIP_LIVE_DEBUG") != NULL
		? RDP_LOG_DEBUG : RDP_LOG_ERR;
	rdp_log_init(&logcfg);

	/* Ignore SIGPIPE: a child dying mid-write must not kill us. */
	(void)signal(SIGPIPE, SIG_IGN);

	g_display = ":91";

	if (spawn_xvfb(g_display) != 0)
		return 2;
	g_dpy = open_display_retry(g_display, 5000);
	if (g_dpy == NULL) {
		(void)fprintf(stderr, "could not open display %s\n", g_display);
		kill_xvfb();
		return 2;
	}
	(void)printf("  Xvfb up on %s (pid %ld)\n", g_display,
		(long)g_xvfb_pid);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		(void)fprintf(stderr, "socketpair: %s\n", strerror(errno));
		XCloseDisplay(g_dpy);
		kill_xvfb();
		return 2;
	}
	g_sv0 = sv[0];
	g_sv1 = sv[1];

	/*
	 * Enlarge both socket buffers past the protocol's 4 MiB frame cap.
	 * In production the worker is a separate process that drains the
	 * socket concurrently, so clip's blocking rdp_be_send of a multi-
	 * hundred-KB CLIP_DATA frame never wedges.  This harness is single
	 * threaded: it both writes and reads the same socketpair, so a frame
	 * larger than the default ~208 KB SO_SNDBUF would deadlock the write
	 * against the read.  Sizing the buffers so any single frame fits keeps
	 * clip's real blocking-send code path under test without a second
	 * process.  The kernel may cap the request; the value chosen is large
	 * enough for the 1 MiB tests in practice.
	 */
	{
		int bufsz = 8 * 1024 * 1024;
		(void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF,
			&bufsz, sizeof bufsz);
		(void)setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF,
			&bufsz, sizeof bufsz);
		(void)setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF,
			&bufsz, sizeof bufsz);
		(void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF,
			&bufsz, sizeof bufsz);
	}

	if (rdp_clip_init(&g_clip, g_dpy, g_sv1) != 0) {
		(void)fprintf(stderr, "rdp_clip_init failed\n");
		(void)close(sv[0]);
		(void)close(sv[1]);
		XCloseDisplay(g_dpy);
		kill_xvfb();
		return 2;
	}
	g_xfd = ConnectionNumber(g_dpy);

	big = malloc(BIG_LEN);
	if (big == NULL) {
		(void)fprintf(stderr, "oom\n");
		rdp_clip_close(&g_clip);
		(void)close(sv[0]);
		(void)close(sv[1]);
		XCloseDisplay(g_dpy);
		kill_xvfb();
		return 2;
	}
	memset(big, BIG_FILL, BIG_LEN);

	/* A: X -> RDP, small. */
	test_x_to_rdp("A", (const uint8_t *)"hello clipboard",
		strlen("hello clipboard"));

	/* B: X -> RDP, large (~1 MiB). */
	test_x_to_rdp("B", big, BIG_LEN);

	/* C: RDP -> X, small. */
	test_rdp_to_x("C", (const uint8_t *)"from rdp side",
		strlen("from rdp side"));

	/* D: RDP -> X, large (~1 MiB). */
	test_rdp_to_x("D", big, BIG_LEN);

	/*
	 * E: X -> RDP via a FORCED INCR transfer.  xclip ships even 1 MiB
	 * directly (BIG-REQUESTS), so cases A/B never reach the INCR reader;
	 * this case uses our own INCR owner with a small chunk so
	 * on_incr_property runs many rounds.  A position-dependent byte
	 * pattern makes reassembly order, not just total length, observable.
	 */
	{
		uint8_t *pat;
		size_t plen = 256 * 1024, i;   /* >> CHUNK and many INCR rounds */
		pat = malloc(plen);
		if (pat == NULL) {
			(void)fprintf(stderr, "oom (pat)\n");
		} else {
			for (i = 0; i < plen; i++)
				pat[i] = (uint8_t)((i * 31 + 7) & 0xff);
			test_x_to_rdp_incr("E", pat, plen, 4000);
			free(pat);
		}
	}

	/* F: X -> RDP, HTML via an xclip -t text/html owner. */
	test_x_to_rdp_html("F", (const uint8_t *)"<b>hello</b> <i>html</i>",
		strlen("<b>hello</b> <i>html</i>"));

	/* G: RDP -> X, HTML; xclip -t text/html -o pulls it back. */
	test_rdp_to_x_html("G", (const uint8_t *)"<p>from rdp</p>",
		strlen("<p>from rdp</p>"));

	/* H: X -> RDP, image via an xclip -t image/bmp owner. */
	test_x_to_rdp_image("H", bmp_2x2, sizeof bmp_2x2);

	/* I: RDP -> X, image; xclip -t image/bmp -o pulls it back. */
	test_rdp_to_x_image("I", bmp_2x2, sizeof bmp_2x2);

	free(big);

	rdp_clip_close(&g_clip);
	(void)close(sv[0]);
	(void)close(sv[1]);
	XCloseDisplay(g_dpy);
	kill_xvfb();
	rdp_log_close();

	if (g_fail)
		(void)printf("clip_x11_live: FAILED\n");
	else
		(void)printf("clip_x11_live: all ok\n");
	return g_fail ? 1 : 0;
}
