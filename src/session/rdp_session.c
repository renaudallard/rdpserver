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
 * rdp_session.c -- per-user session helper.
 *
 * Invoked by rdp-sessionmgr (after authentication, setuid to the
 * target user) with one end of an AF_UNIX socketpair pre-opened on
 * file descriptor 3.  The other end is held by the rdpd worker.
 *
 * Responsibilities (Phase F MVP):
 *   - find a free X DISPLAY number
 *   - spawn Xvfb on that display
 *   - become an X client; set up XShm for capture and XTest for input
 *   - spawn an xterm so there's something to look at
 *   - on a 200 ms timer, capture the root window and push a FRAME
 *     message to the worker
 *   - read INPUT messages from the worker and inject via XTest
 *
 * Tradeoffs (everything below the line is Phase F v2 work):
 *   - no cursor sync (server-rendered system cursor only)
 *   - no clipboard bridge yet (Phase G)
 *   - keystroke mapping is scancode+8 (works for US-layout Xvfb)
 *   - no .xsession; we always launch xterm directly
 */

#define _GNU_SOURCE

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/io.h"
#include "../backend/proto.h"
#include "../backend/proto_api.h"
#include "../common/utf16.h"	/* rdp_utf8_to_utf16le for RAIL window titles */
#include "../channels/rdpei.h"	/* RDPEI_CONTACT_*, RDPEI_MAX_CONTACTS */
#include "../wire/h264enc.h"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xdamage.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/XTest.h>
#include <X11/extensions/Xfixes.h>
#include <X11/XKBlib.h>		/* XkbKeysymToModifiers, XkbLockModifiers */
#include <X11/keysym.h>		/* XK_Caps_Lock, XK_Num_Lock, XK_Scroll_Lock */

#include "clip_x11.h"
#include "audio.h"
#include "mic.h"
#include "kbdmap.h"
#include "fuse_drive.h"
#include "printer.h"
#if HAVE_WLROOTS
#include "wayland_comp.h"
#endif

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../ddx/ddx_proto.h"

#include <sys/mman.h>

#define BE_FD 3
#define FUSE_FD 4   /* RDPDR drive mount, set up by rdp-sessionmgr (Linux) */
#define FRAME_INTERVAL_MS 66

#ifndef RDP_XVFB_PATH
# define RDP_XVFB_PATH "/usr/bin/Xvfb"
#endif

#ifndef RDP_XORG_PATH
# define RDP_XORG_PATH "/usr/lib/xorg/Xorg"
#endif

#ifndef RDP_XORG_CONF_PATH
# define RDP_XORG_CONF_PATH "/etc/rdpserver/xorg.conf"
#endif

static volatile sig_atomic_t want_shutdown;

/* Backend receive buffer.  Sized to the backend's 4 MiB maximum payload so
 * a large clipboard transfer (image or HTML) is not rejected with EMSGSIZE
 * and the connection dropped.  Shared by the session lifecycle's recv
 * loops, which never run concurrently. */
#define BE_RECV_BUF_SZ (4u * 1024u * 1024u + 0x1000u)
static uint8_t be_recv_buf[BE_RECV_BUF_SZ];

static void
on_signal(int sig)
{
	(void)sig;
	want_shutdown = 1;
}

static void
install_signals(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGTERM, &sa, NULL);
	(void)sigaction(SIGINT,  &sa, NULL);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT;   /* auto-reap */
	(void)sigaction(SIGCHLD, &sa, NULL);
}

static int
find_free_display(void)
{
	int n;
	char path[64];
	struct stat st;

	for (n = 100; n < 200; n++) {
		(void)snprintf(path, sizeof path, "/tmp/.X11-unix/X%d", n);
		if (stat(path, &st) != 0)
			return n;
	}
	return -1;
}

static pid_t
spawn_xvfb(int display_num, int w, int h)
{
	pid_t pid;
	char disp[16], screen[64];

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		(void)snprintf(disp, sizeof disp, ":%d", display_num);
		(void)snprintf(screen, sizeof screen, "%dx%dx24", w, h);
		execl(RDP_XVFB_PATH, "Xvfb", disp,
			"-screen", "0", screen,
			"-nolisten", "tcp",
			"-noreset",
			(char *)NULL);
		rdp_err("execl Xvfb: %s", strerror(errno));
		_exit(127);
	}
	return pid;
}

static int
wait_for_x_socket(int display_num, int timeout_ms)
{
	char path[64];
	int elapsed = 0;

	(void)snprintf(path, sizeof path, "/tmp/.X11-unix/X%d", display_num);
	while (elapsed < timeout_ms) {
		struct stat st;
		if (stat(path, &st) == 0) {
			/* Give Xvfb a moment to finish setup. */
			struct timespec ts = { 0, 50 * 1000 * 1000 };
			(void)nanosleep(&ts, NULL);
			return 0;
		}
		{
			struct timespec ts = { 0, 50 * 1000 * 1000 };
			(void)nanosleep(&ts, NULL);
		}
		elapsed += 50;
	}
	return -1;
}

static pid_t
spawn_xterm(void)
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		const char *home = getenv("HOME");
		if (home != NULL) {
			char xs[256];
			(void)snprintf(xs, sizeof xs, "%s/.xsession", home);
			if (access(xs, X_OK) == 0) {
				execl("/bin/sh", "sh", xs, (char *)NULL);
				_exit(127);
			}
		}
		execlp("xterm", "xterm", "-bg", "black", "-fg", "white",
			(char *)NULL);
		execlp("xclock", "xclock", (char *)NULL);
		rdp_err("xterm/xclock not found");
		_exit(127);
	}
	return pid;
}

struct cap {
	Display       *dpy;
	int            root;
	Window         root_win;
	int            w, h;
	XShmSegmentInfo shm;
	XImage        *img;
	int            shm_attached;
	int            use_shm;
};

static int
capture_init(struct cap *c, Display *dpy, int w, int h)
{
	int major, event_base, error_base;
	int sv;

	memset(c, 0, sizeof *c);
	c->dpy = dpy;
	c->root = DefaultScreen(dpy);
	c->root_win = RootWindow(dpy, c->root);
	c->w = w;
	c->h = h;

	c->use_shm = 0;
	if (XQueryExtension(dpy, "MIT-SHM", &major, &event_base, &error_base)
	    && XShmQueryVersion(dpy, &major, &event_base, &sv)) {
		c->img = XShmCreateImage(dpy,
			DefaultVisual(dpy, c->root),
			(unsigned int)DefaultDepth(dpy, c->root), ZPixmap,
			NULL, &c->shm, (unsigned int)w, (unsigned int)h);
		if (c->img != NULL) {
			c->shm.shmid = shmget(IPC_PRIVATE,
				(size_t)c->img->bytes_per_line * c->img->height,
				IPC_CREAT | 0600);
			if (c->shm.shmid != -1) {
				c->shm.shmaddr = shmat(c->shm.shmid, 0, 0);
				if (c->shm.shmaddr != (char *)-1) {
					c->img->data = c->shm.shmaddr;
					c->shm.readOnly = False;
					if (XShmAttach(dpy, &c->shm)) {
						XSync(dpy, False);
						c->shm_attached = 1;
						c->use_shm = 1;
					}
				}
				/* Tell the kernel to delete the segment when
				 * the last attach goes away. */
				(void)shmctl(c->shm.shmid, IPC_RMID, NULL);
			}
		}
	}
	if (!c->use_shm) {
		if (c->img != NULL) XDestroyImage(c->img);
		c->img = NULL;
		rdp_info("X11 capture using XGetImage (no MIT-SHM)");
	} else {
		rdp_info("X11 capture using MIT-SHM");
	}
	return 0;
}

static void
capture_close(struct cap *c)
{
	if (c->shm_attached) {
		XShmDetach(c->dpy, &c->shm);
		(void)shmdt(c->shm.shmaddr);
	}
	if (c->img != NULL) {
		XDestroyImage(c->img);
		c->img = NULL;
	}
}

/* Grab the root window; convert to BGR24 top-down into out (size
 * w*h*3). */
static int
capture_grab(struct cap *c, uint8_t *out)
{
	XImage *img;
	int x, y;

	if (c->use_shm) {
		if (!XShmGetImage(c->dpy, c->root_win, c->img,
			0, 0, AllPlanes))
			return -1;
		img = c->img;
	} else {
		img = XGetImage(c->dpy, c->root_win, 0, 0,
			(unsigned)c->w, (unsigned)c->h, AllPlanes, ZPixmap);
		if (img == NULL) return -1;
	}

	/* img->format is ZPixmap; bits_per_pixel typically 32 or 24.
	 * For 32bpp on most Xvfb the byte order is BGRX in little-endian
	 * memory; for 24bpp it's BGR.  Convert by reading individual
	 * pixels (works for any visual, slower than memcpy). */
	if (img->bits_per_pixel == 32) {
		for (y = 0; y < c->h; y++) {
			const uint8_t *src = (uint8_t *)img->data
				+ (size_t)y * img->bytes_per_line;
			uint8_t *dst = out + (size_t)y * c->w * 3;
			for (x = 0; x < c->w; x++) {
				dst[x * 3 + 0] = src[x * 4 + 0]; /* B */
				dst[x * 3 + 1] = src[x * 4 + 1]; /* G */
				dst[x * 3 + 2] = src[x * 4 + 2]; /* R */
			}
		}
	} else if (img->bits_per_pixel == 24) {
		for (y = 0; y < c->h; y++) {
			memcpy(out + (size_t)y * c->w * 3,
				(uint8_t *)img->data
				+ (size_t)y * img->bytes_per_line,
				(size_t)c->w * 3);
		}
	} else {
		if (img != c->img) XDestroyImage(img);
		return -1;
	}

	if (img != c->img) XDestroyImage(img);
	return 0;
}

static int
send_frame(int fd, int w, int h, const uint8_t *pixels)
{
	struct rdp_be_frame_hdr fhdr;
	uint8_t hdr[RDP_BE_HEADER + sizeof fhdr];
	uint32_t total = (uint32_t)sizeof fhdr + (uint32_t)w * h * 3;

	hdr[0] = RDP_BE_FRAME;
	hdr[1] = 0; hdr[2] = 0; hdr[3] = 0;
	hdr[4] = (uint8_t)(total & 0xff);
	hdr[5] = (uint8_t)((total >> 8) & 0xff);
	hdr[6] = (uint8_t)((total >> 16) & 0xff);
	hdr[7] = (uint8_t)((total >> 24) & 0xff);

	fhdr.x = 0;
	fhdr.y = 0;
	fhdr.w = (uint16_t)w;
	fhdr.h = (uint16_t)h;
	memcpy(hdr + RDP_BE_HEADER, &fhdr, sizeof fhdr);

	{
		uint8_t *buf = malloc(RDP_BE_HEADER + total);
		int rc;
		if (buf == NULL) return -1;
		memcpy(buf, hdr, RDP_BE_HEADER + sizeof fhdr);
		memcpy(buf + RDP_BE_HEADER + sizeof fhdr,
			pixels, (size_t)w * h * 3);
		rc = (rdp_write_full(fd, buf, RDP_BE_HEADER + total)
			== (ssize_t)(RDP_BE_HEADER + total)) ? 0 : -1;
		free(buf);
		return rc;
	}
}

/* Forward the current X cursor image to the worker as an RDP_BE_CURSOR
 * message: an rdp_be_cursor_hdr followed by width*height pixels in
 * top-down R,G,B,A order.  Returns 0 on success, -1 on failure. */
static int
send_cursor(int fd, XFixesCursorImage *ci)
{
	struct rdp_be_cursor_hdr hdr;
	size_t px, i, len;
	uint8_t *buf, *out;
	int rc;

	if (ci == NULL || ci->width == 0 || ci->height == 0) return 0;
	px = (size_t)ci->width * ci->height;
	if (px > (1u << 20)) return 0;
	len = sizeof hdr + px * 4;
	buf = malloc(len);
	if (buf == NULL) return -1;

	hdr.width = ci->width;
	hdr.height = ci->height;
	hdr.hotspot_x = ci->xhot;
	hdr.hotspot_y = ci->yhot;
	memcpy(buf, &hdr, sizeof hdr);

	out = buf + sizeof hdr;
	for (i = 0; i < px; i++) {
		/* ci->pixels is unsigned long*; narrowing to uint32_t is
		 * mandatory on 64-bit so we read one ARGB pixel per slot. */
		uint32_t p = (uint32_t)ci->pixels[i];
		out[i * 4 + 0] = (uint8_t)(p >> 16); /* R */
		out[i * 4 + 1] = (uint8_t)(p >> 8);  /* G */
		out[i * 4 + 2] = (uint8_t)p;         /* B */
		out[i * 4 + 3] = (uint8_t)(p >> 24); /* A */
	}

	rc = rdp_be_send(fd, RDP_BE_CURSOR, buf, len);
	free(buf);
	return rc;
}

static int
send_h264_frame(int fd, int w, int h, const uint8_t *h264_data,
    size_t h264_len)
{
	struct rdp_be_h264_frame_hdr fhdr;
	uint8_t hdr[RDP_BE_HEADER + sizeof fhdr];
	uint32_t total = (uint32_t)sizeof fhdr + (uint32_t)h264_len;

	hdr[0] = RDP_BE_H264_FRAME;
	hdr[1] = 0; hdr[2] = 0; hdr[3] = 0;
	hdr[4] = (uint8_t)(total & 0xff);
	hdr[5] = (uint8_t)((total >> 8) & 0xff);
	hdr[6] = (uint8_t)((total >> 16) & 0xff);
	hdr[7] = (uint8_t)((total >> 24) & 0xff);

	fhdr.x = 0;
	fhdr.y = 0;
	fhdr.w = (uint16_t)w;
	fhdr.h = (uint16_t)h;
	fhdr.h264_len = (uint32_t)h264_len;
	memcpy(hdr + RDP_BE_HEADER, &fhdr, sizeof fhdr);

	{
		uint8_t *buf = malloc(RDP_BE_HEADER + total);
		int rc;
		if (buf == NULL) return -1;
		memcpy(buf, hdr, RDP_BE_HEADER + sizeof fhdr);
		memcpy(buf + RDP_BE_HEADER + sizeof fhdr,
			h264_data, h264_len);
		rc = (rdp_write_full(fd, buf, RDP_BE_HEADER + total)
			== (ssize_t)(RDP_BE_HEADER + total)) ? 0 : -1;
		free(buf);
		return rc;
	}
}

static int
inject_key(Display *dpy, const struct rdp_be_input_key *k)
{
	/* PC/AT set 1 scancode + 8 == X11 keycode on a stock Xvfb. */
	KeyCode kc = (KeyCode)((k->scancode + 8) & 0xff);
	if (kc == 0) return 0;
	(void)XTestFakeKeyEvent(dpy, kc, k->down ? True : False, 0);
	XFlush(dpy);
	return 0;
}

static int
inject_mouse(Display *dpy, const struct rdp_be_input_mouse *m)
{
	if (m->flags & 0x01)
		(void)XTestFakeMotionEvent(dpy, 0, m->x, m->y, 0);
	if (m->flags & 0x02) {
		int btn = 1;
		if (m->buttons & 0x02) btn = 3;
		else if (m->buttons & 0x04) btn = 2;
		(void)XTestFakeButtonEvent(dpy, btn,
			(m->buttons & 0x08) ? True : False, 0);
	}
	XFlush(dpy);
	return 0;
}

/* Inject one INPUT_TOUCH message (MS-RDPEI contacts) into the X session.
 *
 * TODO Stage 2b: the Wayland backend should inject real wl_touch multitouch
 * (one touch point per contact id).  X11 / Xvfb has no multitouch device, so
 * here we emulate only the PRIMARY contact (the one with the lowest contact
 * id) as a single left pointer: move to its (x,y), press button 1 on
 * RDPEI_CONTACT_DOWN, release on RDPEI_CONTACT_UP, and just move on UPDATE.
 * Pen contacts are treated the same way.  Returns 0 always; a malformed
 * buffer is ignored. */
static int
inject_touch(Display *dpy, const uint8_t *buf, size_t len)
{
	struct rdp_be_input_touch th;
	struct rdp_be_touch_contact tc, primary;
	int have_primary = 0;
	size_t off, i;
	uint32_t count;

	if (dpy == NULL || len < sizeof th) return 0;
	memcpy(&th, buf, sizeof th);
	count = th.count;
	if (count > RDPEI_MAX_CONTACTS) count = RDPEI_MAX_CONTACTS;
	off = sizeof th;
	memset(&primary, 0, sizeof primary);
	for (i = 0; i < count; i++) {
		if (len - off < sizeof tc) break;
		memcpy(&tc, buf + off, sizeof tc);
		off += sizeof tc;
		/* Pick the lowest contact id as the primary pointer. */
		if (!have_primary || tc.id < primary.id) {
			primary = tc;
			have_primary = 1;
		}
	}
	if (!have_primary) return 0;

	(void)XTestFakeMotionEvent(dpy, 0, primary.x, primary.y, 0);
	if (primary.flags & RDPEI_CONTACT_DOWN)
		(void)XTestFakeButtonEvent(dpy, 1, True, 0);
	else if (primary.flags & RDPEI_CONTACT_UP)
		(void)XTestFakeButtonEvent(dpy, 1, False, 0);
	/* RDPEI_CONTACT_UPDATE moves only; no button change. */
	XFlush(dpy);
	return 0;
}

/* Map a Unicode scalar value to an X keysym (X.Org convention:
 * Latin-1 maps directly, everything else is 0x01000000 | codepoint). */
static KeySym
cp_to_keysym(uint32_t cp)
{
	if (cp <= 0xff) return (KeySym)cp;
	return (KeySym)(0x01000000u | cp);
}

#define UNI_SPARE_POOL 8
#define UNI_MAX_LEVELS 8     /* cap on keysyms_per_keycode we rewrite */
static KeyCode uni_spare[UNI_SPARE_POOL];  /* reserved all-NoSymbol keycodes */
static int uni_spare_n;       /* number of spare keycodes found */
static unsigned uni_spare_rr; /* round-robin slot */
static int uni_per = 1;       /* keysyms per keycode on this display */

/* Collect up to UNI_SPARE_POOL keycodes that are currently all-NoSymbol,
 * scanning from the top down (high keycodes are never produced by the
 * scancode + 8 path, and we only ever touch genuinely empty ones).
 * inject_unicode round-robins over them and leaves each remapped, so a
 * client can still resolve the delivered KeyPress.  Chosen once, after
 * the display opens. */
static void
uni_init_spares(Display *dpy)
{
	int lo = 0, hi = 0, per = 0, kc, j;
	KeySym *map;

	if (uni_spare_n != 0) return;
	XDisplayKeycodes(dpy, &lo, &hi);
	map = XGetKeyboardMapping(dpy, lo, hi - lo + 1, &per);
	if (map == NULL || per < 1) {
		if (map != NULL) XFree(map);
		return;
	}
	uni_per = (per > UNI_MAX_LEVELS) ? UNI_MAX_LEVELS : per;
	for (kc = hi; kc >= lo && uni_spare_n < UNI_SPARE_POOL; kc--) {
		int empty = 1;
		for (j = 0; j < per; j++)
			if (map[(kc - lo) * per + j] != NoSymbol) {
				empty = 0;
				break;
			}
		if (empty)
			uni_spare[uni_spare_n++] = (KeyCode)kc;
	}
	XFree(map);
}

/* Inject one Unicode codepoint via XTest.  A spare keycode is mapped to
 * the target keysym at every level (so the result does not depend on the
 * modifier state), committed with XSync before the fake key, then pressed
 * and released.  The mapping is deliberately left live: clients resolve a
 * keycode to a keysym lazily, so the mapping must outlast event delivery;
 * the round-robin pool keeps it valid until the slot is reused. */
static int
inject_unicode(Display *dpy, const struct rdp_be_input_unicode *u)
{
	KeySym ks = cp_to_keysym(u->codepoint);
	KeySym lv[UNI_MAX_LEVELS];
	KeyCode kc;
	int i, n = uni_per;

	if (uni_spare_n == 0) return 0;   /* no free keycode to borrow */
	if (n < 1) n = 1;
	if (n > UNI_MAX_LEVELS) n = UNI_MAX_LEVELS;
	kc = uni_spare[uni_spare_rr++ % (unsigned)uni_spare_n];

	for (i = 0; i < n; i++) lv[i] = ks;
	XChangeKeyboardMapping(dpy, kc, n, lv, 1);
	XSync(dpy, False);                   /* commit the map first */
	(void)XTestFakeKeyEvent(dpy, kc, True, 0);
	(void)XTestFakeKeyEvent(dpy, kc, False, 0);
	XSync(dpy, False);
	return 0;
}

/* MS-RDPBCGR fast-path SYNC toggle bits (KANA 0x08 is ignored). */
#define RDP_SYNC_SCROLL_LOCK 0x01
#define RDP_SYNC_NUM_LOCK    0x02
#define RDP_SYNC_CAPS_LOCK   0x04

/* Lock or unlock the X modifier bound to a toggle keysym.  Resolving
 * the mask via XkbKeysymToModifiers is more robust than hardcoding
 * LockMask/Mod2, since Num and Scroll Lock vary by layout. */
static void
lock_one(Display *dpy, KeySym ks, int on)
{
	unsigned int mask = XkbKeysymToModifiers(dpy, ks);

	if (mask == 0)			/* toggle unbound in this layout */
		return;
	(void)XkbLockModifiers(dpy, XkbUseCoreKbd, mask, on ? mask : 0);
}

/* Apply the client's lock-key state to the session keyboard.  The
 * state is absolute, so repeated syncs converge without drift. */
static int
inject_sync(Display *dpy, const struct rdp_be_input_sync *s)
{
	lock_one(dpy, XK_Caps_Lock,   (s->flags & RDP_SYNC_CAPS_LOCK) != 0);
	lock_one(dpy, XK_Num_Lock,    (s->flags & RDP_SYNC_NUM_LOCK) != 0);
	lock_one(dpy, XK_Scroll_Lock, (s->flags & RDP_SYNC_SCROLL_LOCK) != 0);
	XFlush(dpy);
	return 0;
}

static pid_t
spawn_xorg_ddx(int display_num, int w, int h, int ctrl_fd)
{
	pid_t pid;
	char disp[16], wbuf[16], hbuf[16], fdbuf[16];

	(void)snprintf(disp, sizeof disp, ":%d", display_num);
	(void)snprintf(wbuf, sizeof wbuf, "%d", w);
	(void)snprintf(hbuf, sizeof hbuf, "%d", h);
	(void)snprintf(fdbuf, sizeof fdbuf, "%d", ctrl_fd);

	pid = fork();
	if (pid != 0) return pid;

	(void)setenv("RDPSERVER_W", wbuf, 1);
	(void)setenv("RDPSERVER_H", hbuf, 1);
	(void)setenv("RDPSERVER_CTRL_FD", fdbuf, 1);

#ifdef __OpenBSD__
	execl(RDP_XORG_PATH, "Xorg",
	    "-noreset", "-ac",
	    "-config", RDP_XORG_CONF_PATH, disp, (char *)NULL);
#else
	execl(RDP_XORG_PATH, "Xorg",
	    "-noreset", "-sharevts", "-novtswitch", "-keeptty", "-ac",
	    "-config", RDP_XORG_CONF_PATH, disp, (char *)NULL);
#endif
	(void)dprintf(2, "exec %s: %s\n", RDP_XORG_PATH, strerror(errno));
	_exit(127);
}

static int
ddx_recv_shm(int ctrl_fd, int *shm_fd_out,
    uint16_t *w, uint16_t *h, uint32_t *stride)
{
	struct msghdr msg;
	struct iovec iov;
	uint8_t buf[DDX_PROTO_HEADER + sizeof(struct ddx_shm_ready)];
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	struct ddx_shm_ready *sr;
	ssize_t n;
	int fd = -1;

	memset(&msg, 0, sizeof msg);
	iov.iov_base = buf;
	iov.iov_len = sizeof buf;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof cbuf);
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;

	do { n = recvmsg(ctrl_fd, &msg, 0); }
	while (n < 0 && errno == EINTR);
	if (n < (ssize_t)sizeof buf) return -1;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS
		    && cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	}
	if (fd < 0) return -1;

	sr = (struct ddx_shm_ready *)(buf + DDX_PROTO_HEADER);
	*w = sr->width;
	*h = sr->height;
	*stride = sr->stride;
	*shm_fd_out = fd;
	return 0;
}

static int
ddx_send_input_key(int ctrl_fd, const struct rdp_be_input_key *k)
{
	uint8_t buf[DDX_PROTO_HEADER + sizeof(struct ddx_input_key)];
	struct ddx_input_key *dk = (struct ddx_input_key *)(buf + DDX_PROTO_HEADER);
	uint32_t plen = sizeof(struct ddx_input_key);

	buf[0] = DDX_MSG_INPUT_KEY & 0xff;
	buf[1] = buf[2] = buf[3] = 0;
	buf[4] = plen & 0xff;
	buf[5] = buf[6] = buf[7] = 0;
	dk->scancode = k->scancode;
	dk->down = k->down;
	dk->extended = k->extended;
	return rdp_write_full(ctrl_fd, buf, sizeof buf) == sizeof buf ? 0 : -1;
}

static int
ddx_send_input_mouse(int ctrl_fd, const struct rdp_be_input_mouse *m)
{
	uint8_t buf[DDX_PROTO_HEADER + sizeof(struct ddx_input_mouse)];
	struct ddx_input_mouse *dm = (struct ddx_input_mouse *)(buf + DDX_PROTO_HEADER);
	uint32_t plen = sizeof(struct ddx_input_mouse);

	buf[0] = DDX_MSG_INPUT_MOUSE & 0xff;
	buf[1] = buf[2] = buf[3] = 0;
	buf[4] = plen & 0xff;
	buf[5] = buf[6] = buf[7] = 0;
	dm->x = m->x;
	dm->y = m->y;
	dm->buttons = m->buttons;
	dm->flags = m->flags;
	return rdp_write_full(ctrl_fd, buf, sizeof buf) == sizeof buf ? 0 : -1;
}

static int
ddx_send_frame_region(int be_fd, const uint8_t *fb, uint32_t fb_stride,
    int16_t x, int16_t y, int16_t rw, int16_t rh, uint8_t *tmp)
{
	struct rdp_be_frame_hdr fhdr;
	uint8_t hdr[RDP_BE_HEADER + sizeof fhdr];
	uint32_t total;
	int row;

	if (rw <= 0 || rh <= 0) return 0;
	total = (uint32_t)sizeof fhdr + (uint32_t)rw * rh * 3;

	hdr[0] = RDP_BE_FRAME;
	hdr[1] = 0; hdr[2] = 0; hdr[3] = 0;
	hdr[4] = (uint8_t)(total & 0xff);
	hdr[5] = (uint8_t)((total >> 8) & 0xff);
	hdr[6] = (uint8_t)((total >> 16) & 0xff);
	hdr[7] = (uint8_t)((total >> 24) & 0xff);
	fhdr.x = (uint16_t)x;
	fhdr.y = (uint16_t)y;
	fhdr.w = (uint16_t)rw;
	fhdr.h = (uint16_t)rh;
	memcpy(hdr + RDP_BE_HEADER, &fhdr, sizeof fhdr);
	if (rdp_write_full(be_fd, hdr, sizeof hdr) != sizeof hdr)
		return -1;

	for (row = 0; row < rh; row++) {
		const uint8_t *src = fb + (size_t)(y + row) * fb_stride
		    + (size_t)x * 4;
		uint8_t *dst = tmp;
		int col;
		for (col = 0; col < rw; col++) {
			dst[col * 3 + 0] = src[col * 4 + 0];
			dst[col * 3 + 1] = src[col * 4 + 1];
			dst[col * 3 + 2] = src[col * 4 + 2];
		}
		if (rdp_write_full(be_fd, dst, (size_t)rw * 3) != (ssize_t)rw * 3)
			return -1;
	}
	return 0;
}

static int
run_ddx_mode(int w, int h)
{
	int sv[2];
	int display_num;
	pid_t xorg_pid, xterm_pid;
	int shm_fd = -1;
	uint8_t *fb = NULL;
	uint16_t fb_w = 0, fb_h = 0;
	uint32_t fb_stride = 0, fb_size = 0;
	uint8_t *row_buf = NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		rdp_err("socketpair: %s", strerror(errno));
		return 1;
	}

	display_num = find_free_display();
	if (display_num < 0) {
		rdp_err("no free X display");
		return 1;
	}
	rdp_info("DDX mode: display :%d (%dx%d)", display_num, w, h);

	xorg_pid = spawn_xorg_ddx(display_num, w, h, sv[1]);
	if (xorg_pid < 0) {
		rdp_err("spawn Xorg: %s", strerror(errno));
		return 1;
	}
	(void)close(sv[1]);

	if (wait_for_x_socket(display_num, 8000) != 0) {
		rdp_err("Xorg didn't come up");
		(void)kill(xorg_pid, SIGTERM);
		return 1;
	}

	if (ddx_recv_shm(sv[0], &shm_fd, &fb_w, &fb_h, &fb_stride) != 0) {
		rdp_err("failed to receive SHM from DDX");
		(void)kill(xorg_pid, SIGTERM);
		return 1;
	}
	fb_size = fb_stride * fb_h;
	fb = mmap(NULL, fb_size, PROT_READ, MAP_SHARED, shm_fd, 0);
	if (fb == MAP_FAILED) {
		rdp_err("mmap shm: %s", strerror(errno));
		(void)close(shm_fd);
		(void)kill(xorg_pid, SIGTERM);
		return 1;
	}
	rdp_info("DDX shm: %ux%u stride=%u fd=%d",
	    (unsigned)fb_w, (unsigned)fb_h, fb_stride, shm_fd);

	{
		struct rdp_be_hello hello = {fb_w, fb_h, 24, 0};
		if (rdp_be_send(BE_FD, RDP_BE_HELLO_S2W,
		    &hello, sizeof hello) != 0) {
			rdp_err("HELLO send failed: %s", strerror(errno));
			goto out;
		}
	}

	{
		char buf[16];
		(void)snprintf(buf, sizeof buf, ":%d", display_num);
		setenv("DISPLAY", buf, 1);
	}

	{
		char rtdir[64];
		(void)snprintf(rtdir, sizeof rtdir, "/run/user/%u",
			(unsigned)getuid());
		(void)mkdir(rtdir, 0700);
		(void)setenv("XDG_RUNTIME_DIR", rtdir, 1);
	}

	/* Start PulseAudio with a null sink for audio capture. */
	{
		pid_t pa = fork();
		if (pa == 0) {
			execlp("pulseaudio", "pulseaudio",
				"--start", "--exit-idle-time=-1",
				(char *)NULL);
			_exit(0);
		}
		if (pa > 0) {
			int st;
			(void)waitpid(pa, &st, 0);
		}
	}

	xterm_pid = spawn_xterm();

	row_buf = malloc((size_t)fb_w * 3);
	if (row_buf == NULL) goto out;

	if (pledge("stdio rpath wpath cpath unix proc sendfd recvfd", NULL) != 0)
		rdp_warn("pledge session ddx: %s", strerror(errno));

	while (!want_shutdown) {
		struct pollfd pfd[2];
		pfd[0].fd = BE_FD;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = sv[0];
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;

		(void)poll(pfd, 2, FRAME_INTERVAL_MS);

		if (pfd[0].revents & POLLIN) {
			uint32_t type;
			uint8_t *buf = be_recv_buf;
			ssize_t n = rdp_be_recv(BE_FD, &type, buf,
				sizeof be_recv_buf);
			if (n <= 0) break;
			if (type == RDP_BE_INPUT_KEY
			    && n >= (ssize_t)sizeof(struct rdp_be_input_key)) {
				struct rdp_be_input_key k;
				memcpy(&k, buf, sizeof k);
				ddx_send_input_key(sv[0], &k);
			} else if (type == RDP_BE_INPUT_MOUSE
			    && n >= (ssize_t)sizeof(struct rdp_be_input_mouse)) {
				struct rdp_be_input_mouse m;
				memcpy(&m, buf, sizeof m);
				ddx_send_input_mouse(sv[0], &m);
			} else if (type == RDP_BE_RESIZE
			    && n >= (ssize_t)sizeof(struct rdp_be_resize)) {
				struct rdp_be_resize rs;
				uint8_t rbuf[DDX_PROTO_HEADER + sizeof(struct ddx_resize)];
				struct ddx_resize *dr;
				memcpy(&rs, buf, sizeof rs);
				rbuf[0] = DDX_MSG_RESIZE & 0xff;
				rbuf[1] = rbuf[2] = rbuf[3] = 0;
				rbuf[4] = sizeof(struct ddx_resize) & 0xff;
				rbuf[5] = rbuf[6] = rbuf[7] = 0;
				dr = (struct ddx_resize *)(rbuf + DDX_PROTO_HEADER);
				dr->width = rs.width;
				dr->height = rs.height;
				(void)rdp_write_full(sv[0], rbuf, sizeof rbuf);
			} else if (type == RDP_BE_BYE) {
				break;
			}
		}

		if (pfd[1].revents & POLLIN) {
			uint8_t mhdr[DDX_PROTO_HEADER];
			uint32_t mtype, mlen;
			int new_fd = -1;

			{
				struct msghdr msg;
				struct iovec iov;
				char cbuf[CMSG_SPACE(sizeof(int))];
				struct cmsghdr *cmsg;
				ssize_t rr;

				memset(&msg, 0, sizeof msg);
				iov.iov_base = mhdr;
				iov.iov_len = sizeof mhdr;
				msg.msg_iov = &iov;
				msg.msg_iovlen = 1;
				memset(cbuf, 0, sizeof cbuf);
				msg.msg_control = cbuf;
				msg.msg_controllen = sizeof cbuf;
				do { rr = recvmsg(sv[0], &msg, 0); }
				while (rr < 0 && errno == EINTR);
				if (rr < (ssize_t)sizeof mhdr) break;
				for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				     cmsg = CMSG_NXTHDR(&msg, cmsg))
					if (cmsg->cmsg_level == SOL_SOCKET
					    && cmsg->cmsg_type == SCM_RIGHTS)
						memcpy(&new_fd, CMSG_DATA(cmsg),
						    sizeof(int));
			}
			mtype = (uint32_t)mhdr[0]
			    | ((uint32_t)mhdr[1] << 8);
			mlen = (uint32_t)mhdr[4]
			    | ((uint32_t)mhdr[5] << 8)
			    | ((uint32_t)mhdr[6] << 16)
			    | ((uint32_t)mhdr[7] << 24);

			if (mtype == DDX_MSG_SHM_READY
			    && mlen >= sizeof(struct ddx_shm_ready)
			    && new_fd >= 0) {
				struct ddx_shm_ready sr;
				ssize_t rr;
				rr = rdp_read_full(sv[0], &sr, sizeof sr);
				if (rr >= (ssize_t)sizeof sr) {
					uint32_t new_sz = sr.stride * sr.height;
					uint8_t *new_fb = mmap(NULL, new_sz,
					    PROT_READ, MAP_SHARED, new_fd, 0);
					if (new_fb != MAP_FAILED) {
						munmap(fb, fb_size);
						close(shm_fd);
						fb = new_fb;
						fb_w = sr.width;
						fb_h = sr.height;
						fb_stride = sr.stride;
						fb_size = new_sz;
						shm_fd = new_fd;
						new_fd = -1;
						free(row_buf);
						row_buf = malloc((size_t)fb_w * 3);
						if (row_buf == NULL) break;
						rdp_info("DDX resize: %ux%u",
						    (unsigned)fb_w, (unsigned)fb_h);
						struct rdp_be_hello hello = {
						    fb_w, fb_h, 24, 0};
						(void)rdp_be_send(BE_FD,
						    RDP_BE_HELLO_S2W,
						    &hello, sizeof hello);
					}
				}
				if (new_fd >= 0) close(new_fd);
			} else if (mtype == DDX_MSG_DAMAGE && mlen >= sizeof(struct ddx_damage_hdr)) {
				struct ddx_damage_hdr dh;
				if (rdp_read_full(sv[0], &dh, sizeof dh) == sizeof dh) {
					int i;
					for (i = 0; i < dh.nrects; i++) {
						struct ddx_damage_rect dr;
						if (rdp_read_full(sv[0], &dr, sizeof dr) != sizeof dr)
							break;
						if (dr.x < 0) dr.x = 0;
						if (dr.y < 0) dr.y = 0;
						if (dr.x + dr.w > (int16_t)fb_w)
							dr.w = (int16_t)fb_w - dr.x;
						if (dr.y + dr.h > (int16_t)fb_h)
							dr.h = (int16_t)fb_h - dr.y;
						(void)ddx_send_frame_region(BE_FD,
						    fb, fb_stride,
						    dr.x, dr.y, dr.w, dr.h,
						    row_buf);
					}
				}
			} else {
				uint8_t skip[256];
				while (mlen > 0) {
					size_t c = mlen > sizeof skip ? sizeof skip : mlen;
					if (rdp_read_full(sv[0], skip, c) <= 0) break;
					mlen -= (uint32_t)c;
				}
			}
		}
	}

out:
	rdp_info("DDX session shutting down");
	free(row_buf);
	if (fb != NULL && fb != MAP_FAILED) munmap(fb, fb_size);
	if (shm_fd >= 0) (void)close(shm_fd);
	(void)close(sv[0]);
	if (xterm_pid > 0) (void)kill(xterm_pid, SIGTERM);
	(void)kill(xorg_pid, SIGTERM);
	(void)waitpid(xorg_pid, NULL, 0);
	return 0;
}

/* Send one RemoteApp (RAIL) window geometry event to the worker.  op 0
 * (create/update) carries a UTF-16LE title built from the UTF-8 title; op 1
 * (delete) carries no title.  title may be NULL.  The title is capped at
 * RDP_BE_WINDOW_TITLE_MAX UTF-16LE bytes so one message stays bounded. */
#define RDP_BE_WINDOW_TITLE_MAX 256u
static void
send_window_event(int op, uint32_t window_id, int32_t x, int32_t y,
    uint32_t w, uint32_t h, const char *title)
{
	struct rdp_be_window wmsg;
	uint8_t body[sizeof(struct rdp_be_window) + RDP_BE_WINDOW_TITLE_MAX];
	size_t tlen = 0;

	memset(&wmsg, 0, sizeof wmsg);
	wmsg.window_id = window_id;
	wmsg.x = x;
	wmsg.y = y;
	wmsg.w = w;
	wmsg.h = h;
	wmsg.op = (uint8_t)op;

	if (op == RDP_BE_WINDOW_OP_CREATE && title != NULL && *title != '\0') {
		size_t need = rdp_utf8_to_utf16le(
		    body + sizeof wmsg, RDP_BE_WINDOW_TITLE_MAX,
		    title, strlen(title));
		/* On malformed UTF-8 or truncation, fall back to an empty
		 * title rather than send a partial code unit. */
		if (need != (size_t)-1 && need <= RDP_BE_WINDOW_TITLE_MAX)
			tlen = need;
	}
	wmsg.title_len = (uint16_t)tlen;
	memcpy(body, &wmsg, sizeof wmsg);
	(void)rdp_be_send(BE_FD, RDP_BE_WINDOW, body, sizeof wmsg + tlen);
}

#if HAVE_WLROOTS
static int
run_wayland_mode(int w, int h)
{
	struct rdp_wl_comp *wl;
	uint8_t *row_buf;

	wl = rdp_wl_comp_create(w, h);
	if (wl == NULL) {
		rdp_err("wayland compositor init failed");
		return 1;
	}
	rdp_info("Wayland mode: %s (%dx%d)", rdp_wl_comp_get_socket(wl), w, h);

	(void)setenv("WAYLAND_DISPLAY", rdp_wl_comp_get_socket(wl), 1);
	(void)setenv("XDG_RUNTIME_DIR", "/tmp", 0);

	{
		struct rdp_be_hello hello = {(uint16_t)w, (uint16_t)h, 24, 0};
		if (rdp_be_send(BE_FD, RDP_BE_HELLO_S2W,
		    &hello, sizeof hello) != 0) {
			rdp_err("HELLO send failed: %s", strerror(errno));
			rdp_wl_comp_destroy(wl);
			return 1;
		}
	}

	{
		pid_t child = fork();
		if (child == 0) {
			const char *term = getenv("WAYLAND_TERMINAL");
			if (term == NULL) term = "foot";
			execlp(term, term, (char *)NULL);
			execlp("weston-terminal", "weston-terminal", (char *)NULL);
			execlp("xterm", "xterm", (char *)NULL);
			_exit(127);
		}
	}

	row_buf = malloc((size_t)w * 3);
	if (row_buf == NULL) {
		rdp_wl_comp_destroy(wl);
		return 1;
	}

	while (!want_shutdown) {
		struct pollfd pfd;
		pfd.fd = BE_FD;
		pfd.events = POLLIN;
		pfd.revents = 0;

		rdp_wl_comp_dispatch(wl, 0);
		(void)poll(&pfd, 1, FRAME_INTERVAL_MS);

		if (pfd.revents & POLLIN) {
			uint32_t type;
			uint8_t *buf = be_recv_buf;
			ssize_t n = rdp_be_recv(BE_FD, &type, buf,
				sizeof be_recv_buf);
			if (n <= 0) break;
			if (type == RDP_BE_INPUT_KEY
			    && n >= (ssize_t)sizeof(struct rdp_be_input_key)) {
				struct rdp_be_input_key k;
				memcpy(&k, buf, sizeof k);
				rdp_wl_comp_inject_key(wl,
				    k.scancode, k.down);
			} else if (type == RDP_BE_INPUT_MOUSE
			    && n >= (ssize_t)sizeof(struct rdp_be_input_mouse)) {
				struct rdp_be_input_mouse m;
				memcpy(&m, buf, sizeof m);
				rdp_wl_comp_inject_pointer(wl,
				    m.x, m.y, m.buttons, m.flags & 1);
			} else if (type == RDP_BE_INPUT_TOUCH
			    && n >= (ssize_t)sizeof(struct rdp_be_input_touch)) {
				/* Real multitouch: one wl_touch point per RDPEI
				 * contact, mapped by phase (down/motion/up). */
				struct rdp_be_input_touch th;
				struct rdp_be_touch_contact tc;
				size_t off, i;
				uint32_t count;
				int any = 0;
				memcpy(&th, buf, sizeof th);
				count = th.count;
				if (count > RDPEI_MAX_CONTACTS)
					count = RDPEI_MAX_CONTACTS;
				off = sizeof th;
				for (i = 0; i < count; i++) {
					int phase;
					if ((size_t)n - off < sizeof tc) break;
					memcpy(&tc, buf + off, sizeof tc);
					off += sizeof tc;
					if (tc.flags & RDPEI_CONTACT_DOWN)
						phase = 0;
					else if (tc.flags & RDPEI_CONTACT_UP)
						phase = 2;
					else
						phase = 1;
					rdp_wl_comp_inject_touch(wl, tc.id,
					    tc.x, tc.y, phase);
					any = 1;
				}
				if (any)
					rdp_wl_comp_touch_frame(wl);
			} else if (type == RDP_BE_RAIL) {
				/* RemoteApp: switch the compositor to
				 * per-window RAIL mode so it emits WINDOW
				 * geometry events we forward below. */
				rdp_wl_comp_set_rail(wl, 1);
			} else if (type == RDP_BE_RESIZE
			    && n >= (ssize_t)sizeof(struct rdp_be_resize)) {
				struct rdp_be_resize rs;
				memcpy(&rs, buf, sizeof rs);
				if (rs.width >= 200 && rs.height >= 200) {
					w = rs.width; h = rs.height;
					rdp_wl_comp_resize(wl, w, h);
					free(row_buf);
					row_buf = malloc((size_t)w * 3);
					if (row_buf == NULL) break;
				}
			} else if (type == RDP_BE_BYE) {
				break;
			}
		}

		/* Drain RAIL window geometry events the compositor queued
		 * while dispatching, and forward each to the worker. */
		{
			struct rdp_wl_window_event ev;
			while (rdp_wl_comp_poll_window_event(wl, &ev)) {
				int op = ev.op == 1 ? RDP_BE_WINDOW_OP_DELETE
				    : RDP_BE_WINDOW_OP_CREATE;
				send_window_event(op, ev.window_id,
				    ev.x, ev.y, ev.w, ev.h, ev.title);
			}
		}

		if (rdp_wl_comp_is_dirty(wl)) {
			uint8_t *pixels;
			int fw, fh, fstride;
			rdp_wl_comp_clear_dirty(wl);
			if (rdp_wl_comp_get_framebuffer(wl, &pixels,
			    &fw, &fh, &fstride) == 0) {
				struct rdp_be_frame_hdr fhdr;
				uint8_t hdr[RDP_BE_HEADER + sizeof fhdr];
				uint32_t total = (uint32_t)sizeof fhdr
				    + (uint32_t)fw * fh * 3;
				int row;

				hdr[0] = RDP_BE_FRAME;
				hdr[1] = hdr[2] = hdr[3] = 0;
				hdr[4] = (uint8_t)(total & 0xff);
				hdr[5] = (uint8_t)((total >> 8) & 0xff);
				hdr[6] = (uint8_t)((total >> 16) & 0xff);
				hdr[7] = (uint8_t)((total >> 24) & 0xff);
				fhdr.x = 0; fhdr.y = 0;
				fhdr.w = (uint16_t)fw; fhdr.h = (uint16_t)fh;
				memcpy(hdr + RDP_BE_HEADER, &fhdr, sizeof fhdr);
				if (rdp_write_full(BE_FD, hdr, sizeof hdr)
				    != sizeof hdr) break;

				for (row = 0; row < fh; row++) {
					const uint8_t *src = pixels
					    + (size_t)row * fstride;
					int col;
					for (col = 0; col < fw; col++) {
						row_buf[col*3+0] = src[col*4+0];
						row_buf[col*3+1] = src[col*4+1];
						row_buf[col*3+2] = src[col*4+2];
					}
					if (rdp_write_full(BE_FD, row_buf,
					    (size_t)fw * 3) != (ssize_t)fw * 3)
						goto wl_out;
				}
			}
		}
	}

wl_out:
	rdp_info("Wayland session shutting down");
	free(row_buf);
	rdp_wl_comp_destroy(wl);
	return 0;
}
#endif /* HAVE_WLROOTS */

static void
usage(const char *prog)
{
	(void)fprintf(stderr,
"usage: %s [-D] [-W] [-w width] [-H height] [-k lcid] [-z tz]\n"
"  -D     use native DDX driver instead of Xvfb\n"
"  -W     use Wayland compositor instead of X11\n"
"  -w n   desktop width  (default 1024)\n"
"  -H n   desktop height (default 768)\n"
"  -k id  client keyboard layout id (LCID; 0 = us)\n"
"  -z tz  client POSIX TZ string for the session clock\n"
"\n"
"File descriptor 3 must be a SOCK_STREAM socket to the rdpd worker;\n"
"rdp-sessionmgr sets this up on SPAWN.\n",
		prog);
}

/* Set the Xvfb keyboard layout for the client's LCID via setxkbmap.
 * Best-effort: on failure the session keeps the default us layout.
 * Must run before uni_init_spares snapshots the keymap. */
static void
set_keymap(int display_num, uint32_t lcid)
{
	const char *layout = NULL, *variant = NULL;
	struct sigaction dfl, old;
	char disp[16];
	pid_t pid;
	int status = -1, restore = 0;

	rdp_klid_to_xkb(lcid, &layout, &variant);
	(void)snprintf(disp, sizeof disp, ":%d", display_num);

	/* The process-wide SIGCHLD handler uses SA_NOCLDWAIT, under which
	 * waitpid blocks until the child exits but cannot return its status.
	 * Reap this one child with the default disposition so we can report
	 * whether setxkbmap actually succeeded, then restore the handler. */
	memset(&dfl, 0, sizeof dfl);
	dfl.sa_handler = SIG_DFL;
	if (sigaction(SIGCHLD, &dfl, &old) == 0)
		restore = 1;

	pid = fork();
	if (pid < 0) {
		rdp_warn("setxkbmap: fork: %s", strerror(errno));
	} else if (pid == 0) {
		if (variant != NULL)
			execlp("setxkbmap", "setxkbmap", "-display", disp,
				"-layout", layout, "-variant", variant,
				(char *)NULL);
		else
			execlp("setxkbmap", "setxkbmap", "-display", disp,
				"-layout", layout, (char *)NULL);
		_exit(127);
	} else {
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			rdp_info("keyboard layout: LCID 0x%x -> %s",
				(unsigned)lcid, layout);
		else
			rdp_warn("setxkbmap %s failed; keeping us layout",
				layout);
	}
	if (restore)
		(void)sigaction(SIGCHLD, &old, NULL);
}

int
main(int argc, char *argv[])
{
	int w = 1024, h = 768;
	int opt, use_ddx = 0, use_wayland = 0;
	int display_num;
	unsigned long lcid = 0;
	char client_tz[64] = "";
	pid_t xvfb_pid, xterm_pid;
	Display *dpy;
	struct cap cap;
	uint8_t *frame_buf;
	struct timespec last_send = {0, 0};
	struct rdp_log_cfg lc;
	Damage dmg = None;
	int damage_event = 0, damage_error = 0, dirty = 1;
	int cursor_dirty = 1;
	/* RAIL single-window fallback: Xvfb cannot do real per-window RAIL,
	 * so a RemoteApp client is shown the whole desktop as one seamless
	 * window.  Set once a create was sent so we send the matching delete
	 * on teardown. */
	int rail_window_sent = 0;

	while ((opt = getopt(argc, argv, "DWw:H:k:z:?")) != -1) {
		switch (opt) {
		case 'D': use_ddx = 1; break;
		case 'W': use_wayland = 1; break;
		case 'w': w = atoi(optarg); break;
		case 'H': h = atoi(optarg); break;
		case 'k': lcid = strtoul(optarg, NULL, 10); break;
		case 'z':
			(void)snprintf(client_tz, sizeof client_tz,
				"%s", optarg);
			break;
		case '?': default: usage(argv[0]); return 1;
		}
	}

	/* Apply the client's time zone to this process before any session
	 * child is forked, so the spawned shell, X clients, and our own log
	 * timestamps all run in the client's local time.  Inherited by every
	 * later fork; an empty string keeps the server's zone. */
	if (client_tz[0] != '\0') {
		(void)setenv("TZ", client_tz, 1);
		tzset();
	}
	if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
		(void)fprintf(stderr, "rdp-session: bad geometry %dx%d\n", w, h);
		return 1;
	}

	memset(&lc, 0, sizeof lc);
	lc.ident = "rdp-session";
	lc.foreground = 1;
	lc.level = RDP_LOG_DEBUG;
	rdp_log_init(&lc);

	install_signals();

	if (use_wayland) {
#if HAVE_WLROOTS
		int rc = run_wayland_mode(w, h);
		rdp_log_close();
		return rc;
#else
		rdp_err("rdp-session: built without Wayland support");
		rdp_log_close();
		return 1;
#endif
	}

	if (use_ddx) {
		int rc = run_ddx_mode(w, h);
		rdp_log_close();
		return rc;
	}

	display_num = find_free_display();
	if (display_num < 0) {
		rdp_err("no free X display in range :100-:200");
		return 1;
	}
	rdp_info("using display :%d (geometry %dx%d)", display_num, w, h);

	xvfb_pid = spawn_xvfb(display_num, w, h);
	if (xvfb_pid < 0) {
		rdp_err("spawn Xvfb: %s", strerror(errno));
		return 1;
	}
	if (wait_for_x_socket(display_num, 5000) != 0) {
		rdp_err("Xvfb didn't come up");
		(void)kill(xvfb_pid, SIGTERM);
		return 1;
	}

	{
		char buf[16];
		(void)snprintf(buf, sizeof buf, ":%d", display_num);
		setenv("DISPLAY", buf, 1);
	}

	dpy = XOpenDisplay(NULL);
	if (dpy == NULL) {
		rdp_err("XOpenDisplay");
		(void)kill(xvfb_pid, SIGTERM);
		return 1;
	}
	/* Apply the client's keyboard layout before scanning for spare
	 * keycodes, since setxkbmap rewrites the whole map. */
	set_keymap(display_num, (uint32_t)lcid);
	XSync(dpy, False);
	uni_init_spares(dpy);

	/* Resize the Xvfb desktop from 3840x2160 down to the client's
	 * requested size via RANDR. */
	{
		char cmd[256];
		(void)snprintf(cmd, sizeof cmd,
			"xrandr --newmode \"%dx%d\" 0 %d %d %d %d %d %d %d %d 2>/dev/null; "
			"xrandr --addmode screen %dx%d 2>/dev/null; "
			"xrandr --output screen --mode %dx%d 2>/dev/null",
			w, h, w, w, w, w, h, h, h, h, w, h, w, h);
		(void)system(cmd);
	}

	if (capture_init(&cap, dpy, w, h) != 0) {
		rdp_err("capture_init");
		XCloseDisplay(dpy);
		(void)kill(xvfb_pid, SIGTERM);
		return 1;
	}

	if (XDamageQueryExtension(dpy, &damage_event, &damage_error)) {
		dmg = XDamageCreate(dpy, DefaultRootWindow(dpy),
		    XDamageReportRawRectangles);
		if (dmg != None)
			rdp_info("XDamage tracking enabled");
		else
			rdp_info("XDamageCreate failed; full-frame capture");
	} else {
		rdp_info("XDamage unavailable; full-frame capture");
	}

	int xfixes_event = 0, xfixes_error = 0, xfixes_ok = 0;
	if (XFixesQueryExtension(dpy, &xfixes_event, &xfixes_error)) {
		XFixesSelectCursorInput(dpy, DefaultRootWindow(dpy),
		    XFixesDisplayCursorNotifyMask);
		xfixes_ok = 1;
		rdp_info("XFixes cursor tracking enabled");
	}

	struct rdp_clip clip;
	int clip_ok = (rdp_clip_init(&clip, dpy, BE_FD) == 0);

	frame_buf = malloc((size_t)w * h * 3);
	if (frame_buf == NULL) {
		rdp_err("malloc frame_buf");
		capture_close(&cap);
		XCloseDisplay(dpy);
		(void)kill(xvfb_pid, SIGTERM);
		return 1;
	}

	struct rdp_h264 *h264 = NULL;
	if (h264 != NULL)
		rdp_info("session H.264 encoder active (%dx%d)", w, h);
	else
		rdp_info("session H.264 encoder unavailable; raw frames");

	/* Greet the worker with our mode. */
	{
		int sndbuf = 2 * 1024 * 1024;
		(void)setsockopt(BE_FD, SOL_SOCKET, SO_SNDBUF,
			&sndbuf, sizeof sndbuf);
	}
	{
		struct rdp_be_hello hello = { (uint16_t)w, (uint16_t)h, 24, 0 };
		if (rdp_be_send(BE_FD, RDP_BE_HELLO_S2W,
			&hello, sizeof hello) != 0)
			rdp_err("HELLO send failed: %s", strerror(errno));
	}
	{
		char rtdir[64];
		(void)snprintf(rtdir, sizeof rtdir, "/run/user/%u",
			(unsigned)getuid());
		(void)mkdir(rtdir, 0700);
		(void)setenv("XDG_RUNTIME_DIR", rtdir, 1);
	}
	{
		pid_t pa = fork();
		if (pa == 0) {
			execlp("pulseaudio", "pulseaudio",
				"--start", "--exit-idle-time=-1",
				(char *)NULL);
			_exit(0);
		}
		if (pa > 0) {
			int st;
			(void)waitpid(pa, &st, 0);
		}
	}

	xterm_pid = spawn_xterm();
	if (xterm_pid < 0)
		rdp_warn("spawn xterm: %s", strerror(errno));

	/* Now that Xvfb is up and xterm spawned, drop privileges to the
	 * minimum: X11 socket (`unix`), SHM ipc, signals to children
	 * (`proc`), and reading our own files.  We still need `proc`
	 * for kill() on the children at shutdown.  On non-OpenBSD this
	 * compiles to a no-op. */
	/* `exec` is needed to fork+exec lpadmin for printer redirection (and
	 * the xrandr resize helper); on non-OpenBSD this is a no-op. */
	if (pledge("stdio rpath wpath cpath unix proc exec", NULL) != 0)
		rdp_warn("pledge session: %s", strerror(errno));

	struct rdp_audio *audio = rdp_audio_open();
	uint8_t *audio_buf = NULL;
	if (audio != NULL) {
		audio_buf = malloc(17640);
		rdp_info("audio capture active");
	}

	/* Microphone redirection: present the client's captured PCM (arriving
	 * as RDP_BE_AUDIO_INPUT) as a PulseAudio capture source.  Best effort:
	 * a failure here leaves the module inert and never breaks the session. */
	struct rdp_mic *mic = rdp_mic_open();

	/* Probe the inherited fd 4 for an RDPDR drive FUSE mount.  Returns
	 * NULL on non-Linux builds, old kernels, or when sessionmgr did not
	 * set up a mount, in which case the session runs without drives. */
	struct fuse_drive *drive = fuse_drive_init(FUSE_FD, BE_FD);
#if !HAVE_OBSD_FUSE
	int drive_fd = fuse_drive_fd(drive);
#endif

	/* Printer redirection: one AF_UNIX listener serves the custom CUPS
	 * backend.  Best effort: a failure here leaves the module inert and
	 * never breaks the session. */
	struct rdp_printer printer;
	(void)rdp_printer_init(&printer, BE_FD);

	while (!want_shutdown) {
		/* Fixed slots 0..2 (backend, X, optional fuse) plus the
		 * printer listener and its accepted backend connections. */
		struct pollfd pfd[3 + 1 + RDP_PRINTER_MAX_CONNS];
		int npfd = 2;
		int printer_base;
		int xfd = ConnectionNumber(dpy);
		struct timespec now;
		long elapsed_ms;

		pfd[0].fd = BE_FD;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = xfd;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
#if !HAVE_OBSD_FUSE
		/* On Linux the /dev/fuse fd is pollable, so wait on it for
		 * prompt wakeups.  On OpenBSD the fusefs device has no d_poll
		 * (poll() would busy-spin via seltrue), so it is left out of
		 * the poll set and serviced on every frame-interval wakeup
		 * below, where the backend self-gates with a kqueue probe. */
		if (drive_fd >= 0) {
			pfd[2].fd = drive_fd;
			pfd[2].events = POLLIN;
			pfd[2].revents = 0;
			npfd = 3;
		}
#endif

		printer_base = npfd;
		(void)rdp_printer_fill_pollfds(&printer, pfd, &npfd,
		    (int)(sizeof pfd / sizeof pfd[0]));

		(void)poll(pfd, (nfds_t)npfd, FRAME_INTERVAL_MS);

		rdp_printer_service(&printer, pfd + printer_base,
		    npfd - printer_base);

		if (pfd[0].revents & POLLIN) {
			uint32_t type;
			uint8_t *buf = be_recv_buf;
			ssize_t n = rdp_be_recv(BE_FD, &type, buf,
				sizeof be_recv_buf);
			if (n < 0) break;
			if (n == 0) break;
			if (type == RDP_BE_INPUT_KEY
			    && n >= (ssize_t)sizeof(struct rdp_be_input_key)) {
				struct rdp_be_input_key k;
				memcpy(&k, buf, sizeof k);
				(void)inject_key(dpy, &k);
			} else if (type == RDP_BE_INPUT_MOUSE
			    && n >= (ssize_t)sizeof(struct rdp_be_input_mouse)) {
				struct rdp_be_input_mouse m;
				memcpy(&m, buf, sizeof m);
				(void)inject_mouse(dpy, &m);
			} else if (type == RDP_BE_INPUT_TOUCH
			    && n >= (ssize_t)sizeof(struct rdp_be_input_touch)) {
				(void)inject_touch(dpy, buf, (size_t)n);
			} else if (type == RDP_BE_INPUT_UNICODE
			    && n >= (ssize_t)sizeof(struct rdp_be_input_unicode)) {
				struct rdp_be_input_unicode u;
				memcpy(&u, buf, sizeof u);
				(void)inject_unicode(dpy, &u);
			} else if (type == RDP_BE_INPUT_SYNC
			    && n >= (ssize_t)sizeof(struct rdp_be_input_sync)) {
				struct rdp_be_input_sync s;
				memcpy(&s, buf, sizeof s);
				(void)inject_sync(dpy, &s);
			} else if (type == RDP_BE_CLIP_OFFER
			    || type == RDP_BE_CLIP_REQUEST
			    || type == RDP_BE_CLIP_DATA
			    || type == RDP_BE_CLIP_FILE_REQUEST
			    || type == RDP_BE_CLIP_FILE_DATA) {
				if (clip_ok)
					rdp_clip_handle_be_msg(&clip, type,
						buf, (size_t)n);
			} else if (type == RDP_BE_RESIZE
			    && n >= (ssize_t)sizeof(struct rdp_be_resize)) {
				struct rdp_be_resize rs;
				memcpy(&rs, buf, sizeof rs);
				if (rs.width >= 200 && rs.height >= 200
				    && rs.width <= 3840 && rs.height <= 2160) {
					char cmd[256];
					rdp_info("resize: %ux%u -> %ux%u",
						(unsigned)w, (unsigned)h,
						(unsigned)rs.width,
						(unsigned)rs.height);
					w = rs.width;
					h = rs.height;
					(void)snprintf(cmd, sizeof cmd,
						"xrandr --newmode \"%dx%d\" 0 "
						"%d %d %d %d %d %d %d %d 2>/dev/null; "
						"xrandr --addmode screen %dx%d 2>/dev/null; "
						"xrandr --output screen --mode %dx%d 2>/dev/null",
						w, h, w, w, w, w, h, h, h, h,
						w, h, w, h);
					(void)system(cmd);
					capture_close(&cap);
					(void)capture_init(&cap, dpy, w, h);
					if (dmg != None) {
						XDamageDestroy(dpy, dmg);
						dmg = XDamageCreate(dpy,
						    DefaultRootWindow(dpy),
						    XDamageReportRawRectangles);
					}
					dirty = 1;
					free(frame_buf);
					frame_buf = malloc((size_t)w * h * 3);
					if (frame_buf == NULL) break;
					if (h264 != NULL)
						(void)rdp_h264_resize(h264,
						    w, h);
				}
			} else if (type == RDP_BE_FS_DEVICE
			    && n >= (ssize_t)sizeof(struct rdp_be_fs_device)) {
				struct rdp_be_fs_device fsd;
				memcpy(&fsd, buf, sizeof fsd);
				fsd.name[sizeof fsd.name - 1] = '\0';
				fuse_drive_add_device(drive, fsd.device_id,
				    fsd.device_type, fsd.name, fsd.added);
			} else if (type == RDP_BE_FS_RSP
			    && n >= (ssize_t)sizeof(struct rdp_be_fs_rsp)) {
				struct rdp_be_fs_rsp rsp;
				memcpy(&rsp, buf, sizeof rsp);
				fuse_drive_handle_fs_rsp(drive, &rsp,
				    buf + sizeof rsp,
				    (size_t)n - sizeof rsp);
			} else if (type == RDP_BE_PRINTER_DEVICE
			    && n >= (ssize_t)sizeof(struct rdp_be_printer_device)) {
				rdp_printer_handle_device(&printer, buf,
				    (size_t)n);
			} else if (type == RDP_BE_AUDIO_INPUT) {
				rdp_mic_write(mic, buf, (size_t)n);
			} else if (type == RDP_BE_RAIL
			    && n >= (ssize_t)sizeof(struct rdp_be_rail)) {
				/* Single-window RAIL fallback: Xvfb has no real
				 * per-window geometry, so report the whole
				 * desktop as one window so a RemoteApp client
				 * still shows the session seamlessly. */
				struct rdp_be_rail rl;
				memcpy(&rl, buf, sizeof rl);
				if (!rail_window_sent) {
					send_window_event(RDP_BE_WINDOW_OP_CREATE,
					    1, 0, 0, rl.width, rl.height,
					    "RemoteApp");
					rail_window_sent = 1;
				}
			} else if (type == RDP_BE_BYE) {
				break;
			}
		}
#if HAVE_OBSD_FUSE
		/* OpenBSD: the fuse fd is not in the poll set (poll is useless
		 * there), so service it on every wakeup.  fuse_drive_process
		 * self-gates with a non-blocking kqueue probe, so this is cheap
		 * when nothing is queued and never blocks the loop. */
		if (drive != NULL) {
			if (fuse_drive_process(drive) < 0)
				drive = NULL;   /* mount gone: stop servicing it */
		}
#else
		if (drive_fd >= 0 && (pfd[2].revents & POLLIN)) {
			if (fuse_drive_process(drive) < 0) {
				/* The mount went away: stop polling the fd. */
				drive_fd = -1;
			}
		}
#endif
		if (pfd[1].revents & POLLIN) {
			while (XPending(dpy) > 0) {
				XEvent ev;
				XNextEvent(dpy, &ev);
				if (dmg != None
				    && ev.type == damage_event + XDamageNotify)
					dirty = 1;
				else if (xfixes_ok
				    && ev.type == xfixes_event + XFixesCursorNotify)
					cursor_dirty = 1;
				else if (clip_ok)
					(void)rdp_clip_handle_xevent(&clip, &ev);
			}
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - last_send.tv_sec) * 1000
			+ (now.tv_nsec - last_send.tv_nsec) / 1000000;
		if (elapsed_ms >= FRAME_INTERVAL_MS && dirty) {
			if (capture_grab(&cap, frame_buf) == 0) {
				if (h264 != NULL) {
					const uint8_t *enc;
					size_t enc_len;
					int kf;
					if (rdp_h264_encode(h264, frame_buf,
					    w, h, &enc, &enc_len, &kf) == 0
					    && enc != NULL && enc_len > 0) {
						if (send_h264_frame(BE_FD, w, h,
						    enc, enc_len) != 0) {
							rdp_err("h264 frame send failed: %s",
								strerror(errno));
							break;
						}
					}
				} else {
					if (send_frame(BE_FD, w, h,
					    frame_buf) != 0)
						break;
				}
			}
			if (dmg != None) {
				XDamageSubtract(dpy, dmg, None, None);
				dirty = 0;
			}
			last_send = now;
		}
		/* Forward the real X cursor only on a change frame, gated by
		 * the same cadence so animated cursors cannot flood the link.
		 * XFixesGetCursorImage is never called per video frame. */
		if (xfixes_ok && cursor_dirty
		    && elapsed_ms >= FRAME_INTERVAL_MS) {
			XFixesCursorImage *ci = XFixesGetCursorImage(dpy);
			if (ci) {
				(void)send_cursor(BE_FD, ci);
				XFree(ci);
			}
			cursor_dirty = 0;
		}
		if (audio != NULL && audio_buf != NULL) {
			ssize_t ar = rdp_audio_read(audio, audio_buf, 17640);
			if (ar > 0)
				(void)rdp_be_send(BE_FD, RDP_BE_AUDIO,
				    audio_buf, (size_t)ar);
		}
	}

	rdp_info("rdp-session shutting down");
	/* Tear down the single-window RAIL fallback so the client removes the
	 * seamless window cleanly. */
	if (rail_window_sent)
		send_window_event(RDP_BE_WINDOW_OP_DELETE, 1, 0, 0, 0, 0, NULL);
	rdp_printer_close(&printer);
	fuse_drive_free(drive);
	rdp_h264_close(h264);
	rdp_audio_close(audio);
	rdp_mic_close(mic);
	free(audio_buf);
	if (clip_ok) rdp_clip_close(&clip);
	free(frame_buf);
	if (dmg != None) XDamageDestroy(dpy, dmg);
	capture_close(&cap);
	XCloseDisplay(dpy);
	if (xterm_pid > 0) (void)kill(xterm_pid, SIGTERM);
	(void)kill(xvfb_pid, SIGTERM);
	(void)waitpid(xvfb_pid, NULL, 0);
	rdp_log_close();
	return 0;
}
