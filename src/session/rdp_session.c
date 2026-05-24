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
 *   - no XDamage; we always push the whole frame
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

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>
#include <X11/extensions/XTest.h>

#include "clip_x11.h"
#include "audio.h"

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
#define FRAME_INTERVAL_MS 200

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
		/* Try xterm; if it's missing, fall back to xclock to at
		 * least have something on the root window. */
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
			static uint8_t buf[0x10000];
			ssize_t n = rdp_be_recv(BE_FD, &type, buf, sizeof buf);
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
			ssize_t r = rdp_read_full(sv[0], mhdr, sizeof mhdr);
			if (r <= 0) break;
			uint32_t mtype = (uint32_t)mhdr[0]
			    | ((uint32_t)mhdr[1] << 8);
			uint32_t mlen = (uint32_t)mhdr[4]
			    | ((uint32_t)mhdr[5] << 8)
			    | ((uint32_t)mhdr[6] << 16)
			    | ((uint32_t)mhdr[7] << 24);

			if (mtype == DDX_MSG_SHM_READY
			    && mlen >= sizeof(struct ddx_shm_ready)) {
				int new_fd = -1;
				struct ddx_shm_ready sr;
				struct msghdr msg;
				struct iovec iov;
				char cbuf[CMSG_SPACE(sizeof(int))];
				struct cmsghdr *cmsg;
				ssize_t rr;

				memset(&msg, 0, sizeof msg);
				iov.iov_base = &sr;
				iov.iov_len = sizeof sr;
				msg.msg_iov = &iov;
				msg.msg_iovlen = 1;
				memset(cbuf, 0, sizeof cbuf);
				msg.msg_control = cbuf;
				msg.msg_controllen = sizeof cbuf;
				do { rr = recvmsg(sv[0], &msg, 0); }
				while (rr < 0 && errno == EINTR);
				if (rr >= (ssize_t)sizeof sr) {
					for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
					     cmsg = CMSG_NXTHDR(&msg, cmsg))
						if (cmsg->cmsg_level == SOL_SOCKET
						    && cmsg->cmsg_type == SCM_RIGHTS)
							memcpy(&new_fd, CMSG_DATA(cmsg),
							    sizeof(int));
					if (new_fd >= 0) {
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
							free(row_buf);
							row_buf = malloc((size_t)fb_w * 3);
							rdp_info("DDX resize: %ux%u",
							    (unsigned)fb_w, (unsigned)fb_h);
							struct rdp_be_hello hello = {
							    fb_w, fb_h, 24, 0};
							(void)rdp_be_send(BE_FD,
							    RDP_BE_HELLO_S2W,
							    &hello, sizeof hello);
						} else {
							close(new_fd);
						}
					}
				}
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

static void
usage(const char *prog)
{
	(void)fprintf(stderr,
"usage: %s [-D] [-w width] [-H height]\n"
"  -D     use native DDX driver instead of Xvfb\n"
"  -w n   desktop width  (default 1024)\n"
"  -H n   desktop height (default 768)\n"
"\n"
"File descriptor 3 must be a SOCK_STREAM socket to the rdpd worker;\n"
"rdp-sessionmgr sets this up on SPAWN.\n",
		prog);
}

int
main(int argc, char *argv[])
{
	int w = 1024, h = 768;
	int opt, use_ddx = 0;
	int display_num;
	pid_t xvfb_pid, xterm_pid;
	Display *dpy;
	struct cap cap;
	uint8_t *frame_buf;
	struct timespec last_send = {0, 0};
	struct rdp_log_cfg lc;

	while ((opt = getopt(argc, argv, "Dw:H:?")) != -1) {
		switch (opt) {
		case 'D': use_ddx = 1; break;
		case 'w': w = atoi(optarg); break;
		case 'H': h = atoi(optarg); break;
		case '?': default: usage(argv[0]); return 1;
		}
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

	/* Greet the worker with our mode. */
	{
		struct rdp_be_hello hello = { (uint16_t)w, (uint16_t)h, 24, 0 };
		if (rdp_be_send(BE_FD, RDP_BE_HELLO_S2W,
			&hello, sizeof hello) != 0)
			rdp_err("HELLO send failed: %s", strerror(errno));
	}

	xterm_pid = spawn_xterm();
	if (xterm_pid < 0)
		rdp_warn("spawn xterm: %s", strerror(errno));

	/* Now that Xvfb is up and xterm spawned, drop privileges to the
	 * minimum: X11 socket (`unix`), SHM ipc, signals to children
	 * (`proc`), and reading our own files.  We still need `proc`
	 * for kill() on the children at shutdown.  On non-OpenBSD this
	 * compiles to a no-op. */
	if (pledge("stdio rpath wpath cpath unix proc", NULL) != 0)
		rdp_warn("pledge session: %s", strerror(errno));

	struct rdp_audio *audio = rdp_audio_open();
	uint8_t *audio_buf = NULL;
	if (audio != NULL) {
		audio_buf = malloc(17640);
		rdp_info("audio capture active");
	}

	while (!want_shutdown) {
		struct pollfd pfd[2];
		int xfd = ConnectionNumber(dpy);
		struct timespec now;
		long elapsed_ms;

		pfd[0].fd = BE_FD;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = xfd;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;

		(void)poll(pfd, 2, FRAME_INTERVAL_MS);

		if (pfd[0].revents & POLLIN) {
			uint32_t type;
			static uint8_t buf[0x10000];
			ssize_t n = rdp_be_recv(BE_FD, &type, buf, sizeof buf);
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
			} else if (type == RDP_BE_CLIP_OFFER
			    || type == RDP_BE_CLIP_REQUEST
			    || type == RDP_BE_CLIP_DATA) {
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
					free(frame_buf);
					frame_buf = malloc((size_t)w * h * 3);
					if (frame_buf == NULL) break;
				}
			} else if (type == RDP_BE_BYE) {
				break;
			}
		}
		if (pfd[1].revents & POLLIN) {
			while (XPending(dpy) > 0) {
				XEvent ev;
				XNextEvent(dpy, &ev);
				if (clip_ok)
					(void)rdp_clip_handle_xevent(&clip, &ev);
			}
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - last_send.tv_sec) * 1000
			+ (now.tv_nsec - last_send.tv_nsec) / 1000000;
		if (elapsed_ms >= FRAME_INTERVAL_MS) {
			if (capture_grab(&cap, frame_buf) == 0) {
				if (send_frame(BE_FD, w, h, frame_buf) != 0)
					break;
			}
			last_send = now;
		}
		if (audio != NULL && audio_buf != NULL) {
			ssize_t ar = rdp_audio_read(audio, audio_buf, 17640);
			if (ar > 0)
				(void)rdp_be_send(BE_FD, RDP_BE_AUDIO,
				    audio_buf, (size_t)ar);
		}
	}

	rdp_info("rdp-session shutting down");
	rdp_audio_close(audio);
	free(audio_buf);
	if (clip_ok) rdp_clip_close(&clip);
	free(frame_buf);
	capture_close(&cap);
	XCloseDisplay(dpy);
	if (xterm_pid > 0) (void)kill(xterm_pid, SIGTERM);
	(void)kill(xvfb_pid, SIGTERM);
	(void)waitpid(xvfb_pid, NULL, 0);
	rdp_log_close();
	return 0;
}
