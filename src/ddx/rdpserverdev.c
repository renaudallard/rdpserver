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
 * rdpserverdev.c -- native Xorg DDX video driver for rdpserver.
 *
 * Renders to a POSIX shared-memory framebuffer and reports damage
 * regions to rdp-session via a control socket.  Replaces the
 * Xvfb + XShmGetImage capture path with zero-copy, damage-aware
 * frame delivery.
 */

#include "rdpserverdev.h"
#include "ddx_proto.h"

#include <xf86.h>
#include <xf86str.h>
#include <xf86Crtc.h>
#include <xf86Xinput.h>
#include <mipointer.h>
#include <micmap.h>
#include <mi.h>
#include <fb.h>
#include <damage.h>
#include <damagestr.h>
#include <input.h>
#include <inputstr.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static DevPrivateKeyRec rdpserver_screen_key;

struct rdpserver_dev *
rdpserver_dev_from_screen(ScreenPtr pScreen)
{
	return dixLookupPrivate(&pScreen->devPrivates, &rdpserver_screen_key);
}

/* Minimal sprite functions (cursor is handled by rdp-session). */
static Bool sprite_realize(DeviceIntPtr d, ScreenPtr s, CursorPtr c)
{ (void)d; (void)s; (void)c; return TRUE; }

static Bool sprite_unrealize(DeviceIntPtr d, ScreenPtr s, CursorPtr c)
{ (void)d; (void)s; (void)c; return TRUE; }

static void sprite_set(DeviceIntPtr d, ScreenPtr s, CursorPtr c,
    int x, int y)
{ (void)d; (void)s; (void)c; (void)x; (void)y; }

static void sprite_move(DeviceIntPtr d, ScreenPtr s, int x, int y)
{ (void)d; (void)s; (void)x; (void)y; }

static Bool sprite_dev_init(DeviceIntPtr d, ScreenPtr s)
{ (void)d; (void)s; return TRUE; }

static void sprite_dev_cleanup(DeviceIntPtr d, ScreenPtr s)
{ (void)d; (void)s; }

static miPointerSpriteFuncRec sprite_funcs = {
	sprite_realize,
	sprite_unrealize,
	sprite_set,
	sprite_move,
	sprite_dev_init,
	sprite_dev_cleanup
};

/* Minimal screen pointer functions. */
static Bool cursor_offscreen(ScreenPtr *s, int *x, int *y)
{ (void)s; (void)x; (void)y; return FALSE; }

static void cursor_cross(ScreenPtr s, Bool entering)
{ (void)s; (void)entering; }

static void cursor_warp(DeviceIntPtr d, ScreenPtr s, int x, int y)
{ (void)d; (void)s; (void)x; (void)y; }

static miPointerScreenFuncRec screen_cursor_funcs = {
	cursor_offscreen,
	cursor_cross,
	cursor_warp
};

static int
alloc_framebuffer(struct rdpserver_dev *dev, int w, int h)
{
	int fd;
	size_t sz;
	void *ptr;
	char name[64];

	dev->stride = w * 4;
	sz = (size_t)dev->stride * h;

	snprintf(name, sizeof name, "/rdpserver-%d", (int)getpid());
	fd = shm_open(name, O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		return -1;
	shm_unlink(name);
	if (ftruncate(fd, (off_t)sz) != 0) {
		close(fd);
		return -1;
	}
	ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		close(fd);
		return -1;
	}
	memset(ptr, 0, sz);

	if (dev->fb != NULL)
		munmap(dev->fb, dev->shm_size);
	if (dev->shm_fd >= 0)
		close(dev->shm_fd);

	dev->fb = ptr;
	dev->shm_fd = fd;
	dev->shm_size = sz;
	dev->width = w;
	dev->height = h;
	return 0;
}

static void
free_framebuffer(struct rdpserver_dev *dev)
{
	if (dev->fb != NULL) {
		munmap(dev->fb, dev->shm_size);
		dev->fb = NULL;
	}
	if (dev->shm_fd >= 0) {
		close(dev->shm_fd);
		dev->shm_fd = -1;
	}
}

static ssize_t
ctrl_write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t off = 0;
	while (off < len) {
		ssize_t r = write(fd, p + off, len - off);
		if (r < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		off += (size_t)r;
	}
	return (ssize_t)off;
}

static int
ctrl_send_msg(int fd, uint32_t type, const void *payload, uint32_t len)
{
	uint8_t hdr[DDX_PROTO_HEADER];
	hdr[0] = (uint8_t)(type & 0xff);
	hdr[1] = (uint8_t)((type >> 8) & 0xff);
	hdr[2] = (uint8_t)((type >> 16) & 0xff);
	hdr[3] = (uint8_t)((type >> 24) & 0xff);
	hdr[4] = (uint8_t)(len & 0xff);
	hdr[5] = (uint8_t)((len >> 8) & 0xff);
	hdr[6] = (uint8_t)((len >> 16) & 0xff);
	hdr[7] = (uint8_t)((len >> 24) & 0xff);
	if (ctrl_write_full(fd, hdr, sizeof hdr) < 0) return -1;
	if (len > 0 && ctrl_write_full(fd, payload, len) < 0) return -1;
	return 0;
}

static int
ctrl_send_shm_ready(int ctrl_fd, int shm_fd,
    uint16_t w, uint16_t h, uint32_t stride, uint32_t sz)
{
	struct ddx_shm_ready sr;
	struct msghdr msg;
	struct iovec iov[2];
	uint8_t hdr[DDX_PROTO_HEADER];
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	uint32_t plen = (uint32_t)sizeof sr;

	sr.width = w;
	sr.height = h;
	sr.stride = stride;
	sr.size = sz;

	hdr[0] = DDX_MSG_SHM_READY & 0xff;
	hdr[1] = hdr[2] = hdr[3] = 0;
	hdr[4] = plen & 0xff;
	hdr[5] = (plen >> 8) & 0xff;
	hdr[6] = hdr[7] = 0;

	memset(&msg, 0, sizeof msg);
	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof hdr;
	iov[1].iov_base = &sr;
	iov[1].iov_len = sizeof sr;
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	memset(cbuf, 0, sizeof cbuf);
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof cbuf;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &shm_fd, sizeof(int));

	{
		ssize_t r;
		do { r = sendmsg(ctrl_fd, &msg, 0); }
		while (r < 0 && errno == EINTR);
		if (r < 0) return -1;
	}
	return 0;
}

static int
ctrl_send_damage(int ctrl_fd, RegionPtr region)
{
	int nrects = RegionNumRects(region);
	BoxPtr boxes = RegionRects(region);
	uint8_t buf[DDX_PROTO_HEADER + sizeof(struct ddx_damage_hdr)
	    + 256 * sizeof(struct ddx_damage_rect)];
	struct ddx_damage_hdr *dh;
	struct ddx_damage_rect *dr;
	uint32_t plen;
	int i, send_n;

	if (nrects <= 0) return 0;
	send_n = nrects > 256 ? 256 : nrects;
	plen = (uint32_t)(sizeof(struct ddx_damage_hdr)
	    + (size_t)send_n * sizeof(struct ddx_damage_rect));

	buf[0] = DDX_MSG_DAMAGE & 0xff;
	buf[1] = buf[2] = buf[3] = 0;
	buf[4] = plen & 0xff;
	buf[5] = (plen >> 8) & 0xff;
	buf[6] = (plen >> 16) & 0xff;
	buf[7] = 0;

	dh = (struct ddx_damage_hdr *)(buf + DDX_PROTO_HEADER);
	dh->nrects = (uint16_t)send_n;
	dh->reserved = 0;
	dr = (struct ddx_damage_rect *)(dh + 1);
	for (i = 0; i < send_n; i++) {
		dr[i].x = (int16_t)boxes[i].x1;
		dr[i].y = (int16_t)boxes[i].y1;
		dr[i].w = (int16_t)(boxes[i].x2 - boxes[i].x1);
		dr[i].h = (int16_t)(boxes[i].y2 - boxes[i].y1);
	}
	return ctrl_write_full(ctrl_fd, buf,
	    DDX_PROTO_HEADER + plen) < 0 ? -1 : 0;
}

static void
ctrl_handle_input(struct rdpserver_dev *dev)
{
	uint32_t type, len;
	struct pollfd pfd;

	for (;;) {
		pfd.fd = dev->ctrl_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 0) <= 0) break;
		if (!(pfd.revents & POLLIN)) break;

		while (dev->ctrl_hdr_off < DDX_PROTO_HEADER) {
			ssize_t r = read(dev->ctrl_fd,
			    dev->ctrl_hdr + dev->ctrl_hdr_off,
			    DDX_PROTO_HEADER - dev->ctrl_hdr_off);
			if (r <= 0) return;
			dev->ctrl_hdr_off += (size_t)r;
		}
		dev->ctrl_hdr_off = 0;

		type = (uint32_t)dev->ctrl_hdr[0]
		    | ((uint32_t)dev->ctrl_hdr[1] << 8)
		    | ((uint32_t)dev->ctrl_hdr[2] << 16)
		    | ((uint32_t)dev->ctrl_hdr[3] << 24);
		len = (uint32_t)dev->ctrl_hdr[4]
		    | ((uint32_t)dev->ctrl_hdr[5] << 8)
		    | ((uint32_t)dev->ctrl_hdr[6] << 16)
		    | ((uint32_t)dev->ctrl_hdr[7] << 24);

		if (type == DDX_MSG_INPUT_KEY && len >= sizeof(struct ddx_input_key)) {
			struct ddx_input_key k;
			if (read(dev->ctrl_fd, &k, sizeof k) == sizeof k) {
				int keycode = k.scancode + 8;
				xf86PostKeyboardEvent(inputInfo.keyboard,
				    keycode, k.down);
			}
		} else if (type == DDX_MSG_INPUT_MOUSE && len >= sizeof(struct ddx_input_mouse)) {
			struct ddx_input_mouse m;
			if (read(dev->ctrl_fd, &m, sizeof m) == sizeof m) {
				int buttons = 0;
				xf86PostMotionEvent(inputInfo.pointer, TRUE,
				    0, 2, m.x, m.y);
				if (m.flags & 1) {
					if (m.buttons & 1)
						buttons |= 1;
					if (m.buttons & 2)
						buttons |= 4;
					if (m.buttons & 4)
						buttons |= 2;
					xf86PostButtonEvent(inputInfo.pointer,
					    TRUE, buttons ? buttons : 1,
					    (m.buttons != 0), 0, 0);
				}
			}
		} else if (type == DDX_MSG_RESIZE && len >= sizeof(struct ddx_resize)) {
			struct ddx_resize rs;
			if (read(dev->ctrl_fd, &rs, sizeof rs) == sizeof rs) {
				dev->resize_w = rs.width;
				dev->resize_h = rs.height;
			}
		} else {
			uint8_t skip[256];
			while (len > 0) {
				size_t chunk = len > sizeof skip ? sizeof skip : len;
				ssize_t got = read(dev->ctrl_fd, skip, chunk);
				if (got <= 0) break;
				len -= (uint32_t)got;
			}
		}
	}
}

static Bool
rdpserver_CreateScreenResources(ScreenPtr pScreen)
{
	ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
	struct rdpserver_dev *dev = rdpserver_dev_from_screen(pScreen);
	Bool ret;

	pScreen->CreateScreenResources = dev->saved_CreateScreenResources;
	ret = pScreen->CreateScreenResources(pScreen);
	pScreen->CreateScreenResources = rdpserver_CreateScreenResources;

	if (!ret)
		return FALSE;

	dev->damage = DamageCreate(NULL, NULL, DamageReportNone,
	    TRUE, pScreen, pScreen);
	if (dev->damage != NULL) {
		DamageRegister(&pScreen->GetScreenPixmap(pScreen)->drawable,
		    dev->damage);
		dev->damage_registered = TRUE;
		xf86DrvMsg(pScrn->scrnIndex, X_INFO,
		    "damage tracking registered\n");
	}

	if (dev->ctrl_fd >= 0) {
		if (ctrl_send_shm_ready(dev->ctrl_fd, dev->shm_fd,
		    (uint16_t)dev->width, (uint16_t)dev->height,
		    (uint32_t)dev->stride, (uint32_t)dev->shm_size) == 0)
			xf86DrvMsg(pScrn->scrnIndex, X_INFO,
			    "sent SHM_READY to rdp-session\n");
	}
	return TRUE;
}

static Bool
rdpserver_CloseScreen(ScreenPtr pScreen)
{
	struct rdpserver_dev *dev = rdpserver_dev_from_screen(pScreen);

	if (dev->damage_registered && dev->damage != NULL) {
		DamageUnregister(dev->damage);
		DamageDestroy(dev->damage);
		dev->damage = NULL;
		dev->damage_registered = FALSE;
	}
	free_framebuffer(dev);

	pScreen->CloseScreen = dev->saved_CloseScreen;
	return pScreen->CloseScreen(pScreen);
}

static void
do_resize(ScreenPtr pScreen, struct rdpserver_dev *dev, int new_w, int new_h)
{
	ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
	PixmapPtr rootpix;
	xf86CrtcConfigPtr config;
	DisplayModeRec mode;

	if (new_w < 64 || new_h < 64 || new_w > 8192 || new_h > 8192)
		return;
	if (new_w == dev->width && new_h == dev->height)
		return;

	xf86DrvMsg(pScrn->scrnIndex, X_INFO, "resize %dx%d -> %dx%d\n",
	    dev->width, dev->height, new_w, new_h);

	if (dev->damage_registered && dev->damage != NULL) {
		DamageUnregister(dev->damage);
		dev->damage_registered = FALSE;
	}

	if (alloc_framebuffer(dev, new_w, new_h) != 0) {
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		    "resize framebuffer alloc failed\n");
		return;
	}

	pScrn->virtualX = new_w;
	pScrn->virtualY = new_h;

	rootpix = pScreen->GetScreenPixmap(pScreen);
	pScreen->ModifyPixmapHeader(rootpix, new_w, new_h,
	    -1, -1, dev->stride, dev->fb);

	pScreen->width = new_w;
	pScreen->height = new_h;
	pScreen->mmWidth = new_w * 254 / 960;
	pScreen->mmHeight = new_h * 254 / 960;

	memset(&mode, 0, sizeof mode);
	mode.HDisplay = new_w;
	mode.VDisplay = new_h;

	config = XF86_CRTC_CONFIG_PTR(pScrn);
	if (config != NULL && config->num_crtc > 0) {
		xf86CrtcPtr crtc = config->crtc[0];
		crtc->mode = mode;
		crtc->x = 0;
		crtc->y = 0;
	}

	if (dev->damage != NULL) {
		DamageRegister(&rootpix->drawable, dev->damage);
		dev->damage_registered = TRUE;
	}

	RRScreenSizeNotify(pScreen);
	RRTellChanged(pScreen);

	if (dev->ctrl_fd >= 0)
		ctrl_send_shm_ready(dev->ctrl_fd, dev->shm_fd,
		    (uint16_t)new_w, (uint16_t)new_h,
		    (uint32_t)dev->stride, (uint32_t)dev->shm_size);
}

static void
rdpserver_BlockHandler(ScreenPtr pScreen, void *timeout)
{
	struct rdpserver_dev *dev = rdpserver_dev_from_screen(pScreen);
	(void)timeout;

	if (dev->resize_w > 0 && dev->resize_h > 0) {
		int rw = dev->resize_w, rh = dev->resize_h;
		dev->resize_w = 0;
		dev->resize_h = 0;
		do_resize(pScreen, dev, rw, rh);
	}

	if (dev->damage != NULL && dev->damage_registered) {
		RegionPtr region = DamageRegion(dev->damage);
		if (RegionNotEmpty(region) && dev->ctrl_fd >= 0)
			ctrl_send_damage(dev->ctrl_fd, region);
		DamageEmpty(dev->damage);
	}
}

static void
rdpserver_WakeupHandler(ScreenPtr pScreen, int result)
{
	struct rdpserver_dev *dev = rdpserver_dev_from_screen(pScreen);
	(void)result;

	if (dev->ctrl_fd >= 0)
		ctrl_handle_input(dev);
}

static Bool
rdpserver_ScreenInit(ScreenPtr pScreen, int argc, char **argv)
{
	ScrnInfoPtr pScrn = xf86ScreenToScrn(pScreen);
	struct rdpserver_dev *dev;
	VisualPtr visual;
	int w, h;
	(void)argc;
	(void)argv;

	xf86DrvMsg(pScrn->scrnIndex, X_INFO, "entering ScreenInit\n");

	dev = calloc(1, sizeof *dev);
	if (dev == NULL)
		return FALSE;
	dev->shm_fd = -1;
	dev->ctrl_fd = -1;

	{
		const char *env_ctrl = getenv("RDPSERVER_CTRL_FD");
		if (env_ctrl != NULL) {
			dev->ctrl_fd = atoi(env_ctrl);
			int fl = fcntl(dev->ctrl_fd, F_GETFL);
			if (fl >= 0)
				fcntl(dev->ctrl_fd, F_SETFL, fl | O_NONBLOCK);
		}
	}

	if (!dixRegisterPrivateKey(&rdpserver_screen_key, PRIVATE_SCREEN, 0))
		return FALSE;
	dixSetPrivate(&pScreen->devPrivates, &rdpserver_screen_key, dev);

	w = pScrn->virtualX;
	h = pScrn->virtualY;

	if (alloc_framebuffer(dev, w, h) != 0) {
		xf86DrvMsg(pScrn->scrnIndex, X_ERROR,
		    "failed to allocate framebuffer %dx%d\n", w, h);
		free(dev);
		return FALSE;
	}
	xf86DrvMsg(pScrn->scrnIndex, X_INFO,
	    "framebuffer %dx%d stride=%d shm_fd=%d\n",
	    w, h, dev->stride, dev->shm_fd);

	miClearVisualTypes();
	if (!miSetVisualTypes(pScrn->depth,
	    miGetDefaultVisualMask(pScrn->depth),
	    pScrn->rgbBits, pScrn->defaultVisual))
		return FALSE;
	if (!miSetPixmapDepths())
		return FALSE;

	if (!fbScreenInit(pScreen, dev->fb, w, h,
	    pScrn->xDpi, pScrn->yDpi, dev->stride / 4, pScrn->bitsPerPixel))
		return FALSE;

	visual = pScreen->visuals + pScreen->numVisuals;
	while (--visual >= pScreen->visuals) {
		if ((visual->class | DynamicClass) == DirectColor) {
			visual->offsetRed   = pScrn->offset.red;
			visual->offsetGreen = pScrn->offset.green;
			visual->offsetBlue  = pScrn->offset.blue;
			visual->redMask     = pScrn->mask.red;
			visual->greenMask   = pScrn->mask.green;
			visual->blueMask    = pScrn->mask.blue;
		}
	}

	fbPictureInit(pScreen, 0, 0);
	xf86SetBlackWhitePixels(pScreen);

	if (!miPointerInitialize(pScreen, &sprite_funcs,
	    &screen_cursor_funcs, TRUE))
		return FALSE;

	if (!fbCreateDefColormap(pScreen))
		return FALSE;

	dev->saved_CloseScreen = pScreen->CloseScreen;
	pScreen->CloseScreen = rdpserver_CloseScreen;

	dev->saved_CreateScreenResources = pScreen->CreateScreenResources;
	pScreen->CreateScreenResources = rdpserver_CreateScreenResources;

	dev->saved_BlockHandler = pScreen->BlockHandler;
	pScreen->BlockHandler = rdpserver_BlockHandler;

	dev->saved_WakeupHandler = pScreen->WakeupHandler;
	pScreen->WakeupHandler = rdpserver_WakeupHandler;

	return TRUE;
}

/* Minimal CRTC and Output stubs for xf86Crtc. */
static void crtc_dpms(xf86CrtcPtr c, int m)
{ (void)c; (void)m; }

static Bool crtc_set_mode(xf86CrtcPtr c, DisplayModePtr m,
    Rotation r, int x, int y)
{ (void)c; (void)m; (void)r; (void)x; (void)y; return TRUE; }

static const xf86CrtcFuncsRec crtc_funcs = {
	.dpms = crtc_dpms,
	.set_mode_major = crtc_set_mode,
};

static void output_dpms(xf86OutputPtr o, int m)
{ (void)o; (void)m; }

static xf86OutputStatus output_detect(xf86OutputPtr o)
{ (void)o; return XF86OutputStatusConnected; }

static DisplayModePtr
output_get_modes(xf86OutputPtr output)
{
	ScrnInfoPtr pScrn = output->scrn;
	DisplayModePtr mode;

	mode = xf86CVTMode(pScrn->virtualX, pScrn->virtualY, 60, FALSE, FALSE);
	if (mode != NULL)
		mode->type = M_T_DRIVER | M_T_PREFERRED;
	return mode;
}

static int
output_mode_valid(xf86OutputPtr output, DisplayModePtr mode)
{
	(void)output;
	(void)mode;
	return MODE_OK;
}

static const xf86OutputFuncsRec output_funcs = {
	.dpms = output_dpms,
	.detect = output_detect,
	.mode_valid = output_mode_valid,
	.get_modes = output_get_modes,
};

static const xf86CrtcConfigFuncsRec config_funcs = {
	.resize = NULL,
};

static Bool
rdpserver_PreInit(ScrnInfoPtr pScrn, int flags)
{
	const char *env_w, *env_h, *env_ctrl;
	xf86CrtcPtr crtc;
	xf86OutputPtr output;

	if (flags & PROBE_DETECT)
		return FALSE;

	if (pScrn->confScreen != NULL)
		pScrn->monitor = pScrn->confScreen->monitor;

	env_ctrl = getenv("RDPSERVER_CTRL_FD");
	if (env_ctrl != NULL)
		xf86DrvMsg(pScrn->scrnIndex, X_INFO,
		    "control socket fd=%s\n", env_ctrl);

	if (!xf86SetDepthBpp(pScrn, 24, 0, 32, Support32bppFb))
		return FALSE;
	xf86PrintDepthBpp(pScrn);

	pScrn->rgbBits = 8;
	if (!xf86SetWeight(pScrn, (rgb){0, 0, 0}, (rgb){0, 0, 0}))
		return FALSE;
	if (!xf86SetDefaultVisual(pScrn, -1))
		return FALSE;

	env_w = getenv("RDPSERVER_W");
	env_h = getenv("RDPSERVER_H");
	pScrn->virtualX = env_w ? atoi(env_w) : RDPSERVER_DEFAULT_W;
	pScrn->virtualY = env_h ? atoi(env_h) : RDPSERVER_DEFAULT_H;
	if (pScrn->virtualX < 64) pScrn->virtualX = 64;
	if (pScrn->virtualY < 64) pScrn->virtualY = 64;

	xf86CrtcConfigInit(pScrn, &config_funcs);
	xf86CrtcSetSizeRange(pScrn, 64, 64, 8192, 8192);

	crtc = xf86CrtcCreate(pScrn, &crtc_funcs);
	if (crtc == NULL) return FALSE;

	output = xf86OutputCreate(pScrn, &output_funcs, "rdpserver-0");
	if (output == NULL) return FALSE;
	output->possible_crtcs = 1;

	if (!xf86InitialConfiguration(pScrn, TRUE))
		return FALSE;

	pScrn->xDpi = 96;
	pScrn->yDpi = 96;

	if (!xf86LoadSubModule(pScrn, "fb"))
		return FALSE;

	xf86DrvMsg(pScrn->scrnIndex, X_INFO,
	    "virtual size %dx%d depth %d bpp %d\n",
	    pScrn->virtualX, pScrn->virtualY,
	    pScrn->depth, pScrn->bitsPerPixel);

	return TRUE;
}

static void
rdpserver_FreeScreen(ScrnInfoPtr pScrn)
{
	(void)pScrn;
}

static Bool
rdpserver_SwitchMode(ScrnInfoPtr pScrn, DisplayModePtr mode)
{
	(void)pScrn;
	(void)mode;
	return TRUE;
}

static void
rdpserver_AdjustFrame(ScrnInfoPtr pScrn, int x, int y)
{
	(void)pScrn;
	(void)x;
	(void)y;
}

static Bool
rdpserver_EnterVT(ScrnInfoPtr pScrn)
{
	(void)pScrn;
	return TRUE;
}

static void
rdpserver_LeaveVT(ScrnInfoPtr pScrn)
{
	(void)pScrn;
}

static ModeStatus
rdpserver_ValidMode(ScrnInfoPtr pScrn, DisplayModePtr mode,
    Bool verbose, int flags)
{
	(void)pScrn;
	(void)mode;
	(void)verbose;
	(void)flags;
	return MODE_OK;
}

static Bool
rdpserver_Probe(DriverPtr drv, int flags)
{
	ScrnInfoPtr pScrn;
	GDevPtr *devSections;
	int numDevSections;
	int entityIndex;

	if (flags & PROBE_DETECT)
		return FALSE;

	numDevSections = xf86MatchDevice(RDPSERVER_DRIVER_NAME, &devSections);
	if (numDevSections <= 0)
		return FALSE;

	entityIndex = xf86ClaimNoSlot(drv, 0, devSections[0], TRUE);

	pScrn = xf86AllocateScreen(drv, 0);
	if (pScrn == NULL) {
		free(devSections);
		return FALSE;
	}

	pScrn->driverVersion = 1;
	pScrn->driverName    = RDPSERVER_DRIVER_NAME;
	pScrn->name          = RDPSERVER_DRIVER_NAME;
	pScrn->Probe         = rdpserver_Probe;
	pScrn->PreInit       = rdpserver_PreInit;
	pScrn->ScreenInit    = rdpserver_ScreenInit;
	pScrn->SwitchMode    = rdpserver_SwitchMode;
	pScrn->AdjustFrame   = rdpserver_AdjustFrame;
	pScrn->EnterVT       = rdpserver_EnterVT;
	pScrn->LeaveVT       = rdpserver_LeaveVT;
	pScrn->FreeScreen    = rdpserver_FreeScreen;
	pScrn->ValidMode     = rdpserver_ValidMode;

	xf86AddEntityToScreen(pScrn, entityIndex);

	free(devSections);
	return TRUE;
}

static DriverRec rdpserver_driver = {
	.driverVersion = 1,
	.driverName    = RDPSERVER_DRIVER_NAME,
	.Identify      = NULL,
	.Probe         = rdpserver_Probe,
	.AvailableOptions = NULL,
	.module        = NULL,
	.refCount      = 0,
};

static void *
rdpserver_setup(void *module, void *opts, int *errmaj, int *errmin)
{
	static Bool done = FALSE;
	(void)opts;
	(void)errmaj;
	(void)errmin;

	if (done)
		return NULL;
	done = TRUE;

	xf86AddDriver(&rdpserver_driver, module, HaveDriverFuncs);
	return (void *)1;
}

static XF86ModuleVersionInfo rdpserver_version = {
	RDPSERVER_DRIVER_NAME,
	"rdpserver",
	MODINFOSTRING1,
	MODINFOSTRING2,
	XORG_VERSION_CURRENT,
	1, 0, 0,
	ABI_CLASS_VIDEODRV,
	ABI_VIDEODRV_VERSION,
	MOD_CLASS_VIDEODRV,
	{0, 0, 0, 0}
};

_X_EXPORT XF86ModuleData rdpserverdevModuleData = {
	&rdpserver_version,
	rdpserver_setup,
	NULL
};
