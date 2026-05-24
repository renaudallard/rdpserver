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

#include <xf86.h>
#include <xf86str.h>
#include <xf86Crtc.h>
#include <mipointer.h>
#include <micmap.h>
#include <mi.h>
#include <fb.h>
#include <damage.h>
#include <damagestr.h>

#include <fcntl.h>
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
rdpserver_BlockHandler(ScreenPtr pScreen, void *timeout)
{
	struct rdpserver_dev *dev = rdpserver_dev_from_screen(pScreen);
	(void)timeout;

	if (dev->damage != NULL && dev->damage_registered) {
		RegionPtr region = DamageRegion(dev->damage);
		if (RegionNotEmpty(region)) {
			/* TODO: send damage rects to rdp-session via ctrl_fd */
			DamageEmpty(dev->damage);
		}
	}
}

static void
rdpserver_WakeupHandler(ScreenPtr pScreen, int result)
{
	(void)pScreen;
	(void)result;
	/* TODO: read input/resize from ctrl_fd */
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

	mode = xnfcalloc(1, sizeof(DisplayModeRec));
	mode->HDisplay = pScrn->virtualX;
	mode->VDisplay = pScrn->virtualY;
	mode->VRefresh = 60;
	mode->Clock = mode->HDisplay * mode->VDisplay * 60 / 1000;
	mode->HSyncStart = mode->HDisplay + 16;
	mode->HSyncEnd = mode->HSyncStart + 64;
	mode->HTotal = mode->HSyncEnd + 16;
	mode->VSyncStart = mode->VDisplay + 1;
	mode->VSyncEnd = mode->VSyncStart + 3;
	mode->VTotal = mode->VSyncEnd + 1;
	mode->Flags = 0;
	mode->type = M_T_DRIVER | M_T_PREFERRED;
	mode->status = MODE_OK;
	mode->next = NULL;
	mode->prev = NULL;
	xf86SetModeDefaultName(mode);
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
	const char *env_w, *env_h;
	xf86CrtcPtr crtc;
	xf86OutputPtr output;

	if (flags & PROBE_DETECT)
		return FALSE;

	if (pScrn->confScreen != NULL)
		pScrn->monitor = pScrn->confScreen->monitor;

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
