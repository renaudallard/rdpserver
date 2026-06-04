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
 * camera.c -- session side of MS-RDPECAM camera redirection.
 *
 * Writes the raw frames the worker forwards (RDP_BE_CAMERA) to a
 * v4l2loopback output device so applications in the session see a webcam.
 */

#include "camera.h"

#include "../channels/cam.h"   /* CAM_FORMAT_* */
#include "../include/rdp_log.h"

#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>

struct rdp_camera {
	int      fd;
	uint8_t  format;       /* the V4L2 format currently configured */
	uint32_t width, height;
	int      fmt_set;
};

/* Map an MS-RDPECAM raw format to a V4L2 fourcc, or 0 if not raw. */
static uint32_t
v4l2_fourcc_of(uint8_t format)
{
	switch (format) {
	case CAM_FORMAT_NV12:  return V4L2_PIX_FMT_NV12;
	case CAM_FORMAT_I420:  return V4L2_PIX_FMT_YUV420;
	case CAM_FORMAT_YUY2:  return V4L2_PIX_FMT_YUYV;
	case CAM_FORMAT_RGB24: return V4L2_PIX_FMT_RGB24;
	case CAM_FORMAT_RGB32: return V4L2_PIX_FMT_RGB32;
	default:               return 0;
	}
}

/* Bytes in one frame, or 0 for an unknown/non-raw format or implausible
 * dimensions. */
static uint32_t
image_size(uint8_t format, uint32_t w, uint32_t h)
{
	uint64_t px;

	if (w == 0 || h == 0 || w > 8192 || h > 8192) return 0;
	px = (uint64_t)w * (uint64_t)h;
	switch (format) {
	case CAM_FORMAT_NV12:
	case CAM_FORMAT_I420:  return (uint32_t)(px * 3 / 2);
	case CAM_FORMAT_YUY2:  return (uint32_t)(px * 2);
	case CAM_FORMAT_RGB24: return (uint32_t)(px * 3);
	case CAM_FORMAT_RGB32: return (uint32_t)(px * 4);
	default:               return 0;
	}
}

/* The stride of one image row for the format. */
static uint32_t
bytes_per_line(uint8_t format, uint32_t w)
{
	switch (format) {
	case CAM_FORMAT_NV12:
	case CAM_FORMAT_I420:  return w;        /* Y-plane stride */
	case CAM_FORMAT_YUY2:  return w * 2;
	case CAM_FORMAT_RGB24: return w * 3;
	case CAM_FORMAT_RGB32: return w * 4;
	default:               return w;
	}
}

/* A device is usable for writing if it reports VIDEO_OUTPUT (v4l2loopback's
 * writable side) rather than being a real capture-only camera. */
static int
is_output_device(int fd)
{
	struct v4l2_capability cap;

	memset(&cap, 0, sizeof cap);
	if (ioctl(fd, VIDIOC_QUERYCAP, &cap) != 0) return 0;
	return (cap.capabilities & V4L2_CAP_VIDEO_OUTPUT) != 0
	    || (cap.device_caps & V4L2_CAP_VIDEO_OUTPUT) != 0;
}

struct rdp_camera *
rdp_camera_open(void)
{
	struct rdp_camera *c;
	int i, fd = -1;
	char path[32];

	for (i = 0; i < 64; i++) {
		(void)snprintf(path, sizeof path, "/dev/video%d", i);
		fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0) continue;
		if (is_output_device(fd)) break;
		(void)close(fd);
		fd = -1;
	}
	if (fd < 0) {
		rdp_info("camera: no v4l2loopback output device; "
			"virtual camera disabled");
		return NULL;
	}
	c = calloc(1, sizeof *c);
	if (c == NULL) { (void)close(fd); return NULL; }
	c->fd = fd;
	rdp_info("camera: virtual camera on %s", path);
	return c;
}

static int
set_format(struct rdp_camera *c, uint8_t format, uint32_t w, uint32_t h)
{
	struct v4l2_format f;
	uint32_t fourcc = v4l2_fourcc_of(format);
	uint32_t sz = image_size(format, w, h);

	if (fourcc == 0 || sz == 0) return -1;
	memset(&f, 0, sizeof f);
	f.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
	f.fmt.pix.width = w;
	f.fmt.pix.height = h;
	f.fmt.pix.pixelformat = fourcc;
	f.fmt.pix.field = V4L2_FIELD_NONE;
	f.fmt.pix.bytesperline = bytes_per_line(format, w);
	f.fmt.pix.sizeimage = sz;
	f.fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;
	if (ioctl(c->fd, VIDIOC_S_FMT, &f) != 0) {
		rdp_info("camera: VIDIOC_S_FMT failed: %s", strerror(errno));
		return -1;
	}
	c->format = format;
	c->width = w;
	c->height = h;
	c->fmt_set = 1;
	return 0;
}

void
rdp_camera_write(struct rdp_camera *c, uint8_t format, uint32_t width,
    uint32_t height, const void *frame, size_t len)
{
	ssize_t wn;

	if (c == NULL || c->fd < 0 || frame == NULL || len == 0) return;
	if (!c->fmt_set || c->format != format || c->width != width
	    || c->height != height) {
		if (set_format(c, format, width, height) != 0) return;
	}
	/* Drop the frame on EAGAIN or a short write rather than blocking the
	 * session loop; the next frame supersedes it. */
	do { wn = write(c->fd, frame, len); }
	while (wn < 0 && errno == EINTR);
	(void)wn;
}

void
rdp_camera_close(struct rdp_camera *c)
{
	if (c == NULL) return;
	if (c->fd >= 0) (void)close(c->fd);
	free(c);
}

#else /* !__linux__ */

struct rdp_camera *rdp_camera_open(void) { return NULL; }
void rdp_camera_write(struct rdp_camera *c, uint8_t format, uint32_t width,
    uint32_t height, const void *frame, size_t len)
{ (void)c; (void)format; (void)width; (void)height; (void)frame; (void)len; }
void rdp_camera_close(struct rdp_camera *c) { (void)c; }

#endif /* __linux__ */
