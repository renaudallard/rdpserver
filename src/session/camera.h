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
 * camera.h -- session side of RDP camera redirection (MS-RDPECAM).
 *
 * Presents the client's camera (frames arriving from the worker as
 * RDP_BE_CAMERA messages) as a V4L2 video device that applications in
 * the session can open as a webcam.  The worker only forwards raw frames
 * (NV12, I420, YUY2, RGB24, RGB32), so the session writes them straight to
 * a v4l2loopback output device with no decoding.
 *
 * Everything is best effort: with no v4l2loopback device present the module
 * stays inert and the session runs normally without a virtual camera.
 * v4l2loopback must be provisioned by the host (modprobe); the pledged
 * session cannot load it.  Gated by __linux__; elsewhere these are no-op
 * stubs.
 */
#ifndef RDP_CAMERA_H
#define RDP_CAMERA_H

#include <stddef.h>
#include <stdint.h>

struct rdp_camera;

/* Find a writable v4l2loopback output device and open it.  Returns NULL
 * (and the session runs without a virtual camera) when none is present.
 * Never breaks the session. */
struct rdp_camera *rdp_camera_open(void);

/* Write one raw frame in the given MS-RDPECAM format (CAM_FORMAT_*) and
 * geometry to the device, configuring the V4L2 format on the first frame or
 * whenever it changes.  Non-blocking; a frame is dropped rather than blocking
 * the session loop.  A NULL camera is a no-op. */
void rdp_camera_write(struct rdp_camera *c, uint8_t format,
    uint32_t width, uint32_t height, const void *frame, size_t len);

/* Close the device and free the state.  A NULL camera is a no-op. */
void rdp_camera_close(struct rdp_camera *c);

#endif /* RDP_CAMERA_H */
