/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and this disclaimer.
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
 * fuse_drive.h -- session-side RDPDR drive presentation over raw
 * /dev/fuse (Linux only, read path).
 *
 * The session receives a /dev/fuse file descriptor (fd 4) from
 * rdp-sessionmgr, which has already mounted it on ~/RemoteDrive.  This
 * module speaks the raw FUSE kernel protocol on that fd and turns file
 * system requests from the local kernel into RDPDR file operations
 * carried to the worker over the backend RPC (RDP_BE_FS_REQ), correlating
 * the asynchronous RDP_BE_FS_RSP replies back to the originating kernel
 * request.
 *
 * On non-Linux hosts (no <linux/fuse.h>) the whole module compiles to
 * no-op stubs, so the session behaves exactly as before.
 */

#ifndef RDP_SESSION_FUSE_DRIVE_H
#define RDP_SESSION_FUSE_DRIVE_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>

struct fuse_drive;

/*
 * Initialise the module on the given /dev/fuse fd, sending FS_REQ frames
 * on be_fd.  Returns a heap-allocated state on success, or NULL when the
 * host has no FUSE support, fuse_fd is not a usable FUSE char device, or
 * allocation fails.  When NULL is returned the caller must run without
 * drive support (do not poll fuse_fd).
 */
struct fuse_drive *fuse_drive_init(int fuse_fd, int be_fd);

/* Release all state.  Safe on NULL. */
void fuse_drive_free(struct fuse_drive *fd);

/*
 * Drain and dispatch FUSE requests that are ready on the /dev/fuse fd.
 * Call when poll reports POLLIN on the fd returned by fuse_drive_fd.
 * Returns 0 normally, -1 if the fuse fd died (caller should stop polling
 * it).  Safe on NULL (returns 0).
 */
int fuse_drive_process(struct fuse_drive *fd);

/* The /dev/fuse fd to add to the session poll set, or -1 when disabled. */
int fuse_drive_fd(const struct fuse_drive *fd);

/*
 * Announce (added != 0) or remove (added == 0) a top-level drive node
 * for the RDPDR device.  name is the client drive label (<= 8 chars).
 * Safe on NULL.
 */
void fuse_drive_add_device(struct fuse_drive *fd, uint32_t device_id,
		uint32_t device_type, const char *name, int added);

/*
 * Feed a backend RDP_BE_FS_RSP back to the module: rsp is the fixed
 * rdp_be_fs_rsp header, payload/payload_len the trailing op-specific
 * bytes (may be NULL/0).  The module looks up the pending request by
 * rsp->req_id, builds the matching FUSE reply, and writes it to the fuse
 * fd.  Safe on NULL.
 */
void fuse_drive_handle_fs_rsp(struct fuse_drive *fd,
		const void *rsp, const uint8_t *payload, size_t payload_len);

#endif /* RDP_SESSION_FUSE_DRIVE_H */
