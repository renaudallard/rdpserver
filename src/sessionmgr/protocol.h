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
 * protocol.h -- wire protocol between rdpd workers and rdp-sessionmgr.
 *
 * One AF_UNIX SOCK_SEQPACKET datagram per request and per response.
 * SEQPACKET means each send() lands as a single, framed recv() on
 * the peer; we don't have to scan for boundaries.
 *
 * Request layout (little-endian):
 *
 *   u8  op
 *   u8  flags
 *   u16 user_len
 *   u16 pass_len
 *   u16 reserved (0)
 *   user_bytes (user_len)
 *   pass_bytes (pass_len)
 *
 * Response layout:
 *
 *   u8  status        RDP_SESSMGR_OK | RDP_SESSMGR_FAIL
 *   u8  reason        backend-specific hint
 *   u16 errno_hint    libc errno that hints at the underlying issue
 *   u32 reserved (0)
 *
 * Length caps: user up to 256, pass up to 1024.  A whole request is
 * therefore at most 8 + 256 + 1024 = 1288 bytes, well under any
 * SEQPACKET frame size the kernel will accept.
 */

#ifndef RDP_SESSMGR_PROTOCOL_H
#define RDP_SESSMGR_PROTOCOL_H

#include <stdint.h>

#define RDP_SESSMGR_OP_AUTH   0x01
#define RDP_SESSMGR_OP_SPAWN  0x02

#define RDP_SESSMGR_OK        0x00
#define RDP_SESSMGR_FAIL      0x01
#define RDP_SESSMGR_ENOSYS    0x02
#define RDP_SESSMGR_EPERM     0x03   /* SPAWN before successful AUTH */

#define RDP_SESSMGR_USER_MAX  256
#define RDP_SESSMGR_PASS_MAX  1024
#define RDP_SESSMGR_FRAME_MAX (8 + RDP_SESSMGR_USER_MAX + RDP_SESSMGR_PASS_MAX)

#define RDP_SESSMGR_DEFAULT_SOCK "/var/run/rdpserver/sessmgr.sock"

/* SPAWN request layout (no credentials -- bound to prior AUTH on the
 * same connection):
 *
 *   u8  op           = 2
 *   u8  flags
 *   u16 width
 *   u16 height
 *   u16 reserved
 *
 * SPAWN reply (in addition to the status byte we already define):
 *   status     OK on success.  Successful replies include the
 *              backend socket fd as ancillary data (SCM_RIGHTS).
 *              That fd is one end of a SOCK_STREAM socketpair; the
 *              other end has been handed to the rdp-session child
 *              as fd 3 before exec.
 */

#endif /* RDP_SESSMGR_PROTOCOL_H */
