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
 *   u16 reserved (0)     [AUTH: client IP length, ip_len]
 *   user_bytes (user_len)
 *   pass_bytes (pass_len)
 *   ip_bytes   (ip_len)  [AUTH only: client source IP, for rate-limiting]
 *
 * Response layout:
 *
 *   u8  status        RDP_SESSMGR_OK | RDP_SESSMGR_FAIL
 *   u8  reason        backend-specific hint
 *   u16 errno_hint    libc errno that hints at the underlying issue
 *   u32 reserved (0)
 *
 * Length caps: user up to 256, pass up to 1024, AUTH client IP up to
 * 64.  A whole request is therefore at most 8 + 256 + 1024 + 64 = 1352
 * bytes, well under any SEQPACKET frame size the kernel will accept.
 */

#ifndef RDP_SESSMGR_PROTOCOL_H
#define RDP_SESSMGR_PROTOCOL_H

#include <stdint.h>

#define RDP_SESSMGR_OP_AUTH      0x01
#define RDP_SESSMGR_OP_SPAWN     0x02
#define RDP_SESSMGR_OP_SUSPEND   0x03
#define RDP_SESSMGR_OP_RESUME    0x04
#define RDP_SESSMGR_OP_NLA_AUTH  0x05
#define RDP_SESSMGR_OP_NLA_STORE 0x06

#define RDP_SESSMGR_OK        0x00
#define RDP_SESSMGR_FAIL      0x01
#define RDP_SESSMGR_ENOSYS    0x02
#define RDP_SESSMGR_EPERM     0x03   /* SPAWN before successful AUTH */

#define RDP_SESSMGR_USER_MAX  256
#define RDP_SESSMGR_PASS_MAX  1024
#define RDP_SESSMGR_IP_MAX    64   /* AUTH client-IP field, for rate-limiting */
#define RDP_SESSMGR_TZ_MAX    63   /* SPAWN client POSIX TZ string */
#define RDP_SESSMGR_FRAME_MAX (8 + RDP_SESSMGR_USER_MAX + RDP_SESSMGR_PASS_MAX \
				+ RDP_SESSMGR_IP_MAX)

#define RDP_SESSMGR_DEFAULT_SOCK "/var/run/rdpserver/sessmgr.sock"

/* SPAWN request layout (no credentials -- bound to prior AUTH on the
 * same connection):
 *
 *   u8  op           = 2
 *   u8  flags
 *   u16 width
 *   u16 height
 *   u16 tzLen        (length of the trailing POSIX TZ string; 0 = none)
 *   u32 keyboardLayout   (client LCID; 0 = unknown, session uses us)
 *   tz_bytes (tzLen) (client POSIX TZ string, no terminator on the wire)
 *
 * SPAWN reply (in addition to the status byte we already define):
 *   status     OK on success.  Successful replies include the
 *              backend socket fd as ancillary data (SCM_RIGHTS).
 *              That fd is one end of a SOCK_STREAM socketpair; the
 *              other end has been handed to the rdp-session child
 *              as fd 3 before exec.
 *
 * SUSPEND request (worker -> sessmgr, on client disconnect):
 *   u8  op           = 3
 *   u8  reserved
 *   u16 reserved
 *   u32 logonId
 *   u8  arc_random[16]   ARC random bits for verifier
 *   Ancillary: the backend fd via SCM_RIGHTS.
 * SUSPEND reply: status byte (8 bytes).
 *
 * RESUME request (new worker -> sessmgr, on reconnect attempt):
 *   u8  op       = 4
 *   u8  reserved
 *   u16 reserved
 *   u32 logonId
 * RESUME reply (24 bytes): status(8) + arc_random(16). On success,
 *   the backend fd is returned via SCM_RIGHTS.
 */

/* NLA_STORE request (op=6): register a nonce after successful AUTH.
 *   u8  op           = 6
 *   u8  flags
 *   u16 user_len
 *   u16 reserved
 *   u16 reserved
 *   user_bytes (user_len)
 *   nonce[16]
 *
 * NLA_AUTH request (op=5): present the matching nonce.
 *   u8  op           = 5
 *   u8  flags
 *   u16 user_len
 *   u16 reserved
 *   u16 reserved
 *   user_bytes (user_len)
 *   nonce[16]
 *
 * The worker writes the nonce into the .tok file and registers
 * it via NLA_STORE.  A subsequent worker reads the .tok, sends
 * NLA_AUTH with the nonce, and the sessmgr verifies it matches
 * the stored value.  This prevents local processes from using
 * NLA_AUTH without possessing the token file. */

#define RDP_SESSMGR_NLA_NONCE_LEN 16

#define RDP_SESSMGR_SUSPEND_MAX     16
#define RDP_SESSMGR_SUSPEND_TIMEOUT 120  /* seconds */

#endif /* RDP_SESSMGR_PROTOCOL_H */
