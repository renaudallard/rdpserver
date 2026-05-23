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
 * session.h -- per-user session helper (rdp-session) interface.
 *
 * NOT IMPLEMENTED in this drop.  Phase F will build the rdp-session
 * binary which runs as the target user.  Its responsibilities:
 *
 *  1. Open a free X DISPLAY and spawn Xvfb (v1) bound to it.
 *  2. Connect to the X server, set up XDamage + XFixes + XShm
 *     for capture, XTest for input injection.
 *  3. Speak the "backend RPC" (see rdp_backend.h) over the fd
 *     handed in by sessionmgr.
 *  4. Run the user's session script (~/.xsession, or xterm fallback).
 *  5. Bridge X11 CLIPBOARD selection to the CLIPRDR channel.
 *
 * The backend RPC is intentionally small and language-agnostic so
 * that future backends (xrdpdev native, Wayland compositor) can
 * reuse the protocol without re-implementing.
 */

#ifndef RDP_SESSION_H
#define RDP_SESSION_H

#include "../include/compat.h"
#include "../include/rdp_backend.h"

/* Phase F entry point: invoked by rdp-sessionmgr after fork+setuid.
 * fd is the backend-RPC socket (one end of a SOCK_SEQPACKET pair).
 * cfg describes the initial display mode requested by the client. */
int rdp_session_run(int fd, const struct rdp_backend_cfg *cfg);

#endif /* RDP_SESSION_H */
