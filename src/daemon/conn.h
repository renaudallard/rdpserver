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
 * conn.h -- per-connection state machine.
 *
 * Each accepted connection is handed to rdp_conn_run().  The function
 * drives the RDP handshake from CR/CC through MCS, license, caps, and
 * finalization, then sits in a small input/output loop sending a
 * solid-colour bitmap update (Phase B token) and logging input events.
 *
 * On clean disconnect or error it closes resources and returns.
 *
 * The TLS context is owned by the parent daemon and shared (read-only
 * by the children after fork) across connections.
 */

#ifndef RDP_CONN_H
#define RDP_CONN_H

struct rdp_tls_ctx;

struct rdp_conn_cfg {
	struct rdp_tls_ctx *tls;
	const char         *sessmgr_sock;  /* AF_UNIX path; NULL = stub auth */
	int                 auto_login;    /* skip greeter; use Client Info creds */
	int                 allow_v10_avc; /* offer AVC to v10.x-no-AVC_DISABLED clients */
	int                 allow_progressive; /* offer RFX Progressive GFX when AVC is not used */
	int                 prefer_wan_audio;  /* stream G.711 A-law audio (half bandwidth) */
	int                 allow_microphone;  /* offer the AUDIO_INPUT (mic) channel */
	int                 allow_avc444;      /* offer AVC444 (4:4:4 chroma) to v10.x AVC clients */
};

void rdp_conn_run(int fd, const struct rdp_conn_cfg *cfg, const char *peer);

#endif /* RDP_CONN_H */
