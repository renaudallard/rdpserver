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
 * tls.h -- thin TLS server-side wrapper.
 *
 * Hides the choice between OpenSSL and libtls.  The daemon hands in
 * an already-connected fd; we run a server handshake and return a
 * handle that streams bytes the same as the underlying socket.
 *
 * Self-signed certificate generation is provided so first-run works
 * without an operator producing a cert.  The cert/key go under
 * tmp/server.{crt,key} in the project directory (see CLAUDE.md note:
 * no /tmp).  Production deployments override these via rdpd.conf.
 */

#ifndef RDP_TLS_H
#define RDP_TLS_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

struct rdp_tls;
struct rdp_tls_ctx;

/* Per-daemon context (cert + private key bound to it).  Created once
 * at start-up; child connection handlers borrow it. */
struct rdp_tls_ctx *rdp_tls_ctx_new(const char *cert_pem, const char *key_pem);
void rdp_tls_ctx_free(struct rdp_tls_ctx *ctx);

/* Generate a self-signed cert+key pair if they don't already exist.
 * Writes PEM files to cert_path and key_path (mode 0600 for the key).
 * Returns 0 on success, -1 on error.  Caller can then call
 * rdp_tls_ctx_new(cert_path, key_path). */
int rdp_tls_ensure_selfsigned(const char *cert_path, const char *key_path,
		const char *cn);

/* Accept on fd: run TLS server handshake.  fd must already be
 * connected to the client.  On success returns a handle whose read/
 * write functions wrap the TLS stream.  Returns NULL on error. */
struct rdp_tls *rdp_tls_accept(struct rdp_tls_ctx *ctx, int fd);

/* Synchronous read/write over the TLS handle.  Same semantics as
 * read(2)/write(2): may short-read or short-write; returns 0 on EOF;
 * returns -1 with errno on error. */
ssize_t rdp_tls_read(struct rdp_tls *t, void *buf, size_t n);
ssize_t rdp_tls_write(struct rdp_tls *t, const void *buf, size_t n);

/* Read/write exactly n bytes. */
ssize_t rdp_tls_read_full(struct rdp_tls *t, void *buf, size_t n);
ssize_t rdp_tls_write_full(struct rdp_tls *t, const void *buf, size_t n);

/* Underlying fd (for the rare cases we need it -- e.g. setting
 * TCP_NODELAY).  Caller must not directly read/write on it. */
int rdp_tls_fd(const struct rdp_tls *t);

void rdp_tls_close(struct rdp_tls *t);

/* Extract the server certificate's DER-encoded SubjectPublicKeyInfo.
 * Returns bytes written to out, or -1. */
ssize_t rdp_tls_get_server_pubkey(struct rdp_tls *t, uint8_t *out, size_t cap);

#endif /* RDP_TLS_H */
