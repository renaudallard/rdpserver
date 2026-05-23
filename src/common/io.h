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
 * io.h -- blocking and non-blocking I/O helpers.
 *
 * Wraps the awkward bits: short reads/writes, EINTR, setting
 * O_NONBLOCK and SOCK_CLOEXEC, and opening a TCP listener on a
 * given host:port string.
 */

#ifndef RDP_IO_H
#define RDP_IO_H

#include <sys/types.h>
#include <stddef.h>

/* Read exactly n bytes.  Returns n on success, 0 on clean EOF before
 * any byte was read, -1 on error.  Restarts on EINTR. */
ssize_t rdp_read_full(int fd, void *buf, size_t n);

/* Write exactly n bytes.  Returns n on success, -1 on error.
 * Restarts on EINTR. */
ssize_t rdp_write_full(int fd, const void *buf, size_t n);

/* Open a TCP listener on host:port.  host may be NULL (any address)
 * or a literal like "127.0.0.1".  Returns the bound, listening fd,
 * or -1 on error (with errno set).  Sets SO_REUSEADDR and IPV6_V6ONLY
 * sensibly; backlog defaults to 128.  Caller closes. */
int rdp_listen_tcp(const char *host, const char *port);

/* Set FD_CLOEXEC and O_NONBLOCK on fd.  Returns 0 on success. */
int rdp_set_cloexec(int fd);
int rdp_set_nonblock(int fd);

/* Enable TCP keepalive on a connected TCP socket.  Defaults to 60 s
 * idle, 10 s interval between probes, 6 probes (i.e. half-open
 * detection within ~2 minutes of silence).  Per-OS knobs are
 * applied where available; SO_KEEPALIVE alone is the portable
 * floor.  Returns 0 on success, -1 on error. */
int rdp_set_tcp_keepalive(int fd);

#endif /* RDP_IO_H */
