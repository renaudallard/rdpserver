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
 * proto.c -- backend RPC helpers.
 *
 * Read/write framed messages over SOCK_STREAM.  Each call reads or
 * writes one complete frame.  No reordering, no batching: a single
 * pair of rdp-session <-> worker is single-threaded by design.
 */

#include "proto.h"

#include "../common/io.h"

#include <sys/types.h>
#include <errno.h>
#include <string.h>

#define BE_MAX_PAYLOAD (4 * 1024 * 1024)

ssize_t
rdp_be_recv(int fd, uint32_t *type_out, void *payload, size_t cap)
{
	uint8_t hdr[RDP_BE_HEADER];
	uint32_t type, len;
	ssize_t r;

	r = rdp_read_full(fd, hdr, RDP_BE_HEADER);
	if (r == 0) return 0;
	if (r < (ssize_t)RDP_BE_HEADER) {
		errno = EPROTO;
		return -1;
	}
	type = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8)
		| ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
	len  = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8)
		| ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
	if (len > BE_MAX_PAYLOAD || len > cap) {
		errno = EMSGSIZE;
		return -1;
	}
	if (len > 0) {
		r = rdp_read_full(fd, payload, len);
		if (r < (ssize_t)len) {
			errno = EPROTO;
			return -1;
		}
	}
	*type_out = type;
	return (ssize_t)len;
}

int
rdp_be_send(int fd, uint32_t type, const void *payload, size_t len)
{
	uint8_t hdr[RDP_BE_HEADER];

	hdr[0] = (uint8_t)(type & 0xff);
	hdr[1] = (uint8_t)((type >> 8) & 0xff);
	hdr[2] = (uint8_t)((type >> 16) & 0xff);
	hdr[3] = (uint8_t)((type >> 24) & 0xff);
	hdr[4] = (uint8_t)(len & 0xff);
	hdr[5] = (uint8_t)((len >> 8) & 0xff);
	hdr[6] = (uint8_t)((len >> 16) & 0xff);
	hdr[7] = (uint8_t)((len >> 24) & 0xff);
	if (rdp_write_full(fd, hdr, RDP_BE_HEADER) != (ssize_t)RDP_BE_HEADER)
		return -1;
	if (len > 0 && rdp_write_full(fd, payload, len) != (ssize_t)len)
		return -1;
	return 0;
}
