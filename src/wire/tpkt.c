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
 * tpkt.c -- TPKT framing.
 */

#include "tpkt.h"

#include "../common/io.h"

#include <errno.h>

int
rdp_tpkt_parse_hdr(struct rdp_tpkt *out, const uint8_t hdr[4])
{
	uint16_t length;

	if (hdr[0] != RDP_TPKT_VERSION)
		return -1;
	if (hdr[1] != 0)
		return -1;
	length = (uint16_t)((hdr[2] << 8) | hdr[3]);
	if (length < RDP_TPKT_MIN_LEN)
		return -1;
	out->length = length;
	return 0;
}

int
rdp_tpkt_encode_hdr(uint8_t hdr[4], uint16_t length)
{
	if (length < RDP_TPKT_MIN_LEN)
		return -1;
	hdr[0] = RDP_TPKT_VERSION;
	hdr[1] = 0;
	hdr[2] = (uint8_t)((length >> 8) & 0xff);
	hdr[3] = (uint8_t)(length & 0xff);
	return 0;
}

ssize_t
rdp_tpkt_read(int fd, uint8_t *buf, size_t cap)
{
	struct rdp_tpkt h;
	ssize_t r;
	size_t body;

	if (cap < RDP_TPKT_HDR_LEN) {
		errno = EINVAL;
		return -1;
	}
	r = rdp_read_full(fd, buf, RDP_TPKT_HDR_LEN);
	if (r == 0)
		return 0;
	if (r < 0)
		return -1;
	if (r < (ssize_t)RDP_TPKT_HDR_LEN) {
		errno = EPROTO;
		return -1;
	}
	if (rdp_tpkt_parse_hdr(&h, buf) < 0) {
		errno = EPROTO;
		return -1;
	}
	if (h.length > cap) {
		errno = EMSGSIZE;
		return -1;
	}
	body = (size_t)h.length - RDP_TPKT_HDR_LEN;
	if (body > 0) {
		r = rdp_read_full(fd, buf + RDP_TPKT_HDR_LEN, body);
		if (r < (ssize_t)body) {
			if (r >= 0)
				errno = EPROTO;
			return -1;
		}
	}
	return (ssize_t)h.length;
}
