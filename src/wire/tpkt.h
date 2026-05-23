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
 * tpkt.h -- TPKT framing per RFC 1006.
 *
 * TPKT is a 4-byte preamble that lets ISO transport (X.224) ride on
 * top of TCP.  The header is:
 *
 *   off 0  version  (1)  always 3
 *   off 1  reserved (1)  always 0
 *   off 2  length   (2)  big-endian; INCLUDES the 4-byte header
 *
 * Minimum payload is 3 bytes (smallest X.224 TPDU = DT TPDU), so
 * the smallest legal TPKT length value is 7.  The maximum is 65535.
 */

#ifndef RDP_TPKT_H
#define RDP_TPKT_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RDP_TPKT_HDR_LEN  4u
#define RDP_TPKT_VERSION  3u
#define RDP_TPKT_MIN_LEN  7u
#define RDP_TPKT_MAX_LEN  65535u

/* Decoded TPKT header. */
struct rdp_tpkt {
	uint16_t length;   /* total wire length, including the 4-byte header */
};

/* Decode the TPKT header from a 4-byte buffer.  Returns 0 on success
 * and fills *out, or -1 on malformed input (wrong version, length
 * below 7 or above 65535). */
int rdp_tpkt_parse_hdr(struct rdp_tpkt *out, const uint8_t hdr[4]);

/* Encode a TPKT header into a 4-byte buffer.  `length` is the total
 * wire length, header included.  Returns -1 if length is out of range. */
int rdp_tpkt_encode_hdr(uint8_t hdr[4], uint16_t length);

/* Synchronous helper: read a complete TPKT frame from fd into buf
 * (cap bytes).  On success returns total wire length (header + body)
 * and the bytes are in buf[0..len).  Returns 0 on EOF before any
 * bytes were read.  Returns -1 on error (errno set, or malformed
 * header). */
ssize_t rdp_tpkt_read(int fd, uint8_t *buf, size_t cap);

#endif /* RDP_TPKT_H */
