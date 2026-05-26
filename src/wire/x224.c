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
 * x224.c -- ITU-T X.224 Class 0 encoding/decoding.
 *
 * Decoding tolerances follow MS-RDPBCGR observations of real clients:
 *  - Cookie line is optional; routing token is optional; either, both,
 *    or neither may appear before the RDP_NEG_REQ.
 *  - When RDP_NEG_CORRELATION_INFO_PRESENT (0x08) is set, a 36-byte
 *    block follows the RDP_NEG_REQ.  We skip it; we do not parse it.
 *  - LI does not include itself.  X.224 CR/CC header is exactly 7
 *    bytes (LI + code + 2 dst-ref + 2 src-ref + class/opt) when the
 *    body holds only the negotiation PDU; LI reflects the variable
 *    body length (cookie + NEG_REQ + correlation info, if present).
 */

#include "x224.h"

#include "../common/buf.h"

#include <string.h>

int
rdp_x224_parse_cr(struct rdp_x224_cr *out,
		const uint8_t *buf, size_t len)
{
	uint8_t li, code;
	size_t hdr_consumed = 7, body_off, body_end;
	const uint8_t *p;

	memset(out, 0, sizeof *out);

	if (len < RDP_X224_HDR_LEN_CRCC)
		return -1;
	li = buf[0];
	code = buf[1] & 0xf0;
	/* CR is 0xE0 with the lower nibble (CDT) zero. */
	if (code != RDP_X224_CR)
		return -1;
	/* LI counts from "after itself" to end of TPDU.  In a CR the
	 * X.224 header is fixed at 6 bytes after LI (code+2+2+1), and
	 * everything after that is body. */
	if ((size_t)li + 1u > len)
		return -1;
	if (li < 6)
		return -1;
	body_off = hdr_consumed;
	body_end = (size_t)li + 1u;
	if (body_end > len)
		return -1;

	p = buf + body_off;
	{
		size_t remaining = body_end - body_off;
		size_t i = 0;

		/* Optional Cookie line "Cookie: ...\r\n" (RDP cookie) or
		 * "\x03\x0D" routing token (the byte 0x03 followed by 0x0D
		 * was observed in older Windows clients).  Either way we
		 * track its slice and skip past the terminating CRLF. */
		if (remaining >= 7 && memcmp(p, "Cookie:", 7) == 0) {
			while (i + 1 < remaining) {
				if (p[i] == '\r' && p[i + 1] == '\n')
					break;
				i++;
			}
			if (i + 1 >= remaining)
				return -1;   /* unterminated cookie */
			out->cookie = p;
			out->cookie_len = i + 2;
			i += 2;
		} else if (remaining >= 1 && p[0] == 0x03) {
			/* Routing token: starts with 0x03 0x0D, ends \r\n.
			 * We accept just "starts with 0x03" defensively. */
			while (i + 1 < remaining) {
				if (p[i] == '\r' && p[i + 1] == '\n')
					break;
				i++;
			}
			if (i + 1 >= remaining)
				return -1;
			out->cookie = p;
			out->cookie_len = i + 2;
			i += 2;
		}

		/* Optional RDP_NEG_REQ -- 8 bytes (type, flags, len16, proto32). */
		if (remaining - i >= 8 && p[i] == RDP_NEG_TYPE_REQ) {
			uint8_t  flags;
			uint16_t neg_len;
			uint32_t proto;

			flags = p[i + 1];
			neg_len = (uint16_t)p[i + 2] | ((uint16_t)p[i + 3] << 8);
			proto = (uint32_t)p[i + 4]
				| ((uint32_t)p[i + 5] << 8)
				| ((uint32_t)p[i + 6] << 16)
				| ((uint32_t)p[i + 7] << 24);
			if (neg_len != 8)
				return -1;
			out->have_neg_req = 1;
			out->neg_flags = flags;
			out->requested_protocols = proto;
			i += 8;

			/* Optional 36-byte correlation info block, skipped. */
			if (flags & RDP_NEG_CORRELATION_INFO_PRESENT) {
				if (remaining - i < 36)
					return -1;
				i += 36;
			}
		}

		/* Any trailing bytes are unusual but not necessarily fatal.
		 * The spec lets the body end on a boundary.  We don't object. */
	}

	return 0;
}

ssize_t
rdp_x224_build_cc(uint8_t *out, size_t cap,
		int want_failure, uint32_t selected_protocols,
		uint32_t failure_code)
{
	struct rdp_buf b;
	uint8_t li;
	size_t total;

	if (want_failure) {
		total = 7 + 8;
	} else {
		total = 7 + (selected_protocols == 0 ? 0 : 8);
	}
	/* When the body holds the negotiate PDU, LI = total - 1.
	 * When no negotiate PDU is present (e.g. plain "RDP" only),
	 * LI = 6.  We always emit a negotiate PDU when proto != 0,
	 * and never emit a CC with neither. */
	if (total > cap)
		return -1;
	li = (uint8_t)(total - 1);

	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, li) != 0) return -1;
	if (rdp_buf_put_u8(&b, RDP_X224_CC) != 0) return -1;
	if (rdp_buf_put_u16be(&b, 0) != 0) return -1;  /* dst-ref */
	if (rdp_buf_put_u16be(&b, 0) != 0) return -1;  /* src-ref */
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;     /* class/option */

	if (want_failure) {
		if (rdp_buf_put_u8(&b, RDP_NEG_TYPE_FAILURE) != 0) return -1;
		if (rdp_buf_put_u8(&b, 0) != 0) return -1;       /* flags */
		if (rdp_buf_put_u16le(&b, 8) != 0) return -1;     /* length */
		if (rdp_buf_put_u32le(&b, failure_code) != 0) return -1;
	} else if (selected_protocols != 0) {
		if (rdp_buf_put_u8(&b, RDP_NEG_TYPE_RSP) != 0) return -1;
		if (rdp_buf_put_u8(&b, RDP_NEG_RSP_EXTENDED_CLIENT_DATA |
			RDP_NEG_RSP_DYNVC_GFX) != 0) return -1;
		if (rdp_buf_put_u16le(&b, 8) != 0) return -1;     /* length */
		if (rdp_buf_put_u32le(&b, selected_protocols) != 0) return -1;
	}

	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_x224_build_dt(uint8_t *out, size_t cap)
{
	if (cap < RDP_X224_HDR_LEN_DT)
		return -1;
	out[0] = 0x02;             /* LI = 2 */
	out[1] = RDP_X224_DT | 0x00;  /* DT TPDU, ROA=0 */
	out[2] = 0x80;             /* EOT bit, TPDU-NR = 0 */
	return RDP_X224_HDR_LEN_DT;
}

ssize_t
rdp_x224_parse_dt(const uint8_t *buf, size_t len)
{
	if (len < RDP_X224_HDR_LEN_DT)
		return -1;
	if (buf[0] != 0x02)
		return -1;
	if ((buf[1] & 0xf0) != RDP_X224_DT)
		return -1;
	/* buf[2] high bit is the EOT flag; we accept 0x80 or 0x00. */
	return RDP_X224_HDR_LEN_DT;
}
