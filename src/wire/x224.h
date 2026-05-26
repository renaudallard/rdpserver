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
 * x224.h -- ITU-T X.224 Class 0 over TPKT.
 *
 * RDP uses two X.224 PDU types: Connection Request (CR) and
 * Connection Confirm (CC) during handshake, then Data (DT) for
 * everything else.  Encoding follows MS-RDPBCGR 2.2.1.1 / 2.2.1.2
 * and ITU-T Rec. X.224 (1995).
 *
 * Header layout (after TPKT preamble):
 *   off 0  LI         (1)   header length minus this byte
 *   off 1  code       (1)   0xE0=CR, 0xD0=CC, 0xF0=DT, 0x80=DR
 *   off 2  dst-ref    (2)   echoed reference (we use 0)
 *   off 4  src-ref    (2)   our reference (we use 0)
 *   off 6  class/opt  (1)   class 0 = 0x00
 *
 * For CR/CC the body that follows the X.224 header may contain a
 * routing/cookie token, then an RDP_NEG_REQ / RDP_NEG_RSP /
 * RDP_NEG_FAILURE (MS-RDPBCGR 2.2.1.1.1/2.2.1.2.1/2.2.1.2.2).
 *
 * For DT, code is 0xF0 with EOT bit set (0x80 ORed) and LI is 2,
 * so the X.224 header is 3 bytes total.
 */

#ifndef RDP_X224_H
#define RDP_X224_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>

#define RDP_X224_CR 0xE0u
#define RDP_X224_CC 0xD0u
#define RDP_X224_DT 0xF0u
#define RDP_X224_DR 0x80u

#define RDP_X224_HDR_LEN_CRCC 7u   /* LI + code + 2 refs + 2 refs + class/opt */
#define RDP_X224_HDR_LEN_DT   3u   /* LI + (code|EOT) + eot/seq */

/* RDP_NEG_* PDUs that ride after the X.224 CR/CC header. */
#define RDP_NEG_TYPE_REQ      0x01u
#define RDP_NEG_TYPE_RSP      0x02u
#define RDP_NEG_TYPE_FAILURE  0x03u

/* RDP_NEG_REQ flags. */
#define RDP_NEG_RESTRICTED_ADMIN_MODE_REQUIRED 0x01u
#define RDP_NEG_REDIRECTED_AUTHENTICATION      0x02u
#define RDP_NEG_CORRELATION_INFO_PRESENT       0x08u

/* Protocol flags (selectedProtocols / requestedProtocols / flags). */
#define RDP_PROTO_RDP        0x00000000u
#define RDP_PROTO_SSL        0x00000001u
#define RDP_PROTO_HYBRID     0x00000002u
#define RDP_PROTO_RDSTLS     0x00000004u
#define RDP_PROTO_HYBRID_EX  0x00000008u

/* RDP_NEG_RSP flags. */
#define RDP_NEG_RSP_EXTENDED_CLIENT_DATA  0x01u
#define RDP_NEG_RSP_DYNVC_GFX            0x02u

/* RDP_NEG_FAILURE failureCodes. */
#define RDP_NEG_FAIL_SSL_REQUIRED_BY_SERVER         1u
#define RDP_NEG_FAIL_SSL_NOT_ALLOWED_BY_SERVER      2u
#define RDP_NEG_FAIL_SSL_CERT_NOT_ON_SERVER         3u
#define RDP_NEG_FAIL_INCONSISTENT_FLAGS             4u
#define RDP_NEG_FAIL_HYBRID_REQUIRED_BY_SERVER      5u
#define RDP_NEG_FAIL_SSL_WITH_USER_AUTH_REQUIRED    6u

/* Parsed CR. */
struct rdp_x224_cr {
	int      have_neg_req;
	uint8_t  neg_flags;
	uint32_t requested_protocols;
	/* Slice of the cookie/routing area (between the X.224 header and
	 * the optional RDP_NEG_REQ).  Owned by the caller's buffer. */
	const uint8_t *cookie;
	size_t         cookie_len;
};

/* Parse an X.224 CR sitting at `buf` (length `len`, which is the
 * portion *after* the TPKT header, equal to TPKT length - 4).
 * Returns 0 on success and fills *out, -1 on malformed input. */
int rdp_x224_parse_cr(struct rdp_x224_cr *out,
		const uint8_t *buf, size_t len);

/* Build a CC into `out` (capacity `cap`).  If `selected_protocols`
 * is set, an RDP_NEG_RSP is appended advertising it.  Returns the
 * number of bytes written, or -1 on overflow.  Caller wraps in a
 * TPKT.  Pass want_failure=1 and failure_code=N to send a
 * RDP_NEG_FAILURE instead. */
ssize_t rdp_x224_build_cc(uint8_t *out, size_t cap,
		int want_failure, uint32_t selected_protocols,
		uint32_t failure_code);

/* Build a DT (data) header in `out` (capacity at least 3 bytes).
 * Returns 3 on success, -1 on overflow.  Caller writes the payload
 * after byte index 3. */
ssize_t rdp_x224_build_dt(uint8_t *out, size_t cap);

/* Parse the leading X.224 DT header from `buf` (length `len`).
 * On success returns the number of bytes consumed (3) so the caller
 * can advance past the header to the MCS PDU.  Returns -1 if the
 * header is malformed. */
ssize_t rdp_x224_parse_dt(const uint8_t *buf, size_t len);

#endif /* RDP_X224_H */
