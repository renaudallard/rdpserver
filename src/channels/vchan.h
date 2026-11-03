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
 * vchan.h -- static virtual channel PDU reassembly (MS-RDPBCGR 2.2.6.1).
 *
 * A channel PDU larger than the negotiated chunk size arrives as a run of
 * MCS Send Data payloads, each prefixed by a CHANNEL_PDU_HEADER carrying
 * the total PDU length and the CHANNEL_FLAG_FIRST / CHANNEL_FLAG_LAST
 * bits. Feed each chunk body; a complete PDU is returned for dispatch.
 * max_pdu bounds the accumulator so a hostile peer cannot drive unbounded
 * allocation.
 */

#ifndef RDP_VCHAN_H
#define RDP_VCHAN_H

#include <stddef.h>
#include <stdint.h>

/* Channel PDU header flags (MS-RDPBCGR 2.2.6.1.1). */
#define CHANNEL_FLAG_FIRST           0x00000001
#define CHANNEL_FLAG_LAST            0x00000002
#define CHANNEL_FLAG_SHOW_PROTOCOL   0x00000010

#define RDP_VC_PDU_HDR_LEN 8

struct rdp_vc_reasm {
	uint8_t *buf;
	size_t   cap;
	size_t   len;
	size_t   max_pdu;
	int      active;
};

void rdp_vc_reasm_init(struct rdp_vc_reasm *r, size_t max_pdu);
void rdp_vc_reasm_reset(struct rdp_vc_reasm *r);

/*
 * Feed one chunk body. `total` is the CHANNEL_PDU_HEADER length field
 * (present on every chunk), `flags` its FIRST/LAST bits. On a complete
 * PDU, sets *pdu / *pdu_len (valid until the next feed or reset) and
 * returns 1; the caller dispatches then calls reset. Returns 0 when more
 * chunks are needed, or -1 on a malformed or oversize stream (the
 * accumulator is reset). A single FIRST|LAST chunk is returned in place
 * with no copy.
 */
int rdp_vc_reasm_feed(struct rdp_vc_reasm *r,
		const uint8_t *frag, size_t frag_len,
		uint32_t total, uint32_t flags,
		const uint8_t **pdu, size_t *pdu_len);

/*
 * Split a received channel payload into its CHANNEL_PDU_HEADER and body
 * and feed the body. Same return values as rdp_vc_reasm_feed; a payload
 * too short to hold the header returns -1.
 */
int rdp_vc_reasm_feed_payload(struct rdp_vc_reasm *r,
		const uint8_t *payload, size_t payload_len,
		const uint8_t **pdu, size_t *pdu_len);

#endif /* RDP_VCHAN_H */
