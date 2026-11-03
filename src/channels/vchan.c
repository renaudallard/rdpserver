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
 * vchan.c -- static virtual channel PDU reassembly.
 */

#include "vchan.h"

#include <stdlib.h>
#include <string.h>

void
rdp_vc_reasm_init(struct rdp_vc_reasm *r, size_t max_pdu)
{
	r->buf = NULL;
	r->cap = 0;
	r->len = 0;
	r->max_pdu = max_pdu;
	r->active = 0;
}

void
rdp_vc_reasm_reset(struct rdp_vc_reasm *r)
{
	free(r->buf);
	r->buf = NULL;
	r->cap = 0;
	r->len = 0;
	r->active = 0;
}

int
rdp_vc_reasm_feed(struct rdp_vc_reasm *r,
		const uint8_t *frag, size_t frag_len,
		uint32_t total, uint32_t flags,
		const uint8_t **pdu, size_t *pdu_len)
{
	/* A self-contained single fragment is the common case: hand it back
	 * in place with no allocation. */
	if ((flags & CHANNEL_FLAG_FIRST) && (flags & CHANNEL_FLAG_LAST)) {
		rdp_vc_reasm_reset(r);
		*pdu = frag;
		*pdu_len = frag_len;
		return 1;
	}
	if (flags & CHANNEL_FLAG_FIRST) {
		rdp_vc_reasm_reset(r);
		if (total == 0 || total > r->max_pdu)
			return -1;
		r->buf = malloc(total);
		if (r->buf == NULL)
			return -1;
		r->cap = total;
		r->active = 1;
	}
	if (!r->active)
		return -1;   /* a NEXT/LAST fragment without a FIRST */
	if (frag_len > r->cap - r->len) {
		rdp_vc_reasm_reset(r);
		return -1;   /* fragment overruns the declared total */
	}
	memcpy(r->buf + r->len, frag, frag_len);
	r->len += frag_len;
	if (flags & CHANNEL_FLAG_LAST) {
		*pdu = r->buf;
		*pdu_len = r->len;
		return 1;
	}
	return 0;
}

int
rdp_vc_reasm_feed_payload(struct rdp_vc_reasm *r,
		const uint8_t *payload, size_t payload_len,
		const uint8_t **pdu, size_t *pdu_len)
{
	uint32_t total, flags;

	if (payload_len < RDP_VC_PDU_HDR_LEN)
		return -1;
	total = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8)
		| ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
	flags = (uint32_t)payload[4] | ((uint32_t)payload[5] << 8)
		| ((uint32_t)payload[6] << 16) | ((uint32_t)payload[7] << 24);
	return rdp_vc_reasm_feed(r, payload + RDP_VC_PDU_HDR_LEN,
		payload_len - RDP_VC_PDU_HDR_LEN, total, flags, pdu, pdu_len);
}
