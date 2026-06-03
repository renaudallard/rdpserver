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
 * autodetect.c -- MS-RDPBCGR Network Characteristics Detection PDUs.
 */

#include "autodetect.h"

#include "../common/buf.h"
#include "../common/rand.h"

static ssize_t
build_header(struct rdp_buf *b, uint8_t header_len, uint16_t seq,
		uint16_t req_type)
{
	if (rdp_buf_put_u8(b, header_len) != 0) return -1;
	if (rdp_buf_put_u8(b, RDP_AUTODETECT_TYPE_REQ) != 0) return -1;
	if (rdp_buf_put_u16le(b, seq) != 0) return -1;
	if (rdp_buf_put_u16le(b, req_type) != 0) return -1;
	return 0;
}

ssize_t
rdp_autodetect_build_rtt_request(uint8_t *out, size_t cap, uint16_t seq)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (build_header(&b, 0x06, seq, RDP_AUTODETECT_RTT_REQ) != 0)
		return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_autodetect_build_bw_start(uint8_t *out, size_t cap, uint16_t seq)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (build_header(&b, 0x06, seq, RDP_AUTODETECT_BW_START) != 0)
		return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_autodetect_build_bw_payload(uint8_t *out, size_t cap, uint16_t seq,
		uint16_t payload_len)
{
	struct rdp_buf b;
	uint8_t *p;
	payload_len = (uint16_t)(payload_len & ~3u);   /* 4-byte aligned */
	rdp_buf_init(&b, out, cap);
	if (build_header(&b, 0x08, seq, RDP_AUTODETECT_BW_PAYLOAD) != 0)
		return -1;
	if (rdp_buf_put_u16le(&b, payload_len) != 0) return -1;
	/* Random bytes so a compressing transport cannot shrink them and
	 * skew the measurement. */
	p = rdp_buf_reserve(&b, payload_len);
	if (p == NULL) return -1;
	rdp_rand_bytes(p, payload_len);
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_autodetect_build_bw_stop(uint8_t *out, size_t cap, uint16_t seq)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (build_header(&b, 0x08, seq, RDP_AUTODETECT_BW_STOP) != 0)
		return -1;
	/* Connect-time stop carries a payloadLength field; we send none. */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_autodetect_build_netchar_result(uint8_t *out, size_t cap, uint16_t seq,
		uint32_t base_rtt, uint32_t bandwidth, uint32_t avg_rtt)
{
	struct rdp_buf b;
	rdp_buf_init(&b, out, cap);
	if (build_header(&b, 0x12, seq, RDP_AUTODETECT_NETCHAR_RESULT) != 0)
		return -1;
	if (rdp_buf_put_u32le(&b, base_rtt) != 0) return -1;
	if (rdp_buf_put_u32le(&b, bandwidth) != 0) return -1;
	if (rdp_buf_put_u32le(&b, avg_rtt) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int
rdp_autodetect_parse_response(const uint8_t *p, size_t len,
		struct rdp_autodetect_rsp *out)
{
	if (len < 6) return -1;
	if (p[1] != RDP_AUTODETECT_TYPE_RSP) return -1;
	out->header_len = p[0];
	out->seq = ld16(p + 2);
	out->response_type = ld16(p + 4);
	out->time_delta = 0;
	out->byte_count = 0;
	if (out->response_type == RDP_AUTODETECT_BW_RESULTS) {
		/* header(6) + timeDelta(4) + byteCount(4) */
		if (len < 14 || out->header_len != 0x0E) return -1;
		out->time_delta = ld32(p + 6);
		out->byte_count = ld32(p + 10);
	}
	return 0;
}

uint32_t
rdp_autodetect_bandwidth_kbps(uint32_t byte_count, uint32_t time_delta)
{
	/* bits / milliseconds == kilobits per second. */
	if (time_delta == 0) return 0;
	return (uint32_t)(((uint64_t)byte_count * 8) / time_delta);
}
