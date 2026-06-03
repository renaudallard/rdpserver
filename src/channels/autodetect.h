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
 * autodetect.h -- MS-RDPBCGR Network Characteristics Detection.
 *
 * Connect-time auto-detection: the server measures the round-trip time
 * and link bandwidth before the session activates.  Each message is the
 * payload that follows the 4-byte security header (sent with the
 * SEC_AUTODETECT_REQ flag, received with SEC_AUTODETECT_RSP) on the MCS
 * message channel.  The common header is headerLength(u8) +
 * headerTypeId(u8) + sequenceNumber(u16) + request/responseType(u16),
 * all little-endian.
 */

#ifndef RDP_AUTODETECT_H
#define RDP_AUTODETECT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RDP_AUTODETECT_TYPE_REQ   0x00   /* headerTypeId, server -> client */
#define RDP_AUTODETECT_TYPE_RSP   0x01   /* headerTypeId, client -> server */

/* request/response types (connect-time variants). */
#define RDP_AUTODETECT_RTT_REQ        0x1001
#define RDP_AUTODETECT_RTT_RSP        0x0000
#define RDP_AUTODETECT_BW_START       0x1014
#define RDP_AUTODETECT_BW_PAYLOAD     0x0002
#define RDP_AUTODETECT_BW_STOP        0x002B
#define RDP_AUTODETECT_BW_RESULTS     0x0003
#define RDP_AUTODETECT_NETCHAR_RESULT 0x08C0   /* baseRTT + bandwidth + avgRTT */
#define RDP_AUTODETECT_NETCHAR_SYNC   0x0018

/* Build the RTT Measure Request payload (6 bytes). */
ssize_t rdp_autodetect_build_rtt_request(uint8_t *out, size_t cap,
		uint16_t seq);

/* Build the Bandwidth Measure Start payload (6 bytes). */
ssize_t rdp_autodetect_build_bw_start(uint8_t *out, size_t cap,
		uint16_t seq);

/* Build a Bandwidth Measure Payload: an 8-byte header followed by
 * payload_len random bytes (rounded down to a multiple of 4).  Returns
 * the total byte count. */
ssize_t rdp_autodetect_build_bw_payload(uint8_t *out, size_t cap,
		uint16_t seq, uint16_t payload_len);

/* Build the connect-time Bandwidth Measure Stop payload (8 bytes,
 * trailing payloadLength forced to 0). */
ssize_t rdp_autodetect_build_bw_stop(uint8_t *out, size_t cap,
		uint16_t seq);

/* Build the Network Characteristics Result payload (0x08C0 form: baseRTT
 * + bandwidth + averageRTT, 18 bytes). */
ssize_t rdp_autodetect_build_netchar_result(uint8_t *out, size_t cap,
		uint16_t seq, uint32_t base_rtt, uint32_t bandwidth,
		uint32_t avg_rtt);

struct rdp_autodetect_rsp {
	uint8_t  header_len;
	uint16_t seq;
	uint16_t response_type;
	/* Bandwidth Measure Results carry these; zero otherwise. */
	uint32_t time_delta;   /* milliseconds */
	uint32_t byte_count;   /* bytes transferred */
};

/* Parse an autodetect response payload (the bytes after the security
 * header).  Validates the common header and headerTypeId == RSP.  Returns
 * 0 on success with *out filled, -1 on a malformed or truncated PDU. */
int rdp_autodetect_parse_response(const uint8_t *p, size_t len,
		struct rdp_autodetect_rsp *out);

/* Bandwidth in kilobits per second from a Bandwidth Measure Result.
 * Returns 0 when time_delta is 0 (avoids divide-by-zero). */
uint32_t rdp_autodetect_bandwidth_kbps(uint32_t byte_count,
		uint32_t time_delta);

#endif /* RDP_AUTODETECT_H */
