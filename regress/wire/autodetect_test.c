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
 * autodetect_test.c -- MS-RDPBCGR Network Auto-Detection PDU build/parse.
 *
 * Checks the exact wire bytes of each connect-time request, the parse of
 * the RTT and bandwidth-result responses (including truncated and
 * mistyped PDUs, covered by $(TEST_SAN)), and the kbps computation.
 */

#include "../../src/channels/autodetect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
expect(const char *what, const uint8_t *got, size_t got_len,
		const uint8_t *want, size_t want_len)
{
	if (got_len != want_len)
		FAIL("%s: len %zu want %zu", what, got_len, want_len);
	if (memcmp(got, want, want_len) != 0)
		FAIL("%s: bytes differ", what);
}

static void
test_build(void)
{
	uint8_t out[64];
	ssize_t n;

	/* RTT Measure Request: len 0x06, type REQ, seq 0x0023, 0x1001. */
	n = rdp_autodetect_build_rtt_request(out, sizeof out, 0x0023);
	if (n != 6) FAIL("rtt req len %zd", (ssize_t)n);
	expect("rtt req", out, (size_t)n,
		(const uint8_t[]){ 0x06, 0x00, 0x23, 0x00, 0x01, 0x10 }, 6);

	/* Bandwidth Measure Start: 0x1014. */
	n = rdp_autodetect_build_bw_start(out, sizeof out, 0x0001);
	if (n != 6) FAIL("bw start len %zd", (ssize_t)n);
	expect("bw start", out, (size_t)n,
		(const uint8_t[]){ 0x06, 0x00, 0x01, 0x00, 0x14, 0x10 }, 6);

	/* Bandwidth Payload: header(8) + payloadLength + random.  payload_len
	 * 17 rounds down to 16. */
	n = rdp_autodetect_build_bw_payload(out, sizeof out, 0x0002, 17);
	if (n != 8 + 16) FAIL("bw payload len %zd", (ssize_t)n);
	expect("bw payload head", out, 8,
		(const uint8_t[]){ 0x08, 0x00, 0x02, 0x00,
				   0x02, 0x00, 0x10, 0x00 }, 8);

	/* Bandwidth Stop (connect-time): 0x002B + payloadLength 0. */
	n = rdp_autodetect_build_bw_stop(out, sizeof out, 0x0003);
	if (n != 8) FAIL("bw stop len %zd", (ssize_t)n);
	expect("bw stop", out, (size_t)n,
		(const uint8_t[]){ 0x08, 0x00, 0x03, 0x00,
				   0x2B, 0x00, 0x00, 0x00 }, 8);

	/* Network Characteristics Result 0x08C0. */
	n = rdp_autodetect_build_netchar_result(out, sizeof out, 0x0004,
		10, 5000, 12);
	if (n != 18) FAIL("netchar len %zd", (ssize_t)n);
	expect("netchar", out, (size_t)n,
		(const uint8_t[]){ 0x12, 0x00, 0x04, 0x00, 0xC0, 0x08,
				   10, 0, 0, 0,
				   0x88, 0x13, 0, 0,      /* 5000 LE */
				   12, 0, 0, 0 }, 18);
}

static void
test_parse(void)
{
	struct rdp_autodetect_rsp r;
	/* RTT response: header only, type 0x0000. */
	const uint8_t rtt[] = { 0x06, 0x01, 0x23, 0x00, 0x00, 0x00 };
	/* Bandwidth results: timeDelta 100, byteCount 125000 (-> 10000 kbps).
	 * 125000 = 0x0001E848, little-endian 0x48 0xE8 0x01 0x00. */
	const uint8_t bw[] = { 0x0E, 0x01, 0x05, 0x00, 0x03, 0x00,
		100, 0, 0, 0, 0x48, 0xE8, 0x01, 0 };
	const uint8_t bad_type[] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const uint8_t bw_short[] = { 0x0E, 0x01, 0x00, 0x00, 0x03, 0x00,
		1, 0, 0, 0 };
	const uint8_t bw_badlen[] = { 0x06, 0x01, 0x00, 0x00, 0x03, 0x00,
		1, 0, 0, 0, 2, 0, 0, 0 };

	if (rdp_autodetect_parse_response(rtt, sizeof rtt, &r) != 0)
		FAIL("parse rtt");
	if (r.response_type != RDP_AUTODETECT_RTT_RSP || r.seq != 0x23)
		FAIL("rtt fields");

	if (rdp_autodetect_parse_response(bw, sizeof bw, &r) != 0)
		FAIL("parse bw");
	if (r.response_type != RDP_AUTODETECT_BW_RESULTS)
		FAIL("bw type");
	if (r.time_delta != 100 || r.byte_count != 125000)
		FAIL("bw fields td=%u bc=%u", r.time_delta, r.byte_count);

	/* Malformed inputs must be rejected, never over-read. */
	if (rdp_autodetect_parse_response(rtt, 5, &r) != -1)
		FAIL("short header accepted");
	if (rdp_autodetect_parse_response(bad_type, sizeof bad_type, &r) != -1)
		FAIL("wrong typeId accepted");
	if (rdp_autodetect_parse_response(bw_short, sizeof bw_short, &r) != -1)
		FAIL("truncated bw results accepted");
	if (rdp_autodetect_parse_response(bw_badlen, sizeof bw_badlen, &r) != -1)
		FAIL("bw results with wrong headerLength accepted");

	/* kbps = byteCount*8 / timeDelta. */
	if (rdp_autodetect_bandwidth_kbps(125000, 100) != 10000)
		FAIL("kbps math");
	if (rdp_autodetect_bandwidth_kbps(1234, 0) != 0)
		FAIL("kbps divide by zero");
}

int
main(void)
{
	test_build();
	test_parse();
	(void)printf("autodetect_test: all ok\n");
	return 0;
}
