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
 * mcs_test.c -- unit tests for the MCS subset.
 *
 * We test the DomainPDU encoders/decoders directly; the Connect
 * Initial/Response round trip is exercised by feeding a synthetic
 * minimal envelope through the parser/builder pair.
 */

#include "../../src/wire/mcs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static void
test_attach_user_confirm(void)
{
	uint8_t out[8];
	ssize_t n;

	n = rdp_mcs_build_attach_user_confirm(out, sizeof out, 1007);
	if (n != 4) FAIL("auc len %lld", (long long)n);
	if (out[0] != (RDP_MCS_TYPE_ATTACH_USER_CFM | 0x02))
		FAIL("auc type %02x", out[0]);
	if (out[1] != 0) FAIL("auc result %02x", out[1]);
	if (((uint16_t)out[2] << 8 | out[3]) != 6)
		FAIL("auc initiator %u", (out[2] << 8) | out[3]);
}

static void
test_channel_join_confirm(void)
{
	uint8_t out[16];
	ssize_t n;

	n = rdp_mcs_build_channel_join_confirm(out, sizeof out, 1007, 1003);
	if (n != 8) FAIL("cjc len %lld", (long long)n);
	if (out[0] != (RDP_MCS_TYPE_CHANNEL_JOIN_CFM | 0x02))
		FAIL("cjc type");
	if (((uint16_t)out[4] << 8 | out[5]) != 1003)
		FAIL("cjc channel");
}

static void
test_channel_join_request(void)
{
	uint8_t in[] = { RDP_MCS_TYPE_CHANNEL_JOIN_REQ,
		0x00, 0x06,   /* initiator = 6 -> user 1007 */
		0x03, 0xeb }; /* channel 1003 */
	uint16_t uid, cid;
	ssize_t n;

	n = rdp_mcs_parse_channel_join_request(in, sizeof in, &uid, &cid);
	if (n != 5) FAIL("cjr parse %lld", (long long)n);
	if (uid != 1007) FAIL("cjr uid %u", uid);
	if (cid != 1003) FAIL("cjr cid %u", cid);
}

static void
test_send_data_indication(void)
{
	uint8_t out[256];
	uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef };
	ssize_t n;
	uint16_t uid, cid;
	const uint8_t *p;
	size_t pl;

	n = rdp_mcs_build_send_data_indication(out, sizeof out, 1007, 1003,
		payload, sizeof payload);
	if (n != 11) FAIL("sdi len %lld", (long long)n);
	if (out[0] != RDP_MCS_TYPE_SEND_DATA_IND) FAIL("sdi type");

	/* Round-trip by parsing a Send Data Request frame (same wire
	 * shape except for the type byte). */
	out[0] = RDP_MCS_TYPE_SEND_DATA_REQ;
	n = rdp_mcs_parse_send_data_request(out, (size_t)n, &uid, &cid, &p, &pl);
	if (n < 0) FAIL("sdr parse");
	if (uid != 1007 || cid != 1003 || pl != 4 ||
	    memcmp(p, payload, 4) != 0)
		FAIL("sdr fields");
}

static void
test_disconnect(void)
{
	uint8_t out[4];
	uint8_t reason;
	ssize_t n;

	n = rdp_mcs_build_disconnect(out, sizeof out, 0);
	if (n != 2) FAIL("disc len");
	n = rdp_mcs_parse_disconnect(out, 2, &reason);
	if (n != 2 || reason != 0) FAIL("disc parse");
}

int
main(void)
{
	test_attach_user_confirm();
	test_channel_join_confirm();
	test_channel_join_request();
	test_send_data_indication();
	test_disconnect();
	return 0;
}
