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
 * capset_test.c -- spot-check Demand Active byte layout.
 */

#include "../../src/wire/capset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static void
test_demand_active(void)
{
	uint8_t buf[2048];
	ssize_t n;
	uint16_t cap_count;

	n = rdp_capset_build_demand_active(buf, sizeof buf, 0x103EAu,
		1280, 720, 0, 0);
	if (n < 32) FAIL("demand active too short: %lld", (long long)n);
	/* shareId = 0x103EA at offset 0 (LE). */
	if (buf[0] != 0xea || buf[1] != 0x03 || buf[2] != 0x01 || buf[3] != 0)
		FAIL("shareId wrong: %02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3]);
	/* lengthSourceDescriptor at offset 4 LE = strlen("RDP")+1 = 4. */
	if (buf[4] != 4 || buf[5] != 0) FAIL("lenSrc");
	/* Source descriptor "RDP\0" at offset 8. */
	if (memcmp(buf + 8, "RDP\0", 4) != 0) FAIL("src descriptor");
	/* numberCapabilities follows at offset 12 (LE). */
	cap_count = (uint16_t)buf[12] | ((uint16_t)buf[13] << 8);
	if (cap_count != 11) FAIL("cap_count = %u", cap_count);

	/* RemoteApp mode adds the RAIL and Window List capability sets. */
	n = rdp_capset_build_demand_active(buf, sizeof buf, 0x103EAu,
		1280, 720, 1, 0);
	if (n < 32) FAIL("remoteapp demand active too short");
	cap_count = (uint16_t)buf[12] | ((uint16_t)buf[13] << 8);
	if (cap_count != 13) FAIL("remoteapp cap_count = %u", cap_count);

	/* Bitmap cache adds only the host-support capability set; the Rev2 cap
	 * is client-to-server and must not appear in a server demand-active. */
	n = rdp_capset_build_demand_active(buf, sizeof buf, 0x103EAu,
		1280, 720, 0, 1);
	if (n < 32) FAIL("bitmap-cache demand active too short");
	cap_count = (uint16_t)buf[12] | ((uint16_t)buf[13] << 8);
	if (cap_count != 12) FAIL("bitmap-cache cap_count = %u", cap_count);
}

/* Build an Order capability set (88 bytes); set the MemBlt orderSupport slot
 * when memblt is non-zero.  orderSupport[] starts 32 bytes into the body. */
static size_t
order_cap(uint8_t *p, int memblt)
{
	memset(p, 0, 88);
	p[0] = RDP_CAP_ORDER & 0xff; p[1] = RDP_CAP_ORDER >> 8;
	p[2] = 88; p[3] = 0;
	if (memblt)
		p[4 + 32 + RDP_ORDER_NEG_MEMBLT_INDEX] = 1;
	return 88;
}

/* Build a Bitmap Cache Rev2 capability set (40 bytes). */
static size_t
rev2_cap(uint8_t *p)
{
	memset(p, 0, 40);
	p[0] = RDP_CAP_BITMAPCACHE_REV2 & 0xff;
	p[1] = RDP_CAP_BITMAPCACHE_REV2 >> 8;
	p[2] = 40; p[3] = 0;
	return 40;
}

/* Wrap concatenated capability sets in a Confirm Active body. */
static size_t
build_confirm(uint8_t *buf, const uint8_t *caps, size_t caps_len,
    uint16_t cap_count)
{
	uint16_t lenComb = (uint16_t)(4 + caps_len);   /* capCount+pad2+caps */
	size_t off;
	memset(buf, 0, 6);                             /* shareId, originatorId */
	off = 6;
	buf[off++] = 4; buf[off++] = 0;                /* lengthSourceDescriptor */
	buf[off++] = (uint8_t)lenComb; buf[off++] = (uint8_t)(lenComb >> 8);
	memcpy(buf + off, "RDP", 3); buf[off + 3] = 0; off += 4;
	buf[off++] = (uint8_t)cap_count; buf[off++] = (uint8_t)(cap_count >> 8);
	buf[off++] = 0; buf[off++] = 0;                /* pad2 */
	memcpy(buf + off, caps, caps_len); off += caps_len;
	return off;
}

static void
test_parse_confirm_active(void)
{
	uint8_t caps[256], buf[512];
	size_t cl, n;
	int ok;

	/* MemBlt order support + Rev2 cache cap -> the client accepts orders. */
	cl = order_cap(caps, 1);
	cl += rev2_cap(caps + cl);
	n = build_confirm(buf, caps, cl, 2);
	ok = -1;
	if (rdp_capset_parse_confirm_active(buf, n, NULL, NULL, NULL, NULL,
	    NULL, &ok) != 0) FAIL("parse memblt+rev2");
	if (ok != 1) FAIL("memblt+rev2 -> ok=%d", ok);

	/* MemBlt but no Rev2 cap (cache disabled) -> orders must not be used. */
	cl = order_cap(caps, 1);
	n = build_confirm(buf, caps, cl, 1);
	ok = -1;
	if (rdp_capset_parse_confirm_active(buf, n, NULL, NULL, NULL, NULL,
	    NULL, &ok) != 0) FAIL("parse memblt-only");
	if (ok != 0) FAIL("memblt-only -> ok=%d", ok);

	/* Rev2 cap but MemBlt slot zero -> orders must not be used. */
	cl = order_cap(caps, 0);
	cl += rev2_cap(caps + cl);
	n = build_confirm(buf, caps, cl, 2);
	ok = -1;
	if (rdp_capset_parse_confirm_active(buf, n, NULL, NULL, NULL, NULL,
	    NULL, &ok) != 0) FAIL("parse rev2-no-memblt");
	if (ok != 0) FAIL("rev2-no-memblt -> ok=%d", ok);
}

int
main(void)
{
	test_demand_active();
	test_parse_confirm_active();
	return 0;
}
