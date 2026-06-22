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
 * rdpgfx_test.c -- RDPGFX_CMDID_CAPSADVERTISE parser bounds hardening.
 *
 * Exercises a well-formed advertise plus the malicious shapes a hostile client
 * can send: a cap-set length that runs past the PDU, a length that would
 * integer-overflow the bounds arithmetic, more cap sets than the slot array
 * holds, and trailing bytes from a following PDU that must not be parsed as
 * extra cap sets (the pduLength field bounds the walk).
 */

#include "../../src/channels/rdpgfx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t
get32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
	    | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Build a CAPSADVERTISE header at buf: cmdId, flags=0, pduLength, count. */
static size_t
hdr(uint8_t *buf, uint32_t pdu_len, uint16_t count)
{
	buf[0] = (uint8_t)(RDPGFX_CMDID_CAPSADVERTISE & 0xff);
	buf[1] = (uint8_t)(RDPGFX_CMDID_CAPSADVERTISE >> 8);
	buf[2] = 0; buf[3] = 0;                 /* flags */
	put32(buf + 4, pdu_len);                /* pduLength */
	buf[8] = (uint8_t)(count & 0xff);
	buf[9] = (uint8_t)(count >> 8);
	return 10;
}

/* Append a cap set (version, dataLength, then dataLength bytes of which the
 * first 4 are flags when present). */
static size_t
capset(uint8_t *p, uint32_t ver, uint32_t dlen, uint32_t flags)
{
	put32(p, ver);
	put32(p + 4, dlen);
	if (dlen >= 4) put32(p + 8, flags);
	return 8 + dlen;
}

static int
may_send(uint32_t last_ack, uint32_t frame_id, uint32_t qd)
{
	struct rdpgfx_state g;
	memset(&g, 0, sizeof g);
	g.last_ack_frame = last_ack;
	g.frame_id = frame_id;
	g.queue_depth = qd;
	return rdp_rdpgfx_may_send_frame(&g);
}

static void
test_may_send_frame(void)
{
	/* No ack yet, or the client suspended acks: never throttled. */
	if (!may_send(0, 100, 0)) FAIL("startup should send");
	if (!may_send(10, 100, 0xFFFFFFFFu)) FAIL("suspended should send");
	/* queue depth 0 -> window 4 (pending = frame_id - last_ack). */
	if (!may_send(10, 13, 0)) FAIL("qd0 pending3");
	if (may_send(10, 14, 0))  FAIL("qd0 pending4 should hold");
	/* queue depth 1 -> window 2. */
	if (!may_send(10, 11, 1)) FAIL("qd1 pending1");
	if (may_send(10, 12, 1))  FAIL("qd1 pending2 should hold");
	/* queue depth >= 2 -> window 1. */
	if (!may_send(10, 10, 2)) FAIL("qd2 pending0");
	if (may_send(10, 11, 2))  FAIL("qd2 pending1 should hold");
	if (may_send(10, 11, 9))  FAIL("qd9 pending1 should hold");
}

static void
test_bytes_in_flight(void)
{
	struct rdpgfx_state g;

	/* Frame 10 acked, queue depth 0 (frame window 4).  Send frame 11 as a
	 * 2 MiB keyframe: under the frame window but over the byte budget. */
	memset(&g, 0, sizeof g);
	g.last_ack_frame = 10; g.frame_id = 10; g.queue_depth = 0;
	g.bytes_sent = 1000;
	g.cum_bytes[10 % RDPGFX_ACK_RING] = 1000;
	g.frame_id = 11;
	rdp_rdpgfx_frame_sent(&g, 2u << 20);
	if (rdp_rdpgfx_may_send_frame(&g))
		FAIL("large frame in flight should throttle on bytes");

	/* A small frame in flight stays under the budget. */
	memset(&g, 0, sizeof g);
	g.last_ack_frame = 10; g.frame_id = 10; g.queue_depth = 0;
	g.bytes_sent = 1000;
	g.cum_bytes[10 % RDPGFX_ACK_RING] = 1000;
	g.frame_id = 11;
	rdp_rdpgfx_frame_sent(&g, 8u * 1024);
	if (!rdp_rdpgfx_may_send_frame(&g))
		FAIL("small frame should send");

	/* Nothing pending: always send, even after a huge frame. */
	memset(&g, 0, sizeof g);
	g.last_ack_frame = 11; g.frame_id = 11; g.queue_depth = 0;
	g.bytes_sent = 3u << 20;
	g.cum_bytes[11 % RDPGFX_ACK_RING] = 3u << 20;
	if (!rdp_rdpgfx_may_send_frame(&g))
		FAIL("no frames pending should send");
}

static void
test_caps_confirm(void)
{
	uint8_t buf[64];
	ssize_t n;
	uint32_t i;

	/* Ordinary version: 4-byte capsData (flags only), 20-byte PDU. */
	n = rdp_rdpgfx_build_caps_confirm(buf, sizeof buf,
		0x000A0200u, RDPGFX_CAPS_FLAG_AVC_DISABLED);
	if (n != 20) FAIL("confirm v10.2 len %zd != 20", (ssize_t)n);
	if (get32(buf) != RDPGFX_CMDID_CAPSCONFIRM)
		FAIL("confirm cmdId");
	if (get32(buf + 4) != 20) FAIL("confirm v10.2 pduLength");
	if (get32(buf + 8) != 0x000A0200u) FAIL("confirm v10.2 version");
	if (get32(buf + 12) != 4) FAIL("confirm v10.2 capsDataLength != 4");
	if (get32(buf + 16) != RDPGFX_CAPS_FLAG_AVC_DISABLED)
		FAIL("confirm v10.2 flags");

	/* v10.1: 16-byte capsData (flags + 12 reserved zero bytes), 32-byte
	 * PDU, matching the FreeRDP/Windows servers. */
	n = rdp_rdpgfx_build_caps_confirm(buf, sizeof buf, RDPGFX_CAPVERSION_101,
		RDPGFX_CAPS_FLAG_AVC420_ENABLED);
	if (n != 32) FAIL("confirm v10.1 len %zd != 32", (ssize_t)n);
	if (get32(buf + 4) != 32) FAIL("confirm v10.1 pduLength");
	if (get32(buf + 8) != RDPGFX_CAPVERSION_101) FAIL("confirm v10.1 version");
	if (get32(buf + 12) != 16) FAIL("confirm v10.1 capsDataLength != 16");
	if (get32(buf + 16) != RDPGFX_CAPS_FLAG_AVC420_ENABLED)
		FAIL("confirm v10.1 flags");
	for (i = 20; i < 32; i++)
		if (buf[i] != 0) FAIL("confirm v10.1 pad byte %u nonzero", i);

	/* A buffer too small for the v10.1 capsData is refused, not overrun. */
	if (rdp_rdpgfx_build_caps_confirm(buf, 20, RDPGFX_CAPVERSION_101, 0)
	    != -1)
		FAIL("confirm v10.1 should reject a 20-byte buffer");
}

int
main(void)
{
	struct rdpgfx_caps_advertise adv;
	uint8_t buf[512];
	size_t n;

	/* Well-formed: two cap sets. */
	n = hdr(buf, 0, 2);
	n += capset(buf + n, 0x000A0002u, 4, 0x22);
	n += capset(buf + n, 0x00080105u, 4, 0x02);
	if (rdp_rdpgfx_parse_caps_advertise(buf, n, &adv) != 0) FAIL("wellformed");
	if (adv.count != 2) FAIL("count %u != 2", adv.count);
	if (adv.sets[0].version != 0x000A0002u || adv.sets[0].flags != 0x22)
		FAIL("set0");
	if (adv.sets[1].version != 0x00080105u) FAIL("set1");

	/* Too short, wrong cmdId. */
	if (rdp_rdpgfx_parse_caps_advertise(buf, 9, &adv) != -1) FAIL("short");
	{
		uint8_t bad[16];
		memset(bad, 0, sizeof bad);
		bad[0] = 0x99;   /* not CAPSADVERTISE */
		if (rdp_rdpgfx_parse_caps_advertise(bad, sizeof bad, &adv) != -1)
			FAIL("wrong cmdId");
	}

	/* A cap-set length that runs past the buffer is not over-read. */
	n = hdr(buf, 0, 2);
	n += capset(buf + n, 0x000A0002u, 4, 0x22);
	put32(buf + n, 0x000A0100u);             /* second set version */
	put32(buf + n + 4, 0x10000);             /* dataLength way past buf */
	n += 8;
	if (rdp_rdpgfx_parse_caps_advertise(buf, n, &adv) != 0) FAIL("overrun");
	if (adv.count != 1) FAIL("overrun count %u != 1", adv.count);

	/* A length near UINT32_MAX must not overflow the bounds arithmetic. */
	n = hdr(buf, 0, 1);
	put32(buf + n, 0x000A0002u);
	put32(buf + n + 4, 0xFFFFFFFFu);         /* dataLength */
	n += 8;
	if (rdp_rdpgfx_parse_caps_advertise(buf, n, &adv) != 0) FAIL("overflow");
	if (adv.count != 0) FAIL("overflow count %u != 0", adv.count);

	/* pduLength bounds the walk: count claims 2, but pduLength only covers
	 * the first set; the trailing bytes (a following PDU) must be ignored. */
	{
		size_t base = hdr(buf, 22, 2);   /* pduLength = 10 + (8+4) */
		size_t m = base + capset(buf + base, 0x000A0002u, 4, 0x22);
		/* Trailing bytes that look like a second cap set. */
		m += capset(buf + m, 0xDEADBEEFu, 4, 0xBADF00Du);
		if (rdp_rdpgfx_parse_caps_advertise(buf, m, &adv) != 0)
			FAIL("pdulen");
		if (adv.count != 1) FAIL("pdulen count %u != 1", adv.count);
		if (adv.sets[0].version != 0x000A0002u)
			FAIL("pdulen read into trailing PDU");
	}

	/* More cap sets than the slot array holds: stored count is capped, no
	 * out-of-bounds write. */
	{
		uint16_t k;
		n = hdr(buf, 0, 30);
		for (k = 0; k < 30; k++)
			n += capset(buf + n, 0x000A0002u + k, 4, k);
		if (rdp_rdpgfx_parse_caps_advertise(buf, n, &adv) != 0)
			FAIL("manysets");
		if (adv.count != RDPGFX_MAX_CAPSETS)
			FAIL("manysets count %u != %u", adv.count, RDPGFX_MAX_CAPSETS);
	}

	test_may_send_frame();
	test_bytes_in_flight();
	test_caps_confirm();

	(void)printf("rdpgfx_test: all ok\n");
	return 0;
}
