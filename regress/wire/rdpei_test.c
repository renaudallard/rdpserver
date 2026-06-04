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
 * rdpei_test.c -- MS-RDPEI touch/pen PDU parse and SC_READY build.
 *
 * Hand-crafts PDUs whose coordinates and flags use the variable-length
 * integer encodings (1, 2 and 3 byte forms, plus negatives) and checks
 * the decoded contacts, the CS_READY fixed fields, the SC_READY bytes,
 * and that truncated PDUs are rejected without over-reading (under
 * $(TEST_SAN)).
 */

#include "../../src/channels/rdpei.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
test_touch(void)
{
	/* TOUCH PDU, 2 contacts.  Contact 0: id 0, fields=PRESSURE,
	 * x=100000 (4byte-signed, 3-byte form), y=200 (2-byte form),
	 * flags=DOWN|INRANGE|INCONTACT (0x19), pressure=512 (2-byte form).
	 * Contact 1: id 1, no fields, x=-50 (negative), y=0, flags=UP. */
	const uint8_t pdu[] = {
		0x03, 0x00, 0x1A, 0x00, 0x00, 0x00,   /* eventId TOUCH, len 26 */
		0x00,             /* encodeTime = 0 */
		0x01,             /* frameCount = 1 */
		0x02,             /* contactCount = 2 */
		0x00,             /* frameOffset = 0 */
		/* contact 0 */
		0x00,             /* contactId 0 */
		0x04,             /* fieldsPresent = PRESSURE */
		0x81, 0x86, 0xA0, /* x = 100000 */
		0x40, 0xC8,       /* y = 200 */
		0x19,             /* contactFlags = 0x19 */
		0x42, 0x00,       /* pressure = 512 */
		/* contact 1 */
		0x01,             /* contactId 1 */
		0x00,             /* fieldsPresent = 0 */
		0x60, 0x32,       /* x = -50 */
		0x00,             /* y = 0 */
		0x04              /* contactFlags = UP */
	};
	struct rdp_rdpei_event ev;

	if (rdp_rdpei_parse_event(pdu, sizeof pdu, &ev) != 0)
		FAIL("parse touch");
	if (ev.event_id != RDPEI_EVENTID_TOUCH) FAIL("event id");
	if (ev.contact_count != 2) FAIL("contact count %u", ev.contact_count);

	if (ev.contacts[0].id != 0) FAIL("c0 id");
	if (ev.contacts[0].x != 100000) FAIL("c0 x %d", ev.contacts[0].x);
	if (ev.contacts[0].y != 200) FAIL("c0 y %d", ev.contacts[0].y);
	if (ev.contacts[0].flags != (RDPEI_CONTACT_DOWN | RDPEI_CONTACT_INRANGE
	    | RDPEI_CONTACT_INCONTACT)) FAIL("c0 flags 0x%x", ev.contacts[0].flags);
	if (ev.contacts[0].pressure != 512) FAIL("c0 pressure %u",
		ev.contacts[0].pressure);
	if (ev.contacts[0].is_pen) FAIL("c0 should be touch");

	if (ev.contacts[1].id != 1) FAIL("c1 id");
	if (ev.contacts[1].x != -50) FAIL("c1 x %d", ev.contacts[1].x);
	if (ev.contacts[1].y != 0) FAIL("c1 y %d", ev.contacts[1].y);
	if (ev.contacts[1].flags != RDPEI_CONTACT_UP) FAIL("c1 flags");
	if (ev.contacts[1].pressure != 0) FAIL("c1 pressure");
}

static void
test_pen(void)
{
	/* PEN PDU, 1 contact with penFlags + pressure present. */
	const uint8_t pdu[] = {
		0x08, 0x00, 0x12, 0x00, 0x00, 0x00,   /* eventId PEN, len 18 */
		0x00,             /* encodeTime */
		0x01,             /* frameCount */
		0x01,             /* contactCount */
		0x00,             /* frameOffset */
		0x05,             /* deviceId 5 */
		0x03,             /* fieldsPresent = PENFLAGS|PRESSURE */
		0x0A,             /* x = 10 */
		0x14,             /* y = 20 */
		0x01,             /* contactFlags = DOWN */
		0x02,             /* penFlags = ERASER (4byte-unsigned, 1 byte) */
		0x41, 0x00        /* pressure = 256 (2-byte form) */
	};
	struct rdp_rdpei_event ev;

	if (rdp_rdpei_parse_event(pdu, sizeof pdu, &ev) != 0)
		FAIL("parse pen");
	if (ev.event_id != RDPEI_EVENTID_PEN) FAIL("pen event id");
	if (ev.contact_count != 1) FAIL("pen contact count");
	if (!ev.contacts[0].is_pen) FAIL("c0 should be pen");
	if (ev.contacts[0].id != 5) FAIL("pen id");
	if (ev.contacts[0].x != 10 || ev.contacts[0].y != 20) FAIL("pen xy");
	if (ev.contacts[0].flags != RDPEI_CONTACT_DOWN) FAIL("pen flags");
	if (ev.contacts[0].pressure != 256) FAIL("pen pressure %u",
		ev.contacts[0].pressure);
}

static void
test_cs_ready(void)
{
	const uint8_t pdu[] = {
		0x02, 0x00, 0x10, 0x00, 0x00, 0x00,   /* eventId CS_READY, len 16 */
		0x04, 0x00, 0x00, 0x00,   /* flags = 4 */
		0x00, 0x00, 0x01, 0x00,   /* protocolVersion = 0x00010000 */
		0x0A, 0x00                /* maxTouchContacts = 10 */
	};
	struct rdp_rdpei_event ev;

	if (rdp_rdpei_parse_event(pdu, sizeof pdu, &ev) != 0)
		FAIL("parse cs_ready");
	if (ev.event_id != RDPEI_EVENTID_CS_READY) FAIL("cs event id");
	if (ev.cs_flags != 4) FAIL("cs flags");
	if (ev.cs_version != RDPEI_PROTOCOL_V1) FAIL("cs version 0x%x",
		ev.cs_version);
	if (ev.cs_max_contacts != 10) FAIL("cs max contacts");
}

static void
test_sc_ready_build(void)
{
	uint8_t out[16];
	ssize_t n;
	const uint8_t want[] = {
		0x01, 0x00, 0x0A, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00
	};

	n = rdp_rdpei_build_sc_ready(out, sizeof out, RDPEI_PROTOCOL_V1);
	if (n != 10) FAIL("sc_ready len %zd", (ssize_t)n);
	if (memcmp(out, want, 10) != 0) FAIL("sc_ready bytes");
	if (rdp_rdpei_build_sc_ready(out, 4, RDPEI_PROTOCOL_V1) != -1)
		FAIL("sc_ready should reject small buffer");
}

static void
test_truncated(void)
{
	/* The full touch PDU header claims 26 bytes; feed fewer so the body
	 * decode must hit the end mid-contact and reject cleanly. */
	const uint8_t pdu[] = {
		0x03, 0x00, 0x1A, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x00,
		0x00, 0x04, 0x81, 0x86   /* truncated inside contact 0's x */
	};
	/* Same bytes but pduLength set to the actual size: the body claims 2
	 * contacts yet ends inside contact 0's x, so the cursor must underflow
	 * and reject rather than over-read. */
	const uint8_t pdu2[] = {
		0x03, 0x00, 0x0E, 0x00, 0x00, 0x00,   /* len 14 == buffer */
		0x00, 0x01, 0x02, 0x00,
		0x00, 0x04, 0x81, 0x86
	};
	struct rdp_rdpei_event ev;
	size_t i;

	/* pduLength (26) exceeds the actual buffer -> reject. */
	if (rdp_rdpei_parse_event(pdu, sizeof pdu, &ev) != -1)
		FAIL("oversize pduLength accepted");
	if (rdp_rdpei_parse_event(pdu2, sizeof pdu2, &ev) != -1)
		FAIL("internally truncated body accepted");
	/* Every prefix of a valid-looking PDU must be rejected, not over-read. */
	for (i = 0; i < 6; i++) {
		if (rdp_rdpei_parse_event(pdu, i, &ev) != -1)
			FAIL("short header %zu accepted", i);
	}
}

int
main(void)
{
	test_touch();
	test_pen();
	test_cs_ready();
	test_sc_ready_build();
	test_truncated();
	(void)printf("rdpei_test: all ok\n");
	return 0;
}
