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
 * rdpei.h -- MS-RDPEI multitouch and pen input channel.
 *
 * Carried on the "Microsoft::Windows::RDS::Input" dynamic virtual
 * channel.  Every PDU is an RDPINPUT_HEADER (eventId u16 LE, pduLength
 * u32 LE including the 6-byte header) followed by a body.  The server
 * sends SC_READY, the client replies CS_READY, then the client streams
 * touch and pen frames.  Coordinates and flags use the MS-RDPEI
 * variable-length integer encodings (a length/sign prefix in the first
 * byte, the rest MSB-first).
 */

#ifndef RDP_RDPEI_H
#define RDP_RDPEI_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RDPEI_CHANNEL_NAME "Microsoft::Windows::RDS::Input"

#define RDPEI_EVENTID_SC_READY        0x0001
#define RDPEI_EVENTID_CS_READY        0x0002
#define RDPEI_EVENTID_TOUCH           0x0003
#define RDPEI_EVENTID_SUSPEND_TOUCH   0x0004
#define RDPEI_EVENTID_RESUME_TOUCH    0x0005
#define RDPEI_EVENTID_DISMISS_HOVER   0x0006
#define RDPEI_EVENTID_PEN             0x0008

#define RDPEI_PROTOCOL_V1   0x00010000u

/* contactFlags (shared by touch and pen). */
#define RDPEI_CONTACT_DOWN      0x0001
#define RDPEI_CONTACT_UPDATE    0x0002
#define RDPEI_CONTACT_UP        0x0004
#define RDPEI_CONTACT_INRANGE   0x0008
#define RDPEI_CONTACT_INCONTACT 0x0010
#define RDPEI_CONTACT_CANCELED  0x0020

#define RDPEI_MAX_CONTACTS 64

struct rdp_rdpei_contact {
	uint8_t  id;        /* contactId (touch) or deviceId (pen) */
	int      is_pen;
	int32_t  x, y;
	uint32_t flags;     /* RDPEI_CONTACT_* */
	uint32_t pressure;  /* 0 when the field is absent */
};

struct rdp_rdpei_event {
	uint16_t event_id;
	/* CS_READY fields (valid when event_id == RDPEI_EVENTID_CS_READY). */
	uint32_t cs_flags;
	uint32_t cs_version;
	uint16_t cs_max_contacts;
	/* Flattened contacts across all frames (TOUCH / PEN / DISMISS). */
	uint16_t contact_count;
	struct rdp_rdpei_contact contacts[RDPEI_MAX_CONTACTS];
};

/* Build the SC_READY PDU advertising the given protocol version (use
 * RDPEI_PROTOCOL_V1).  Returns the byte count or -1 on overflow. */
ssize_t rdp_rdpei_build_sc_ready(uint8_t *out, size_t cap, uint32_t version);

/* Parse one RDPEI PDU (the reassembled channel payload).  Fills *out
 * with the eventId and, for CS_READY / TOUCH / PEN / DISMISS, the parsed
 * fields.  Contacts beyond RDPEI_MAX_CONTACTS are dropped.  Returns 0 on
 * success, -1 on a malformed or truncated PDU. */
int rdp_rdpei_parse_event(const uint8_t *p, size_t len,
		struct rdp_rdpei_event *out);

#endif /* RDP_RDPEI_H */
