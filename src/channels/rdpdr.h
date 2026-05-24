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
 * rdpdr.h -- MS-RDPEFS device redirection (drives, printers, serial).
 *
 * Implements the RDPDR static virtual channel protocol:
 * Server Announce, Core Capabilities, Client ID Confirm,
 * Device List parsing, and IRP dispatch for drive file I/O.
 */

#ifndef RDP_RDPDR_H
#define RDP_RDPDR_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* RDPDR packet header: component(u16) + packetId(u16) */
#define RDPDR_CTYP_CORE    0x4472
#define RDPDR_CTYP_PRN     0x5052

#define PAKID_CORE_SERVER_ANNOUNCE     0x496E
#define PAKID_CORE_CLIENTID_CONFIRM    0x4343
#define PAKID_CORE_CLIENT_NAME         0x434E
#define PAKID_CORE_DEVICE_LIST_ANNOUNCE 0x4441
#define PAKID_CORE_DEVICE_LIST_REMOVE  0x4452
#define PAKID_CORE_DEVICE_REPLY        0x6472
#define PAKID_CORE_DEVICE_IOREQUEST    0x4952
#define PAKID_CORE_DEVICE_IOCOMPLETION 0x4943
#define PAKID_CORE_SERVER_CAPABILITY   0x5350
#define PAKID_CORE_CLIENT_CAPABILITY   0x4350
#define PAKID_CORE_USER_LOGGEDON       0x554C

/* Device types */
#define RDPDR_DTYP_SERIAL    0x0001
#define RDPDR_DTYP_PARALLEL  0x0002
#define RDPDR_DTYP_PRINT     0x0004
#define RDPDR_DTYP_FILESYSTEM 0x0008
#define RDPDR_DTYP_SMARTCARD 0x0020

/* Capability types */
#define CAP_GENERAL_TYPE    0x0001
#define CAP_PRINTER_TYPE    0x0002
#define CAP_PORT_TYPE       0x0003
#define CAP_DRIVE_TYPE      0x0004
#define CAP_SMARTCARD_TYPE  0x0005

#define RDPDR_MAX_DEVICES 32

struct rdpdr_device {
	int      in_use;
	uint32_t device_type;
	uint32_t device_id;
	char     name[9];
};

struct rdpdr_state {
	int      handshake_done;
	uint32_t client_id;
	uint16_t version_major;
	uint16_t version_minor;
	char     client_name[128];
	uint32_t device_count;
	struct rdpdr_device devices[RDPDR_MAX_DEVICES];
};

/* Build the Server Announce Request PDU. */
ssize_t rdp_rdpdr_build_announce(uint8_t *out, size_t cap);

/* Build the Server Core Capability Request PDU. */
ssize_t rdp_rdpdr_build_caps(uint8_t *out, size_t cap);

/* Build the Server Client ID Confirm PDU. */
ssize_t rdp_rdpdr_build_clientid_confirm(uint8_t *out, size_t cap,
		uint32_t client_id);

/* Build the Server User Logged On PDU. */
ssize_t rdp_rdpdr_build_user_loggedon(uint8_t *out, size_t cap);

/* Build a Device Create Response (IRP completion). */
ssize_t rdp_rdpdr_build_device_reply(uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t status);

/* Return the wire length of a single outbound RDPDR PDU. */
size_t rdp_rdpdr_pdu_len(uint16_t component, uint16_t packet_id,
		const uint8_t *pdu, size_t avail);

/* Handle an inbound RDPDR PDU. Returns:
 *   0 = handled, may have response in resp_out
 *  <0 = error */
int rdp_rdpdr_handle(struct rdpdr_state *st,
		const uint8_t *pdu, size_t len,
		uint8_t *resp_out, size_t resp_cap, size_t *resp_len);

#endif
