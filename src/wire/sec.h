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
 * sec.h -- RDP Security header and Client Info PDU.
 *
 * Even when TLS is the transport security, RDP keeps a 4-byte
 * "Security Header" on certain PDUs whose `flags` field tells the
 * server which payload follows (Client Info, License Error, etc.).
 *
 * Header layout (MS-RDPBCGR 2.2.8.1.1.2):
 *   uint16  flags         (LE)
 *   uint16  flagsHi       (LE; reserved when TLS, must be 0)
 *
 * Flags bits we care about:
 *   SEC_INFO_PKT    0x0040   payload is a Client Info PDU
 *   SEC_LICENSE_PKT 0x0080   payload is a Licensing PDU
 *   SEC_ENCRYPT     0x0008   would mean legacy encryption (we forbid)
 */

#ifndef RDP_SEC_H
#define RDP_SEC_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>

#define RDP_SEC_INFO_PKT     0x0040
#define RDP_SEC_LICENSE_PKT  0x0080
#define RDP_SEC_ENCRYPT      0x0008
#define RDP_SEC_HDR_LEN      4u

/* INFO_PACKET flags (MS-RDPBCGR 2.2.1.11.1.1). */
#define RDP_INFO_MOUSE               0x00000001
#define RDP_INFO_DISABLECTRLALTDEL   0x00000002
#define RDP_INFO_AUTOLOGON           0x00000008
#define RDP_INFO_UNICODE             0x00000010
#define RDP_INFO_MAXIMIZESHELL       0x00000020
#define RDP_INFO_LOGONNOTIFY         0x00000040
#define RDP_INFO_COMPRESSION         0x00000080
#define RDP_INFO_ENABLEWINDOWSKEY    0x00000100
#define RDP_INFO_REMOTECONSOLEAUDIO  0x00002000
#define RDP_INFO_FORCE_ENCRYPTED_CS_PDU 0x00004000
#define RDP_INFO_RAIL                0x00008000

/* Parsed Client Info PDU.  Strings are UTF-8 (we convert from
 * UTF-16LE when INFO_UNICODE is set).  Caller owns the buffer
 * supplied to the parser; the string fields point into it. */
struct rdp_client_info {
	uint32_t flags;
	uint32_t codepage;
	char     domain[64];
	char     username[256];
	/* For now we capture the password length but never store the
	 * cleartext beyond the parse call. */
	int      have_password;
	char     working_dir[260];
	char     alt_shell[260];
	/* Auto-reconnect cookie from ARC_CS_PRIVATE_PACKET. */
	int      have_arc;
	uint32_t arc_logon_id;
	uint8_t  arc_security_verifier[16];
};

/* Parse a single Security Header from p[..len) into *flags_out.
 * Returns the bytes consumed (4) on success, -1 on truncation. */
ssize_t rdp_sec_parse_header(const uint8_t *p, size_t len, uint32_t *flags_out);

/* Build a 4-byte Security Header into out. */
ssize_t rdp_sec_build_header(uint8_t *out, size_t cap, uint32_t flags);

/* Parse a Client Info PDU body (the bytes after the Security Header).
 * Returns 0 on success and fills *info, -1 on malformed input.
 * `pw_out` (if non-NULL) is filled with the cleartext password
 * pointer; the caller is responsible for explicit_bzero'ing it.
 * `pw_len_out` is the password length in bytes (UTF-8 byte count). */
int rdp_client_info_parse(const uint8_t *p, size_t len,
		struct rdp_client_info *info,
		const uint8_t **pw_out, size_t *pw_len_out);

#endif /* RDP_SEC_H */
