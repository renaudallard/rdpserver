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
 * rail.h -- MS-RDPERP RemoteApp (RAIL) order PDUs.
 *
 * The "rail" static virtual channel carries TS_RAIL_ORDER PDUs.  Each is
 * a 4-byte header (orderType u16, orderLength u16 including the header)
 * followed by a body.  The server drives the handshake (it sends
 * HANDSHAKE first), then consumes the client's HANDSHAKE, CLIENTSTATUS,
 * SYSPARAM and, optionally, EXEC, to which it replies EXEC_RESULT.
 * Window geometry is carried separately as Window Information drawing
 * orders, not here.
 */

#ifndef RDP_RAIL_H
#define RDP_RAIL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RAIL_CHANNEL_NAME "rail"

#define RAIL_ORDER_EXEC          0x0001
#define RAIL_ORDER_ACTIVATE      0x0002
#define RAIL_ORDER_SYSPARAM      0x0003
#define RAIL_ORDER_SYSCOMMAND    0x0004
#define RAIL_ORDER_HANDSHAKE     0x0005
#define RAIL_ORDER_NOTIFY_EVENT  0x0006
#define RAIL_ORDER_WINDOWMOVE    0x0008
#define RAIL_ORDER_LOCALMOVESIZE 0x0009
#define RAIL_ORDER_MINMAXINFO    0x000A
#define RAIL_ORDER_CLIENTSTATUS  0x000B
#define RAIL_ORDER_SYSMENU       0x000C
#define RAIL_ORDER_LANGBARINFO   0x000D
#define RAIL_ORDER_GET_APPID_REQ 0x000E
#define RAIL_ORDER_HANDSHAKE_EX  0x0013
#define RAIL_ORDER_EXEC_RESULT   0x0080

/* RAIL capability levels (CAPSETTYPE_RAIL railSupportLevel). */
#define RAIL_LEVEL_SUPPORTED              0x00000001
#define RAIL_LEVEL_SHELL_INTEGRATION      0x00000004

/* Window list capability levels (CAPSETTYPE_WINDOW wndSupportLevel). */
#define RAIL_WND_LEVEL_SUPPORTED          0x00000001
#define RAIL_WND_LEVEL_SUPPORTED_EX       0x00000002

/* EXEC_RESULT codes. */
#define RAIL_EXEC_S_OK                    0x0000
#define RAIL_EXEC_E_FAIL                  0x0006

/* Build the server HANDSHAKE PDU (orderType 0x0005, buildNumber).
 * Returns the byte count or -1 on overflow. */
ssize_t rdp_rail_build_handshake(uint8_t *out, size_t cap,
		uint32_t build_number);

/* Build an EXEC_RESULT PDU echoing the requested executable string
 * (raw UTF-16LE, exe_len bytes).  Returns the byte count or -1. */
ssize_t rdp_rail_build_exec_result(uint8_t *out, size_t cap,
		uint16_t flags, uint16_t result, uint32_t raw_result,
		const uint8_t *exe_utf16, uint16_t exe_len);

struct rdp_rail_order {
	uint16_t order_type;
	uint16_t order_length;
	/* HANDSHAKE / HANDSHAKE_EX */
	uint32_t build_number;
	/* CLIENTSTATUS */
	uint32_t client_status;
	/* EXEC: the three strings point into the parsed PDU (raw UTF-16LE). */
	uint16_t exec_flags;
	const uint8_t *exe;     uint16_t exe_len;
	const uint8_t *workdir; uint16_t workdir_len;
	const uint8_t *args;    uint16_t args_len;
};

/* Parse one TS_RAIL_ORDER PDU.  Fills *out with the orderType and, for
 * HANDSHAKE / CLIENTSTATUS / EXEC, the decoded fields (EXEC string
 * pointers reference p).  Returns 0 on success, -1 on a malformed or
 * truncated PDU. */
int rdp_rail_parse_order(const uint8_t *p, size_t len,
		struct rdp_rail_order *out);

#endif /* RDP_RAIL_H */
