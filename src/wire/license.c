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
 * license.c -- MS-RDPELE Valid Client error alert.
 *
 * Wire layout we emit:
 *   bMsgType        (1)  0xff = ERROR_ALERT
 *   bVersion        (1)  PREAMBLE_VERSION_3_0 | EXTENDED_ERROR_MSG_SUPPORTED
 *   wMsgSize        (2)  total bytes, LE
 *   dwErrorCode     (4)  STATUS_VALID_CLIENT (0x00000007), LE
 *   dwStateTransition (4) ST_NO_TRANSITION (0x00000002), LE
 *   LICENSE_BINARY_BLOB:
 *     wBlobType     (2)  any (we use 0x0004, BB_ERROR_BLOB)
 *     wBlobLen      (2)  0
 */

#include "license.h"

#include "../common/buf.h"

ssize_t
rdp_license_build_valid_client(uint8_t *out, size_t cap)
{
	struct rdp_buf b;
	uint16_t total = 16;

	if (cap < total) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, RDP_LIC_MSGTYPE_ERROR_ALERT) != 0) return -1;
	if (rdp_buf_put_u8(&b,
		RDP_LIC_PREAMBLE_VERSION_3_0
		| RDP_LIC_EXT_ERROR_MSG_SUPPORTED) != 0) return -1;
	if (rdp_buf_put_u16le(&b, total) != 0) return -1;
	if (rdp_buf_put_u32le(&b, RDP_LIC_STATUS_VALID_CLIENT) != 0) return -1;
	if (rdp_buf_put_u32le(&b, RDP_LIC_STATE_NO_TRANSITION) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0x0004) != 0) return -1;  /* BB_ERROR_BLOB */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;        /* wBlobLen = 0 */
	return (ssize_t)rdp_buf_used(&b);
}
