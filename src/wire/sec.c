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
 * sec.c -- security header and Client Info PDU.
 */

#include "sec.h"

#include "../common/utf16.h"
#include "../include/rdp_log.h"

#include <string.h>

ssize_t
rdp_sec_parse_header(const uint8_t *p, size_t len, uint32_t *flags_out)
{
	if (len < RDP_SEC_HDR_LEN) return -1;
	*flags_out = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
	/* p[2..3] = flagsHi -- must be 0 for TLS-secured traffic, but
	 * some clients put junk there.  We just ignore it. */
	return RDP_SEC_HDR_LEN;
}

ssize_t
rdp_sec_build_header(uint8_t *out, size_t cap, uint32_t flags)
{
	if (cap < RDP_SEC_HDR_LEN) return -1;
	out[0] = (uint8_t)(flags & 0xff);
	out[1] = (uint8_t)((flags >> 8) & 0xff);
	out[2] = 0;
	out[3] = 0;
	return RDP_SEC_HDR_LEN;
}

/* Decode a UTF-16LE or ANSI string into UTF-8 in dst.  cb does NOT
 * include the trailing NUL (per spec) but the NUL bytes ARE present
 * on the wire and must be included in the offset advance.  We add
 * the implicit terminator size when stepping past. */
static int
decode_string(int unicode, const uint8_t *p, size_t cb,
		char *dst, size_t dsz)
{
	if (unicode) {
		size_t need = rdp_utf16le_to_utf8(dst, dsz - 1, p, cb);
		if (need == (size_t)-1)
			return -1;
		if (need >= dsz)
			need = dsz - 1;
		dst[need] = '\0';
		return 0;
	} else {
		size_t n = cb < dsz - 1 ? cb : dsz - 1;
		memcpy(dst, p, n);
		dst[n] = '\0';
		return 0;
	}
}

int
rdp_client_info_parse(const uint8_t *p, size_t len,
		struct rdp_client_info *info,
		const uint8_t **pw_out, size_t *pw_len_out)
{
	size_t off = 0;
	uint16_t cbDomain, cbUserName, cbPassword, cbAltShell, cbWorkingDir;
	int unicode;
	size_t step;

	memset(info, 0, sizeof *info);
	if (pw_out) *pw_out = NULL;
	if (pw_len_out) *pw_len_out = 0;

	if (len < 18) return -1;
	info->codepage = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	info->flags = (uint32_t)p[4] | ((uint32_t)p[5] << 8)
		| ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
	cbDomain     = (uint16_t)p[8]  | ((uint16_t)p[9]  << 8);
	cbUserName   = (uint16_t)p[10] | ((uint16_t)p[11] << 8);
	cbPassword   = (uint16_t)p[12] | ((uint16_t)p[13] << 8);
	cbAltShell   = (uint16_t)p[14] | ((uint16_t)p[15] << 8);
	cbWorkingDir = (uint16_t)p[16] | ((uint16_t)p[17] << 8);
	off = 18;
	unicode = (info->flags & RDP_INFO_UNICODE) != 0;
	step = unicode ? 2 : 1;

	/* Each string is cbX bytes + an implicit terminator (2 for
	 * UTF-16LE, 1 for ANSI).  cbX does not include the terminator. */
	#define READ_STR(cb, field) do {                                \
		if (off + (cb) + step > len) return -1;                  \
		if (decode_string(unicode, p + off, (cb), (field),      \
				sizeof (field)) != 0)                            \
			return -1;                                          \
		off += (cb) + step;                                     \
	} while (0)

	READ_STR(cbDomain,   info->domain);
	READ_STR(cbUserName, info->username);

	if (off + cbPassword + step > len) return -1;
	if (cbPassword > 0) {
		info->have_password = 1;
		if (pw_out) *pw_out = p + off;
		if (pw_len_out) *pw_len_out = cbPassword;
	}
	off += cbPassword + step;

	READ_STR(cbAltShell,   info->alt_shell);
	READ_STR(cbWorkingDir, info->working_dir);

	#undef READ_STR
	return 0;
}
