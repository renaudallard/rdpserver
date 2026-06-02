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
 * rdp_pdu.c -- share-control/data framing and finalization PDUs.
 */

#include "rdp_pdu.h"

#include "../common/buf.h"
#include "../common/utf16.h"

#include <string.h>

ssize_t
rdp_pdu_build_share_control(uint8_t *out, size_t cap,
		uint16_t pdu_type, uint16_t pdu_source,
		uint16_t total_length)
{
	struct rdp_buf b;
	if (cap < 6) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u16le(&b, total_length) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)((pdu_type & 0x0f) | (1 << 4))) != 0)
		return -1;
	if (rdp_buf_put_u16le(&b, pdu_source) != 0) return -1;
	return 6;
}

ssize_t
rdp_pdu_build_share_data(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint8_t pdu_type2, uint16_t total_length)
{
	struct rdp_buf b;
	if (cap < 18) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u16le(&b, total_length) != 0) return -1;
	if (rdp_buf_put_u16le(&b,
		(uint16_t)((RDP_PDU_TYPE_DATA & 0x0f) | (1 << 4))) != 0)
		return -1;
	if (rdp_buf_put_u16le(&b, pdu_source) != 0) return -1;
	if (rdp_buf_put_u32le(&b, share_id) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;  /* pad1 */
	if (rdp_buf_put_u8(&b, RDP_STREAM_MED) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)(total_length - 14)) != 0) return -1;
	if (rdp_buf_put_u8(&b, pdu_type2) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;  /* compressedType */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;  /* compressedLength */
	return 18;
}

ssize_t
rdp_pdu_parse_share_control(const uint8_t *p, size_t len,
		uint16_t *pdu_type_out, uint16_t *pdu_source_out,
		uint16_t *total_length_out)
{
	uint16_t total, type;

	if (len < 6) return -1;
	total = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
	type  = (uint16_t)p[2] | ((uint16_t)p[3] << 8);
	*total_length_out = total;
	*pdu_type_out = (uint16_t)(type & 0x0f);
	*pdu_source_out = (uint16_t)p[4] | ((uint16_t)p[5] << 8);
	return 6;
}

ssize_t
rdp_pdu_parse_share_data(const uint8_t *p, size_t len,
		uint32_t *share_id_out, uint8_t *pdu_type2_out)
{
	if (len < 12) return -1;
	*share_id_out = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	*pdu_type2_out = p[6];
	return 12;
}

ssize_t
rdp_pdu_build_synchronize(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint16_t target_user)
{
	uint16_t total = 18 + 4;
	struct rdp_buf b;
	ssize_t r;

	if (cap < total) return -1;
	rdp_buf_init(&b, out, cap);
	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_SYNCHRONIZE, total);
	if (r != 18) return -1;
	(void)rdp_buf_skip(&b, 18);
	if (rdp_buf_put_u16le(&b, RDP_SYNCMSGTYPE_SYNC) != 0) return -1;
	if (rdp_buf_put_u16le(&b, target_user) != 0) return -1;
	return total;
}

ssize_t
rdp_pdu_build_control(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint16_t action, uint16_t grant_id, uint32_t control_id)
{
	uint16_t total = 18 + 8;
	struct rdp_buf b;
	ssize_t r;

	if (cap < total) return -1;
	rdp_buf_init(&b, out, cap);
	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_CONTROL, total);
	if (r != 18) return -1;
	(void)rdp_buf_skip(&b, 18);
	if (rdp_buf_put_u16le(&b, action) != 0) return -1;
	if (rdp_buf_put_u16le(&b, grant_id) != 0) return -1;
	if (rdp_buf_put_u32le(&b, control_id) != 0) return -1;
	return total;
}

ssize_t
rdp_pdu_build_font_map(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id)
{
	uint16_t total = 18 + 8;
	struct rdp_buf b;
	ssize_t r;

	if (cap < total) return -1;
	rdp_buf_init(&b, out, cap);
	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_FONTMAP, total);
	if (r != 18) return -1;
	(void)rdp_buf_skip(&b, 18);
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;  /* numberEntries */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;  /* totalNumEntries */
	if (rdp_buf_put_u16le(&b,
		RDP_FONTMAP_FIRST | RDP_FONTMAP_LAST) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 4) != 0) return -1;  /* entrySize */
	return total;
}

int
rdp_pdu_extract_confirm_active(const uint8_t *p, size_t len,
		const uint8_t **caps_out, size_t *caps_len_out)
{
	uint16_t lenSrc, lenComb;
	size_t off = 0;

	if (len < 10) return -1;
	off += 4; /* shareId */
	off += 2; /* originatorId */
	lenSrc  = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8); off += 2;
	lenComb = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8); off += 2;
	if (off + lenSrc + lenComb > len) return -1;
	off += lenSrc;
	if (lenComb < 4) return -1;
	off += 2; /* numberCapabilities */
	off += 2; /* pad2 */
	*caps_out = p + off;
	*caps_len_out = lenComb - 4;
	return 0;
}

ssize_t
rdp_pdu_build_deactivate_all(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id)
{
	/* Deactivate-All: share-control header (pduType=6) + shareId(4)
	 * + lengthSourceDescriptor(2) + sourceDescriptor. */
	uint16_t total = 6 + 4 + 2 + 4;
	struct rdp_buf b;

	if (cap < total) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_pdu_build_share_control(out, cap,
		RDP_PDU_TYPE_DEACTIVATE_ALL, pdu_source, total) < 0)
		return -1;
	(void)rdp_buf_skip(&b, 6);
	if (rdp_buf_put_u32le(&b, share_id) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 4) != 0) return -1;
	if (rdp_buf_put(&b, "RDP", 4) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_pdu_build_save_session_info_arc(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint32_t logon_id, const uint8_t arc_random[16])
{
	/* Body layout after the share-data header:
	 *   infoType     u32 = INFOTYPE_LOGON_EXTENDED (3)
	 *   length       u16 = 2+4+28 = 34
	 *   fieldPresent u32 = LOGON_EX_AUTORECONNECTCOOKIE
	 *   ARC_SC_PRIVATE_PACKET:
	 *     cbLen      u32 = 28
	 *     version    u32 = 1
	 *     logonId    u32
	 *     ArcRandomBits u8[16]
	 *   pad[570]  -- spec says pad to 583; we pad to fill.
	 *
	 * Total body = 4 + 2 + 4 + 28 = 38.
	 * share-data header = 18.
	 * total = 56 (without padding).
	 *
	 * mstsc expects some padding; keep it short for v1. */
	uint16_t body_len = 38;
	uint16_t total = 18 + body_len;
	struct rdp_buf b;
	ssize_t r;

	if (cap < total) return -1;
	rdp_buf_init(&b, out, cap);
	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_SAVE_SESSION_INFO, total);
	if (r != 18) return -1;
	(void)rdp_buf_skip(&b, 18);

	/* infoType */
	if (rdp_buf_put_u32le(&b, RDP_INFOTYPE_LOGON_EXTENDED) != 0)
		return -1;
	/* length of the remaining TS_LOGON_INFO_EXTENDED fields */
	if (rdp_buf_put_u16le(&b, 4 + 28) != 0) return -1;
	/* fieldPresent */
	if (rdp_buf_put_u32le(&b, RDP_LOGON_EX_AUTORECONNECTCOOKIE) != 0)
		return -1;
	/* ARC_SC_PRIVATE_PACKET */
	if (rdp_buf_put_u32le(&b, 28) != 0) return -1;  /* cbLen */
	if (rdp_buf_put_u32le(&b, 1) != 0) return -1;   /* version */
	if (rdp_buf_put_u32le(&b, logon_id) != 0) return -1;
	if (rdp_buf_put(&b, arc_random, 16) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_pdu_build_set_error_info(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id, uint32_t error_code)
{
	uint16_t total = 18 + 4;
	ssize_t r;
	struct rdp_buf b;

	if (cap < total) return -1;
	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_SET_ERROR_INFO, total);
	if (r < 0) return -1;
	rdp_buf_init(&b, out + r, cap - (size_t)r);
	if (rdp_buf_put_u32le(&b, error_code) != 0) return -1;
	return total;
}

ssize_t
rdp_pdu_build_save_session_logon(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id)
{
	uint16_t total = 18 + 4 + 576;
	ssize_t r;
	struct rdp_buf b;
	uint8_t pad[576];

	if (cap < total) return -1;
	memset(pad, 0, sizeof pad);
	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_SAVE_SESSION_INFO, total);
	if (r < 0) return -1;
	rdp_buf_init(&b, out + r, cap - (size_t)r);
	if (rdp_buf_put_u32le(&b, RDP_INFOTYPE_LOGON_PLAINNOTIFY) != 0)
		return -1;
	if (rdp_buf_put(&b, pad, sizeof pad) != 0) return -1;
	return total;
}

/* TS_LOGON_INFO_VERSION_2 (MS-RDPBCGR 2.2.10.1.1.2): the logon
 * notification carrying the session id, domain, and user name.  The
 * fixed header (Version + Size + SessionId + cbDomain + cbUserName)
 * is 18 bytes, followed by a 558-byte reserved pad, then the variable
 * length Domain and UserName UTF-16LE strings (each null-terminated;
 * cbDomain/cbUserName count those bytes including the terminator).
 * The client caps Domain at 52 and UserName at 512 bytes, so the
 * payloads are clamped to 50 and 510 to leave room for the NUL. */
ssize_t
rdp_pdu_build_save_session_logon_v2(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		const char *domain, const char *username, uint32_t session_id)
{
	uint8_t dom16[52], usr16[512], pad[558];
	size_t dw, uw;
	uint32_t cb_domain, cb_username;
	uint16_t total;
	ssize_t r;
	struct rdp_buf b;

	if (domain == NULL) domain = "";
	if (username == NULL) username = "";

	dw = rdp_utf8_to_utf16le(dom16, sizeof dom16 - 2, domain, strlen(domain));
	if (dw == (size_t)-1 || dw > sizeof dom16 - 2)
		dw = sizeof dom16 - 2;   /* malformed or truncated: clamp */
	dw &= ~(size_t)1;                /* keep whole UTF-16 units */
	dom16[dw] = 0; dom16[dw + 1] = 0;
	cb_domain = (uint32_t)(dw + 2);

	uw = rdp_utf8_to_utf16le(usr16, sizeof usr16 - 2, username, strlen(username));
	if (uw == (size_t)-1 || uw > sizeof usr16 - 2)
		uw = sizeof usr16 - 2;
	uw &= ~(size_t)1;
	usr16[uw] = 0; usr16[uw + 1] = 0;
	cb_username = (uint32_t)(uw + 2);

	total = (uint16_t)(18 + 4 + 18 + 558 + cb_domain + cb_username);
	if (cap < total) return -1;
	memset(pad, 0, sizeof pad);

	r = rdp_pdu_build_share_data(out, cap, pdu_source, share_id,
		RDP_PDU2_SAVE_SESSION_INFO, total);
	if (r < 0) return -1;
	rdp_buf_init(&b, out + r, cap - (size_t)r);
	if (rdp_buf_put_u32le(&b, RDP_INFOTYPE_LOGON_LONG) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 1) != 0) return -1;        /* Version */
	if (rdp_buf_put_u32le(&b, 576) != 0) return -1;      /* Size */
	if (rdp_buf_put_u32le(&b, session_id) != 0) return -1;
	if (rdp_buf_put_u32le(&b, cb_domain) != 0) return -1;
	if (rdp_buf_put_u32le(&b, cb_username) != 0) return -1;
	if (rdp_buf_put(&b, pad, sizeof pad) != 0) return -1;
	if (rdp_buf_put(&b, dom16, cb_domain) != 0) return -1;
	if (rdp_buf_put(&b, usr16, cb_username) != 0) return -1;
	return total;
}
