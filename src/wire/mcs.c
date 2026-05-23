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
 * mcs.c -- T.125 MCS subset for RDP.
 *
 * The fiddly bits are Connect Initial / Connect Response.  Those are
 * BER-encoded with a GCC Conference Create Request/Response payload
 * nested inside as PER-aligned data.  Because the GCC envelope is
 * constant for RDP we emit it as a canonical byte sequence and
 * parse incoming envelopes by skipping fixed offsets, then iterating
 * over Client Data Blocks (CS_*) by their 4-byte TLV headers.
 *
 * Subsequent DomainPDUs (Erect Domain, Attach User, Channel Join,
 * Send Data) use the trivial single-byte choice encoding.
 */

#include "mcs.h"

#include "../common/ber.h"
#include "../common/per.h"
#include "../include/rdp_log.h"

#include <string.h>

/* GCC Conference Create Response fixed prefix used by RDP.  This is
 * the canonical byte sequence emitted by Windows servers and xrdp
 * for the response envelope, up to (but not including) the H.221
 * key "McDn" and the user-data length determinant.  The trailing
 * variable bits (length + server data blocks) are appended at run
 * time. */
static const uint8_t GCC_CR_PREFIX[] = {
	/* T.124 object identifier (PER), nodeID (16-bit), tag
	 * (16-bit), result (3-bit choice 0 = success, padded), and
	 * the user-data sequence-of envelope. */
	0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01,
	0x2a, 0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01,
	0xc0, 0x00,
};

/* Compute the encoded size of a PER length field. */
static size_t
per_len_size(size_t v)
{
	return v < 128 ? 1 : 2;
}

/* Compute the encoded size of a BER application tag. */
static size_t
ber_app_tag_size(uint32_t tag)
{
	return tag < 31 ? 1 : 2;
}

ssize_t
rdp_mcs_parse_connect_initial(const uint8_t *p, size_t len,
		struct rdp_mcs_connect_initial *out)
{
	size_t off = 0, vlen;
	ssize_t r;
	const uint8_t *user_data;
	size_t user_data_len;
	size_t ud_off;

	memset(out, 0, sizeof *out);

	/* BER application 101 (Connect Initial), constructed. */
	r = rdp_ber_read_app_tag(p + off, len - off,
		RDP_BER_CONSTRUCTED, 101, &vlen);
	if (r < 0) return -1;
	off += (size_t)r;

	{
		const uint8_t *od;
		size_t odl;
		/* callingDomainSelector, calledDomainSelector. */
		r = rdp_ber_read_octet_string(p + off, len - off, &od, &odl);
		if (r < 0) return -1;
		off += (size_t)r;
		r = rdp_ber_read_octet_string(p + off, len - off, &od, &odl);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	{
		int upward;
		r = rdp_ber_read_boolean(p + off, len - off, &upward);
		if (r < 0) return -1;
		off += (size_t)r;
	}

	/* Skip three DomainParameters (each is a BER SEQUENCE of
	 * 8 INTEGERs).  We don't care about the values for our use. */
	for (int dp = 0; dp < 3; dp++) {
		r = rdp_ber_read_universal_tag(p + off, len - off,
			RDP_BER_CONSTRUCTED, 0x10, &vlen);
		if (r < 0) return -1;
		off += (size_t)r + vlen;
	}

	/* userData: BER OCTET STRING containing the GCC Conference
	 * Create Request payload. */
	r = rdp_ber_read_octet_string(p + off, len - off,
		&user_data, &user_data_len);
	if (r < 0) return -1;
	off += (size_t)r;

	/* GCC envelope.  Fixed prefix bytes up to "Duca" key + length. */
	ud_off = 0;
	if (user_data_len < 21) return -1;
	/* OID (canonical 7 bytes) and the choice/flags region.  We just
	 * skip to the H.221 key. */
	{
		size_t i;
		int found = 0;
		for (i = 7; i + 4 <= user_data_len; i++) {
			if (user_data[i] == 'D' && user_data[i + 1] == 'u'
			    && user_data[i + 2] == 'c'
			    && user_data[i + 3] == 'a') {
				ud_off = i + 4;
				found = 1;
				break;
			}
		}
		if (!found) return -1;
	}

	/* Variable-length envelope: the user data length determinant
	 * follows the H.221 key.  Then the client data blocks. */
	{
		size_t blob_len;
		ssize_t lr = rdp_per_read_length(user_data + ud_off,
			user_data_len - ud_off, &blob_len);
		if (lr < 0) return -1;
		ud_off += (size_t)lr;
	}

	/* Iterate Client Data Blocks. */
	while (ud_off + 4 <= user_data_len) {
		uint16_t btype = (uint16_t)user_data[ud_off]
			| ((uint16_t)user_data[ud_off + 1] << 8);
		uint16_t blen  = (uint16_t)user_data[ud_off + 2]
			| ((uint16_t)user_data[ud_off + 3] << 8);
		const uint8_t *body;

		if (blen < 4 || blen > user_data_len - ud_off)
			return -1;
		body = user_data + ud_off + 4;
		switch (btype) {
		case RDP_CS_CORE:
			if (blen >= 4 + 16) {
				out->client_version =
					(uint32_t)body[0]
					| ((uint32_t)body[1] << 8)
					| ((uint32_t)body[2] << 16)
					| ((uint32_t)body[3] << 24);
				out->desktop_width  =
					(uint16_t)body[4]
					| ((uint16_t)body[5] << 8);
				out->desktop_height =
					(uint16_t)body[6]
					| ((uint16_t)body[7] << 8);
				out->color_depth    =
					(uint16_t)body[8]
					| ((uint16_t)body[9] << 8);
				/* sasSequence(2), keyboardLayout(4),
				 * clientBuild(4), clientName(32-byte UTF-16LE
				 * starting at offset 18). */
				if (blen >= 4 + 18 + 4) {
					out->keyboard_layout =
						(uint32_t)body[14]
						| ((uint32_t)body[15] << 8)
						| ((uint32_t)body[16] << 16)
						| ((uint32_t)body[17] << 24);
				}
				if (blen >= 4 + 22 + 4) {
					out->client_build =
						(uint32_t)body[18]
						| ((uint32_t)body[19] << 8)
						| ((uint32_t)body[20] << 16)
						| ((uint32_t)body[21] << 24);
				}
				if (blen >= 4 + 22 + 32) {
					size_t i;
					for (i = 0; i < 15; i++)
						out->client_hostname[i] =
							(char)body[22 + i * 2];
				}
			}
			break;
		case RDP_CS_SECURITY:
			if (blen >= 4 + 8) {
				out->encryption_methods =
					(uint32_t)body[0]
					| ((uint32_t)body[1] << 8)
					| ((uint32_t)body[2] << 16)
					| ((uint32_t)body[3] << 24);
				out->ext_encryption_methods =
					(uint32_t)body[4]
					| ((uint32_t)body[5] << 8)
					| ((uint32_t)body[6] << 16)
					| ((uint32_t)body[7] << 24);
			}
			break;
		case RDP_CS_NET:
			if (blen >= 4 + 4) {
				uint32_t cnt = (uint32_t)body[0]
					| ((uint32_t)body[1] << 8)
					| ((uint32_t)body[2] << 16)
					| ((uint32_t)body[3] << 24);
				uint32_t i;
				if (cnt > RDP_MCS_MAX_CHANNELS)
					return -1;
				if (blen < 4 + 4 + cnt * 12)
					return -1;
				out->channel_count = cnt;
				for (i = 0; i < cnt; i++) {
					const uint8_t *cb = body + 4 + i * 12;
					memcpy(out->channels[i].name, cb, 8);
					out->channels[i].options =
						(uint32_t)cb[8]
						| ((uint32_t)cb[9] << 8)
						| ((uint32_t)cb[10] << 16)
						| ((uint32_t)cb[11] << 24);
				}
			}
			break;
		case RDP_CS_CLUSTER:
			if (blen >= 4 + 8) {
				out->cluster_flags =
					(uint32_t)body[0]
					| ((uint32_t)body[1] << 8)
					| ((uint32_t)body[2] << 16)
					| ((uint32_t)body[3] << 24);
				out->redirected_session_id =
					(uint32_t)body[4]
					| ((uint32_t)body[5] << 8)
					| ((uint32_t)body[6] << 16)
					| ((uint32_t)body[7] << 24);
			}
			break;
		default:
			/* Unknown block; ignore. */
			break;
		}
		ud_off += blen;
	}

	(void)off;
	return (ssize_t)len;
}

/* DomainParameters used for Connect Response (server picks these,
 * RDP doesn't actually care about exact values). */
static int
write_domain_params(struct rdp_buf *b)
{
	struct rdp_buf inner;
	uint8_t scratch[64];

	rdp_buf_init(&inner, scratch, sizeof scratch);
	if (rdp_ber_write_integer(&inner, 34) != 0) return -1; /* maxChannelIds */
	if (rdp_ber_write_integer(&inner, 2) != 0)  return -1; /* maxUserIds */
	if (rdp_ber_write_integer(&inner, 0) != 0)  return -1; /* maxTokenIds */
	if (rdp_ber_write_integer(&inner, 1) != 0)  return -1; /* numPriorities */
	if (rdp_ber_write_integer(&inner, 0) != 0)  return -1; /* minThroughput */
	if (rdp_ber_write_integer(&inner, 1) != 0)  return -1; /* maxHeight */
	if (rdp_ber_write_integer(&inner, 0xffff) != 0) return -1; /* maxMcsPduSize */
	if (rdp_ber_write_integer(&inner, 2) != 0)  return -1; /* protocolVersion */

	if (rdp_ber_write_universal(b, RDP_BER_CONSTRUCTED,
		0x10, rdp_buf_used(&inner)) != 0) return -1;
	return rdp_buf_put(b, scratch, rdp_buf_used(&inner));
}

ssize_t
rdp_mcs_build_connect_response(uint8_t *out, size_t cap,
		const struct rdp_mcs_connect_response *r)
{
	uint8_t sc[1024], gcc[1024], envelope[1280];
	struct rdp_buf sb, gb, eb;
	struct rdp_buf b;
	size_t i;

	if (r->channel_count > RDP_MCS_MAX_CHANNELS) return -1;

	/* SC_CORE block: type(2) length(2) version(4) clientRequestedProtocols(4)
	 * earlyCapabilityFlags(4 -- optional, omit). */
	rdp_buf_init(&sb, sc, sizeof sc);
	{
		uint8_t *hdr;
		size_t start;

		hdr = rdp_buf_reserve(&sb, 4);
		if (hdr == NULL) return -1;
		start = rdp_buf_used(&sb);
		if (rdp_buf_put_u32le(&sb, 0x00080004u) != 0) return -1;
		if (rdp_buf_put_u32le(&sb, r->requested_protocols) != 0) return -1;
		hdr[0] = RDP_SC_CORE & 0xff;
		hdr[1] = (RDP_SC_CORE >> 8) & 0xff;
		{
			uint16_t sz = (uint16_t)(rdp_buf_used(&sb) - start + 4);
			hdr[2] = sz & 0xff;
			hdr[3] = (sz >> 8) & 0xff;
		}
	}
	/* SC_SECURITY block. */
	{
		uint8_t *hdr;
		size_t start;
		hdr = rdp_buf_reserve(&sb, 4);
		if (hdr == NULL) return -1;
		start = rdp_buf_used(&sb);
		if (rdp_buf_put_u32le(&sb, r->encryption_method) != 0) return -1;
		if (rdp_buf_put_u32le(&sb, r->encryption_level) != 0) return -1;
		if (rdp_buf_put_u32le(&sb, 0) != 0) return -1;  /* serverRandomLen */
		if (rdp_buf_put_u32le(&sb, 0) != 0) return -1;  /* serverCertLen */
		hdr[0] = RDP_SC_SECURITY & 0xff;
		hdr[1] = (RDP_SC_SECURITY >> 8) & 0xff;
		{
			uint16_t sz = (uint16_t)(rdp_buf_used(&sb) - start + 4);
			hdr[2] = sz & 0xff;
			hdr[3] = (sz >> 8) & 0xff;
		}
	}
	/* SC_NET block: type(2) length(2) MCSChannelId(2) channelCount(2)
	 * channelIds(2 * count) [pad to 4-byte boundary]. */
	{
		uint8_t *hdr;
		size_t start;
		hdr = rdp_buf_reserve(&sb, 4);
		if (hdr == NULL) return -1;
		start = rdp_buf_used(&sb);
		if (rdp_buf_put_u16le(&sb, r->io_channel_id) != 0) return -1;
		if (rdp_buf_put_u16le(&sb, r->channel_count) != 0) return -1;
		for (i = 0; i < r->channel_count; i++) {
			if (rdp_buf_put_u16le(&sb, r->channel_ids[i]) != 0)
				return -1;
		}
		/* Pad to multiple of 4 bytes total block length. */
		while ((rdp_buf_used(&sb) - start + 4) % 4 != 0) {
			if (rdp_buf_put_u8(&sb, 0) != 0) return -1;
		}
		hdr[0] = RDP_SC_NET & 0xff;
		hdr[1] = (RDP_SC_NET >> 8) & 0xff;
		{
			uint16_t sz = (uint16_t)(rdp_buf_used(&sb) - start + 4);
			hdr[2] = sz & 0xff;
			hdr[3] = (sz >> 8) & 0xff;
		}
	}

	/* GCC user data layout that xfreerdp / mstsc expect:
	 *   17-byte fixed prefix (ends with 0xc0 0x00 -- "non-standard
	 *   parameter"), then the H.221 key "McDn", then a single PER
	 *   length determinant covering the server data blocks, then
	 *   the SC_* blocks themselves. */
	rdp_buf_init(&gb, gcc, sizeof gcc);
	if (rdp_buf_put(&gb, GCC_CR_PREFIX, sizeof GCC_CR_PREFIX) != 0) return -1;
	if (rdp_per_write_h221_key(&gb, "McDn") != 0) return -1;
	if (rdp_per_write_length(&gb, rdp_buf_used(&sb)) != 0) return -1;
	if (rdp_buf_put(&gb, sc, rdp_buf_used(&sb)) != 0) return -1;

	/* BER Connect Response envelope: application tag 102 + body. */
	rdp_buf_init(&eb, envelope, sizeof envelope);
	if (rdp_ber_write_enumerated(&eb, 0) != 0) return -1;   /* result = success */
	if (rdp_ber_write_integer(&eb, 0) != 0) return -1;       /* calledConnectId */
	if (write_domain_params(&eb) != 0) return -1;
	if (rdp_ber_write_octet_string(&eb, gcc, rdp_buf_used(&gb)) != 0)
		return -1;

	rdp_buf_init(&b, out, cap);
	if (rdp_ber_write_app_tag(&b, RDP_BER_CONSTRUCTED, 102) != 0) return -1;
	if (rdp_ber_write_length(&b, rdp_buf_used(&eb)) != 0) return -1;
	if (rdp_buf_put(&b, envelope, rdp_buf_used(&eb)) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_mcs_build_attach_user_confirm(uint8_t *out, size_t cap, uint16_t user_id)
{
	if (cap < 5) return -1;
	out[0] = RDP_MCS_TYPE_ATTACH_USER_CFM | 0x02;  /* result subfield = 0,
	                                                  user-id present */
	out[1] = 0;                                    /* result = rt-successful */
	{
		uint16_t initiator = (uint16_t)(user_id - 1001);
		out[2] = (uint8_t)((initiator >> 8) & 0xff);
		out[3] = (uint8_t)(initiator & 0xff);
	}
	return 4;
}

ssize_t
rdp_mcs_build_channel_join_confirm(uint8_t *out, size_t cap,
		uint16_t user_id, uint16_t channel_id)
{
	if (cap < 8) return -1;
	out[0] = RDP_MCS_TYPE_CHANNEL_JOIN_CFM | 0x02;
	out[1] = 0;  /* result = rt-successful */
	{
		uint16_t initiator = (uint16_t)(user_id - 1001);
		out[2] = (uint8_t)((initiator >> 8) & 0xff);
		out[3] = (uint8_t)(initiator & 0xff);
	}
	out[4] = (uint8_t)((channel_id >> 8) & 0xff);
	out[5] = (uint8_t)(channel_id & 0xff);
	out[6] = (uint8_t)((channel_id >> 8) & 0xff);
	out[7] = (uint8_t)(channel_id & 0xff);
	return 8;
}

ssize_t
rdp_mcs_build_disconnect(uint8_t *out, size_t cap, uint8_t reason)
{
	if (cap < 2) return -1;
	out[0] = RDP_MCS_TYPE_DISCONNECT;
	out[1] = (uint8_t)((reason & 0x07) << 5);
	return 2;
}

ssize_t
rdp_mcs_parse_erect_domain(const uint8_t *p, size_t len)
{
	if (len < 1) return -1;
	if (p[0] != RDP_MCS_TYPE_ERECT_DOMAIN) return -1;
	/* Body has subHeight + subInterval per-encoded; we skip. */
	return (ssize_t)len;
}

ssize_t
rdp_mcs_parse_attach_user_request(const uint8_t *p, size_t len)
{
	if (len < 1) return -1;
	if (p[0] != RDP_MCS_TYPE_ATTACH_USER_REQ) return -1;
	return 1;
}

ssize_t
rdp_mcs_parse_channel_join_request(const uint8_t *p, size_t len,
		uint16_t *user_id_out, uint16_t *channel_id_out)
{
	if (len < 5) return -1;
	if (p[0] != RDP_MCS_TYPE_CHANNEL_JOIN_REQ) return -1;
	*user_id_out = (uint16_t)(1001 + (((uint16_t)p[1] << 8) | p[2]));
	*channel_id_out = (uint16_t)(((uint16_t)p[3] << 8) | p[4]);
	return 5;
}

ssize_t
rdp_mcs_parse_disconnect(const uint8_t *p, size_t len, uint8_t *reason_out)
{
	if (len < 2) return -1;
	if (p[0] != RDP_MCS_TYPE_DISCONNECT) return -1;
	*reason_out = (uint8_t)((p[1] >> 5) & 0x07);
	return 2;
}

/* Send Data: PER length determinant of payload length + payload.
 * Length is a "fragmented" small length with high bit 0 (single
 * byte 0..127) or bits 10xxxxxx (two-byte for 128..16383). */
ssize_t
rdp_mcs_build_send_data_indication(uint8_t *out, size_t cap,
		uint16_t user_id, uint16_t channel_id,
		const void *payload, size_t payload_len)
{
	size_t need = 1 + 2 + 2 + 1 + per_len_size(payload_len) + payload_len;
	uint16_t initiator;

	if (need > cap) return -1;
	out[0] = RDP_MCS_TYPE_SEND_DATA_IND;
	initiator = (uint16_t)(user_id - 1001);
	out[1] = (uint8_t)((initiator >> 8) & 0xff);
	out[2] = (uint8_t)(initiator & 0xff);
	out[3] = (uint8_t)((channel_id >> 8) & 0xff);
	out[4] = (uint8_t)(channel_id & 0xff);
	out[5] = 0x70;   /* flags: dataPriority=high, segmentation=BEGIN|END */

	if (payload_len < 128) {
		out[6] = (uint8_t)payload_len;
		memcpy(out + 7, payload, payload_len);
		return (ssize_t)(7 + payload_len);
	}
	if (payload_len < 0x4000) {
		out[6] = (uint8_t)(0x80 | (payload_len >> 8));
		out[7] = (uint8_t)(payload_len & 0xff);
		memcpy(out + 8, payload, payload_len);
		return (ssize_t)(8 + payload_len);
	}
	return -1;
}

ssize_t
rdp_mcs_parse_send_data_request(const uint8_t *p, size_t len,
		uint16_t *user_id_out, uint16_t *channel_id_out,
		const uint8_t **payload_out, size_t *payload_len_out)
{
	size_t off;
	size_t plen;

	if (len < 7) return -1;
	if (p[0] != RDP_MCS_TYPE_SEND_DATA_REQ) return -1;
	*user_id_out = (uint16_t)(1001 + (((uint16_t)p[1] << 8) | p[2]));
	*channel_id_out = (uint16_t)(((uint16_t)p[3] << 8) | p[4]);
	/* p[5] = flags. */
	off = 6;
	if ((p[off] & 0x80) == 0) {
		plen = p[off];
		off += 1;
	} else if ((p[off] & 0xc0) == 0x80) {
		if (len < off + 2) return -1;
		plen = ((size_t)(p[off] & 0x3f) << 8) | (size_t)p[off + 1];
		off += 2;
	} else {
		return -1;
	}
	if (off + plen > len) return -1;
	*payload_out = p + off;
	*payload_len_out = plen;
	return (ssize_t)(off + plen);
}

/* Suppress unused-function warnings when only some code paths use
 * the size helpers. */
__attribute__((unused)) static size_t mcs_unused_ber_app_tag_size(uint32_t t)
	{ return ber_app_tag_size(t); }
