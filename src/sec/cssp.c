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
 * cssp.c -- TSRequest DER parser/builder.
 *
 * The DER subset we need is small enough that the existing BER
 * helpers cover the universal types; the only thing we add is
 * context-specific tagged components ([n] EXPLICIT).
 */

#include "cssp.h"

#include "../common/ber.h"
#include "../common/buf.h"

#include <errno.h>
#include <string.h>

#define BER_CTX_CONSTRUCTED(n) ((uint8_t)(0xA0 | (n)))
#define BER_CTX_PRIMITIVE(n)   ((uint8_t)(0x80 | (n)))

/* Decode a context-specific tag with the given tag number and
 * primitive/constructed flag.  Returns header bytes consumed,
 * stores the inner value length in *vlen, or -1 if no match.
 * Caller checks that vlen fits in the remaining buffer. */
static ssize_t
read_ctx_tag(const uint8_t *p, size_t left, uint8_t wire_tag,
		size_t *vlen)
{
	ssize_t r;
	if (left < 1 || p[0] != wire_tag) return -1;
	r = rdp_ber_read_length(p + 1, left - 1, vlen);
	if (r < 0) return -1;
	return r + 1;
}

int
rdp_cssp_parse(const uint8_t *p, size_t len, struct rdp_tsrequest *out)
{
	size_t outer_len, off = 0;
	ssize_t r;

	memset(out, 0, sizeof *out);
	/* Outer SEQUENCE. */
	r = rdp_ber_read_universal_tag(p + off, len - off,
		RDP_BER_CONSTRUCTED, 0x10, &outer_len);
	if (r < 0) return -1;
	off += (size_t)r;
	if (off + outer_len > len) return -1;

	while (off < len) {
		size_t comp_len;
		uint8_t tag;
		if (off + 1 > len) return -1;
		tag = p[off];

		if (tag == BER_CTX_CONSTRUCTED(0)) {
			/* version */
			uint32_t v;
			r = read_ctx_tag(p + off, len - off, tag, &comp_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_integer(p + off, comp_len, &v);
			if (r < 0) return -1;
			out->version = v;
			off += comp_len;
		} else if (tag == BER_CTX_CONSTRUCTED(1)) {
			/* negoTokens: SEQUENCE OF SEQUENCE {
			 *     negoToken [0] OCTET STRING } */
			size_t outer_seq_len, inner_seq_len, ns_inner_len;
			r = read_ctx_tag(p + off, len - off, tag,
				&outer_seq_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_universal_tag(p + off, outer_seq_len,
				RDP_BER_CONSTRUCTED, 0x10, &inner_seq_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_universal_tag(p + off, inner_seq_len,
				RDP_BER_CONSTRUCTED, 0x10, &ns_inner_len);
			if (r < 0) return -1;
			off += (size_t)r;
			{
				size_t blob_len;
				r = read_ctx_tag(p + off, ns_inner_len,
					BER_CTX_CONSTRUCTED(0), &blob_len);
				if (r < 0) return -1;
				off += (size_t)r;
				{
					const uint8_t *od;
					size_t odl;
					r = rdp_ber_read_octet_string(p + off,
						blob_len, &od, &odl);
					if (r < 0) return -1;
					out->nego_token = od;
					out->nego_token_len = odl;
					off += blob_len;
				}
			}
		} else if (tag == BER_CTX_CONSTRUCTED(2)) {
			const uint8_t *od;
			size_t odl;
			r = read_ctx_tag(p + off, len - off, tag, &comp_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_octet_string(p + off, comp_len,
				&od, &odl);
			if (r < 0) return -1;
			out->auth_info = od;
			out->auth_info_len = odl;
			off += comp_len;
		} else if (tag == BER_CTX_CONSTRUCTED(3)) {
			const uint8_t *od;
			size_t odl;
			r = read_ctx_tag(p + off, len - off, tag, &comp_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_octet_string(p + off, comp_len,
				&od, &odl);
			if (r < 0) return -1;
			out->pub_key_auth = od;
			out->pub_key_auth_len = odl;
			off += comp_len;
		} else if (tag == BER_CTX_CONSTRUCTED(5)) {
			const uint8_t *od;
			size_t odl;
			r = read_ctx_tag(p + off, len - off, tag, &comp_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_octet_string(p + off, comp_len,
				&od, &odl);
			if (r < 0) return -1;
			out->client_nonce = od;
			out->client_nonce_len = odl;
			off += comp_len;
		} else {
			r = rdp_ber_read_length(p + off + 1, len - off - 1,
				&comp_len);
			if (r < 0) return -1;
			off += (size_t)r + 1 + comp_len;
		}
	}
	return 0;
}

static int
put_ctx_tagged_inner(struct rdp_buf *b, uint8_t wire_tag,
		const void *inner, size_t inner_len)
{
	if (rdp_buf_put_u8(b, wire_tag) != 0) return -1;
	if (rdp_ber_write_length(b, inner_len) != 0) return -1;
	if (inner_len > 0 && rdp_buf_put(b, inner, inner_len) != 0)
		return -1;
	return 0;
}

ssize_t
rdp_cssp_build(uint8_t *out, size_t cap, const struct rdp_tsrequest *in)
{
	uint8_t version_buf[8];
	struct rdp_buf vb, body;
	size_t body_used;
	uint8_t body_buf[8 * 1024];
	uint8_t nego_outer[8 * 1024];
	struct rdp_buf no;
	size_t nego_outer_used = 0;

	/* version. */
	rdp_buf_init(&vb, version_buf, sizeof version_buf);
	if (rdp_ber_write_integer(&vb, in->version) != 0) return -1;

	rdp_buf_init(&body, body_buf, sizeof body_buf);
	if (put_ctx_tagged_inner(&body, BER_CTX_CONSTRUCTED(0),
		version_buf, rdp_buf_used(&vb)) != 0) return -1;

	if (in->nego_token_len > 0) {
		uint8_t blob_outer[4 * 1024];
		struct rdp_buf bo;
		uint8_t inner_octet[4 * 1024];
		struct rdp_buf io_;
		uint8_t inner_seq[4 * 1024];
		struct rdp_buf is;
		uint8_t outer_seq[4 * 1024];
		struct rdp_buf os;

		rdp_buf_init(&io_, inner_octet, sizeof inner_octet);
		if (rdp_ber_write_octet_string(&io_, in->nego_token,
			in->nego_token_len) != 0) return -1;
		rdp_buf_init(&bo, blob_outer, sizeof blob_outer);
		if (put_ctx_tagged_inner(&bo, BER_CTX_CONSTRUCTED(0),
			inner_octet, rdp_buf_used(&io_)) != 0) return -1;
		rdp_buf_init(&is, inner_seq, sizeof inner_seq);
		if (rdp_ber_write_universal(&is, RDP_BER_CONSTRUCTED,
			0x10, rdp_buf_used(&bo)) != 0) return -1;
		if (rdp_buf_put(&is, blob_outer, rdp_buf_used(&bo)) != 0)
			return -1;
		rdp_buf_init(&os, outer_seq, sizeof outer_seq);
		if (rdp_ber_write_universal(&os, RDP_BER_CONSTRUCTED,
			0x10, rdp_buf_used(&is)) != 0) return -1;
		if (rdp_buf_put(&os, inner_seq, rdp_buf_used(&is)) != 0)
			return -1;
		rdp_buf_init(&no, nego_outer, sizeof nego_outer);
		if (put_ctx_tagged_inner(&no, BER_CTX_CONSTRUCTED(1),
			outer_seq, rdp_buf_used(&os)) != 0) return -1;
		nego_outer_used = rdp_buf_used(&no);
		if (rdp_buf_put(&body, nego_outer, nego_outer_used) != 0)
			return -1;
	}
	if (in->auth_info_len > 0) {
		uint8_t oct[4096];
		struct rdp_buf ob;
		rdp_buf_init(&ob, oct, sizeof oct);
		if (rdp_ber_write_octet_string(&ob, in->auth_info,
			in->auth_info_len) != 0) return -1;
		if (put_ctx_tagged_inner(&body, BER_CTX_CONSTRUCTED(2),
			oct, rdp_buf_used(&ob)) != 0) return -1;
	}
	if (in->pub_key_auth_len > 0) {
		uint8_t oct[4096];
		struct rdp_buf ob;
		rdp_buf_init(&ob, oct, sizeof oct);
		if (rdp_ber_write_octet_string(&ob, in->pub_key_auth,
			in->pub_key_auth_len) != 0) return -1;
		if (put_ctx_tagged_inner(&body, BER_CTX_CONSTRUCTED(3),
			oct, rdp_buf_used(&ob)) != 0) return -1;
	}

	body_used = rdp_buf_used(&body);
	{
		struct rdp_buf out_b;
		rdp_buf_init(&out_b, out, cap);
		if (rdp_ber_write_universal(&out_b, RDP_BER_CONSTRUCTED,
			0x10, body_used) != 0) return -1;
		if (rdp_buf_put(&out_b, body_buf, body_used) != 0) return -1;
		return (ssize_t)rdp_buf_used(&out_b);
	}
}

/* TSCredentials ::= SEQUENCE {
 *   credType  [0] INTEGER,
 *   credentials [1] OCTET STRING   -- DER of TSPasswordCreds when credType=1
 * }
 * TSPasswordCreds ::= SEQUENCE {
 *   domainName   [0] OCTET STRING,
 *   userName     [1] OCTET STRING,
 *   password     [2] OCTET STRING
 * } */
int
rdp_cssp_parse_tscredentials(const uint8_t *p, size_t len,
		struct rdp_tscredentials *out)
{
	size_t outer_len, off = 0, comp_len;
	ssize_t r;
	uint32_t cred_type = 0;
	const uint8_t *creds_blob = NULL;
	size_t  creds_blob_len = 0;

	memset(out, 0, sizeof *out);

	r = rdp_ber_read_universal_tag(p + off, len - off,
		RDP_BER_CONSTRUCTED, 0x10, &outer_len);
	if (r < 0) return -1;
	off += (size_t)r;
	while (off < len) {
		uint8_t tag = p[off];
		if (tag == BER_CTX_CONSTRUCTED(0)) {
			r = read_ctx_tag(p + off, len - off, tag, &comp_len);
			if (r < 0) return -1;
			off += (size_t)r;
			r = rdp_ber_read_integer(p + off, comp_len, &cred_type);
			if (r < 0) return -1;
			off += comp_len;
		} else if (tag == BER_CTX_CONSTRUCTED(1)) {
			r = read_ctx_tag(p + off, len - off, tag, &comp_len);
			if (r < 0) return -1;
			off += (size_t)r;
			{
				const uint8_t *od; size_t odl;
				r = rdp_ber_read_octet_string(p + off, comp_len,
					&od, &odl);
				if (r < 0) return -1;
				creds_blob = od;
				creds_blob_len = odl;
				off += comp_len;
			}
		} else {
			r = rdp_ber_read_length(p + off + 1, len - off - 1,
				&comp_len);
			if (r < 0) return -1;
			off += (size_t)r + 1 + comp_len;
		}
	}
	if (cred_type != 1 || creds_blob == NULL) return -1;

	/* Now parse TSPasswordCreds. */
	off = 0;
	r = rdp_ber_read_universal_tag(creds_blob, creds_blob_len,
		RDP_BER_CONSTRUCTED, 0x10, &outer_len);
	if (r < 0) return -1;
	off += (size_t)r;
	while (off < creds_blob_len) {
		uint8_t tag = creds_blob[off];
		uint8_t which = (uint8_t)(tag & 0x1f);
		if ((tag & 0xe0) != 0xa0) return -1;
		r = read_ctx_tag(creds_blob + off, creds_blob_len - off,
			tag, &comp_len);
		if (r < 0) return -1;
		off += (size_t)r;
		{
			const uint8_t *od; size_t odl;
			r = rdp_ber_read_octet_string(creds_blob + off,
				comp_len, &od, &odl);
			if (r < 0) return -1;
			switch (which) {
			case 0: out->domain_utf16   = od; out->domain_utf16_len = odl; break;
			case 1: out->user_utf16     = od; out->user_utf16_len   = odl; break;
			case 2: out->password_utf16 = od; out->password_utf16_len = odl; break;
			}
			off += comp_len;
		}
	}
	(void)errno;
	return 0;
}
