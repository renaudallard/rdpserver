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
 * cssp.h -- MS-CSSP TSRequest DER framing.
 *
 * TSRequest ::= SEQUENCE {
 *     version    [0] INTEGER,
 *     negoTokens [1] NegoData OPTIONAL,
 *     authInfo   [2] OCTET STRING OPTIONAL,
 *     pubKeyAuth [3] OCTET STRING OPTIONAL,
 *     errorCode  [4] INTEGER OPTIONAL,
 *     clientNonce[5] OCTET STRING OPTIONAL
 * }
 *
 * NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
 *
 * v1 implementation: build/parse just version + negoTokens (one
 * blob) + pubKeyAuth + authInfo.  TSCredentials inside authInfo
 * carries the cleartext password we want.
 */

#ifndef RDP_CSSP_H
#define RDP_CSSP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct rdp_tsrequest {
	uint32_t       version;
	const uint8_t *nego_token;     size_t nego_token_len;
	const uint8_t *auth_info;      size_t auth_info_len;
	const uint8_t *pub_key_auth;   size_t pub_key_auth_len;
	const uint8_t *client_nonce;   size_t client_nonce_len;
};

int rdp_cssp_parse(const uint8_t *p, size_t len,
		struct rdp_tsrequest *out);

ssize_t rdp_cssp_build(uint8_t *out, size_t cap,
		const struct rdp_tsrequest *in);

/* TSCredentials carrying TSPasswordCreds (credType=1).  Decoded
 * cleartext fields are pointers into the caller-owned buffer. */
struct rdp_tscredentials {
	const uint8_t *domain_utf16;     size_t domain_utf16_len;
	const uint8_t *user_utf16;       size_t user_utf16_len;
	const uint8_t *password_utf16;   size_t password_utf16_len;
};

int rdp_cssp_parse_tscredentials(const uint8_t *p, size_t len,
		struct rdp_tscredentials *out);

#endif /* RDP_CSSP_H */
