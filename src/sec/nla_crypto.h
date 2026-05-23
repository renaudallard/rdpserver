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
 * nla_crypto.h -- crypto primitives that NLA / CredSSP / NTLMv2 need.
 * Thin wrappers around OpenSSL/LibreSSL EVP so callers don't have
 * to deal with the API churn between OpenSSL 1.x and 3.x.
 *
 * Algorithms exposed:
 *   MD4         (NT hash of UTF-16LE password)
 *   HMAC-MD5    (NTLMv2 hash, NTProofStr, sealing key derivation)
 *   RC4 stream  (encrypt/decrypt TSCredentials and EncryptedRandom-
 *                SessionKey using the negotiated NTLM seal key)
 */

#ifndef RDP_NLA_CRYPTO_H
#define RDP_NLA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define RDP_MD4_LEN 16
#define RDP_MD5_LEN 16

int rdp_md4(const void *data, size_t len, uint8_t out[RDP_MD4_LEN]);

int rdp_hmac_md5(const void *key, size_t key_len,
		const void *data, size_t data_len,
		uint8_t out[RDP_MD5_LEN]);

/* Two-buffer convenience: HMAC over concatenation of (a, b) without
 * allocating. */
int rdp_hmac_md5_2(const void *key, size_t key_len,
		const void *a, size_t a_len,
		const void *b, size_t b_len,
		uint8_t out[RDP_MD5_LEN]);

/* Stateful RC4 stream cipher.  Same context for encrypt and decrypt
 * (RC4 is symmetric).  NTLM uses separate seal contexts for the two
 * directions but the cipher is the same. */
struct rdp_rc4;
struct rdp_rc4 *rdp_rc4_new(const void *key, size_t key_len);
void            rdp_rc4_process(struct rdp_rc4 *r,
			const void *in, void *out, size_t len);
void            rdp_rc4_free(struct rdp_rc4 *r);

#endif /* RDP_NLA_CRYPTO_H */
