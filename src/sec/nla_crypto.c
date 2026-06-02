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
 * nla_crypto.c -- NTLM crypto primitives via OpenSSL/LibreSSL EVP.
 */

#include "nla_crypto.h"

#include "../include/rdp_log.h"

/* OpenSSL 3.0 deprecated HMAC_*; EVP_MAC is the new API but
 * LibreSSL doesn't ship it yet.  Silence the deprecation here so
 * the same code compiles cleanly on both. */
#if defined(__GNUC__) || defined(__clang__)
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int legacy_loaded = 0;
static void
ensure_legacy_provider(void)
{
	if (legacy_loaded) return;
	if (OSSL_PROVIDER_load(NULL, "legacy") != NULL) {
		OSSL_PROVIDER_load(NULL, "default");
		legacy_loaded = 1;
	}
}
#endif

void
rdp_nla_crypto_init(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	ensure_legacy_provider();
#endif
}

int
rdp_md4(const void *data, size_t len, uint8_t out[RDP_MD4_LEN])
{
	EVP_MD_CTX *ctx;
	unsigned int outlen = 0;
	int rc = -1;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) return -1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	ensure_legacy_provider();
#endif
	if (EVP_DigestInit_ex(ctx, EVP_md4(), NULL) != 1) goto out;
	if (EVP_DigestUpdate(ctx, data, len) != 1) goto out;
	if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) goto out;
	if (outlen != RDP_MD4_LEN) goto out;
	rc = 0;
out:
	EVP_MD_CTX_free(ctx);
	return rc;
}

int
rdp_hmac_md5(const void *key, size_t key_len,
		const void *data, size_t data_len,
		uint8_t out[RDP_MD5_LEN])
{
	unsigned int outlen = RDP_MD5_LEN;
	if (HMAC(EVP_md5(), key, (int)key_len, data, data_len,
		out, &outlen) == NULL)
		return -1;
	if (outlen != RDP_MD5_LEN) return -1;
	return 0;
}

int
rdp_hmac_md5_2(const void *key, size_t key_len,
		const void *a, size_t a_len,
		const void *b, size_t b_len,
		uint8_t out[RDP_MD5_LEN])
{
	HMAC_CTX *ctx;
	unsigned int outlen = RDP_MD5_LEN;
	int rc = -1;

	ctx = HMAC_CTX_new();
	if (ctx == NULL) return -1;
	if (HMAC_Init_ex(ctx, key, (int)key_len, EVP_md5(), NULL) != 1)
		goto out;
	if (HMAC_Update(ctx, a, a_len) != 1) goto out;
	if (HMAC_Update(ctx, b, b_len) != 1) goto out;
	if (HMAC_Final(ctx, out, &outlen) != 1) goto out;
	if (outlen != RDP_MD5_LEN) goto out;
	rc = 0;
out:
	HMAC_CTX_free(ctx);
	return rc;
}

struct rdp_rc4 {
	EVP_CIPHER_CTX *ctx;
};

struct rdp_rc4 *
rdp_rc4_new(const void *key, size_t key_len)
{
	struct rdp_rc4 *r;

	r = calloc(1, sizeof *r);
	if (r == NULL) return NULL;
	r->ctx = EVP_CIPHER_CTX_new();
	if (r->ctx == NULL) { free(r); return NULL; }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	ensure_legacy_provider();
#endif
	if (EVP_EncryptInit_ex(r->ctx, EVP_rc4(), NULL, NULL, NULL) != 1)
		goto err;
	if (EVP_CIPHER_CTX_set_padding(r->ctx, 0) != 1)
		goto err;
	if (EVP_CIPHER_CTX_set_key_length(r->ctx, (int)key_len) != 1)
		goto err;
	if (EVP_EncryptInit_ex(r->ctx, NULL, NULL, key, NULL) != 1) goto err;
	return r;
err:
	EVP_CIPHER_CTX_free(r->ctx);
	free(r);
	return NULL;
}

void
rdp_rc4_process(struct rdp_rc4 *r, const void *in, void *out, size_t len)
{
	int outlen = 0;
	(void)EVP_EncryptUpdate(r->ctx, out, &outlen, in, (int)len);
}

void
rdp_rc4_free(struct rdp_rc4 *r)
{
	if (r == NULL) return;
	EVP_CIPHER_CTX_free(r->ctx);
	free(r);
}
