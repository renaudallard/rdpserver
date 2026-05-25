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
 * tls.c -- TLS server wrapper using OpenSSL.
 *
 * This release targets the OpenSSL backend selected by configure.
 * A libtls path is straightforward to add later; the public API
 * here is deliberately small and library-agnostic.
 *
 * Self-signed certificate generation uses OpenSSL's EVP API and a
 * minimal X509 builder so we don't depend on the openssl(1) command.
 * Generated artifacts go to tmp/server.{crt,key} relative to CWD,
 * per the project policy of not touching /tmp.
 */

#include "tls.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/io.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct rdp_tls_ctx {
	SSL_CTX *ctx;
};

struct rdp_tls {
	SSL *ssl;
	int  fd;
};

static int tls_inited;

static void
tls_init_once(void)
{
	if (tls_inited)
		return;
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	tls_inited = 1;
}

static void
tls_log_err(const char *what)
{
	unsigned long e;
	char buf[256];

	while ((e = ERR_get_error()) != 0) {
		ERR_error_string_n(e, buf, sizeof buf);
		rdp_err("%s: %s", what, buf);
	}
}

struct rdp_tls_ctx *
rdp_tls_ctx_new(const char *cert_pem, const char *key_pem)
{
	struct rdp_tls_ctx *t;

	tls_init_once();
	t = calloc(1, sizeof *t);
	if (t == NULL)
		return NULL;

	t->ctx = SSL_CTX_new(TLS_server_method());
	if (t->ctx == NULL) {
		tls_log_err("SSL_CTX_new");
		free(t);
		return NULL;
	}
	(void)SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION);
	(void)SSL_CTX_set_options(t->ctx,
		SSL_OP_NO_COMPRESSION
		| SSL_OP_NO_RENEGOTIATION
		| SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (SSL_CTX_use_certificate_chain_file(t->ctx, cert_pem) != 1) {
		tls_log_err("use_certificate_chain_file");
		SSL_CTX_free(t->ctx);
		free(t);
		return NULL;
	}
	if (SSL_CTX_use_PrivateKey_file(t->ctx, key_pem, SSL_FILETYPE_PEM) != 1) {
		tls_log_err("use_PrivateKey_file");
		SSL_CTX_free(t->ctx);
		free(t);
		return NULL;
	}
	if (SSL_CTX_check_private_key(t->ctx) != 1) {
		tls_log_err("check_private_key");
		SSL_CTX_free(t->ctx);
		free(t);
		return NULL;
	}
	return t;
}

void
rdp_tls_ctx_free(struct rdp_tls_ctx *t)
{
	if (t == NULL) return;
	if (t->ctx != NULL) SSL_CTX_free(t->ctx);
	free(t);
}

int
rdp_tls_ensure_selfsigned(const char *cert_path, const char *key_path,
		const char *cn)
{
	struct stat st;
	EVP_PKEY *pk = NULL;
	X509 *x = NULL;
	X509_NAME *name;
	BIO *bcrt = NULL, *bkey = NULL;
	int rc = -1;

	tls_init_once();

	if (stat(cert_path, &st) == 0 && stat(key_path, &st) == 0)
		return 0;

	{
		EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
		if (kctx == NULL) {
			tls_log_err("EVP_PKEY_CTX_new_id");
			goto out;
		}
		if (EVP_PKEY_keygen_init(kctx) <= 0
		    || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0
		    || EVP_PKEY_keygen(kctx, &pk) <= 0) {
			tls_log_err("EVP_PKEY_keygen");
			EVP_PKEY_CTX_free(kctx);
			goto out;
		}
		EVP_PKEY_CTX_free(kctx);
	}
	if (pk == NULL) goto out;

	x = X509_new();
	if (x == NULL) { tls_log_err("X509_new"); goto out; }
	(void)X509_set_version(x, 2);
	(void)ASN1_INTEGER_set(X509_get_serialNumber(x), (long)time(NULL));
	(void)X509_gmtime_adj(X509_get_notBefore(x), 0);
	(void)X509_gmtime_adj(X509_get_notAfter(x),
		(long)(60 * 60 * 24 * 365 * 5));   /* 5 years */
	if (!X509_set_pubkey(x, pk)) { tls_log_err("set_pubkey"); goto out; }

	name = X509_get_subject_name(x);
	(void)X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
		(const unsigned char *)cn, -1, -1, 0);
	if (!X509_set_issuer_name(x, name)) goto out;
	if (!X509_sign(x, pk, EVP_sha256())) {
		tls_log_err("X509_sign");
		goto out;
	}

	bcrt = BIO_new_file(cert_path, "w");
	if (bcrt == NULL || !PEM_write_bio_X509(bcrt, x)) {
		tls_log_err("write cert");
		goto out;
	}
	(void)chmod(cert_path, 0644);

	{
		int kfd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (kfd < 0) { tls_log_err("open key"); goto out; }
		bkey = BIO_new_fd(kfd, BIO_CLOSE);
		if (bkey == NULL) { close(kfd); goto out; }
	}
	if (!PEM_write_bio_PrivateKey(bkey, pk,
			NULL, NULL, 0, NULL, NULL)) {
		tls_log_err("write key");
		goto out;
	}

	rc = 0;
out:
	if (bcrt) BIO_free(bcrt);
	if (bkey) BIO_free(bkey);
	if (x)    X509_free(x);
	if (pk)   EVP_PKEY_free(pk);
	return rc;
}

struct rdp_tls *
rdp_tls_accept(struct rdp_tls_ctx *ctx, int fd)
{
	struct rdp_tls *t;

	t = calloc(1, sizeof *t);
	if (t == NULL) return NULL;
	t->fd = fd;
	t->ssl = SSL_new(ctx->ctx);
	if (t->ssl == NULL) { free(t); return NULL; }
	if (SSL_set_fd(t->ssl, fd) != 1) {
		SSL_free(t->ssl);
		free(t);
		return NULL;
	}
	for (;;) {
		int r = SSL_accept(t->ssl);
		if (r == 1) break;
		int err = SSL_get_error(t->ssl, r);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			continue;
		tls_log_err("SSL_accept");
		SSL_free(t->ssl);
		free(t);
		return NULL;
	}
	return t;
}

ssize_t
rdp_tls_read(struct rdp_tls *t, void *buf, size_t n)
{
	int r;
	for (;;) {
		r = SSL_read(t->ssl, buf,
			n > (size_t)INT_MAX ? INT_MAX : (int)n);
		if (r > 0) return r;
		if (r == 0) return 0;
		int err = SSL_get_error(t->ssl, r);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			continue;
		errno = EIO;
		return -1;
	}
}

ssize_t
rdp_tls_write(struct rdp_tls *t, const void *buf, size_t n)
{
	int r;
	for (;;) {
		r = SSL_write(t->ssl, buf,
			n > (size_t)INT_MAX ? INT_MAX : (int)n);
		if (r > 0) return r;
		int err = SSL_get_error(t->ssl, r);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			continue;
		errno = EIO;
		return -1;
	}
}

ssize_t
rdp_tls_read_full(struct rdp_tls *t, void *buf, size_t n)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < n) {
		ssize_t r = rdp_tls_read(t, p + got, n - got);
		if (r == 0) return (ssize_t)got;
		if (r < 0)  return -1;
		got += (size_t)r;
	}
	return (ssize_t)got;
}

ssize_t
rdp_tls_write_full(struct rdp_tls *t, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	size_t sent = 0;

	while (sent < n) {
		ssize_t r = rdp_tls_write(t, p + sent, n - sent);
		if (r <= 0) return -1;
		sent += (size_t)r;
	}
	return (ssize_t)sent;
}

int
rdp_tls_fd(const struct rdp_tls *t)
{
	return t->fd;
}

ssize_t
rdp_tls_get_server_pubkey(struct rdp_tls *t, uint8_t *out, size_t cap)
{
	X509 *cert;
	unsigned char *der = NULL;
	int len;

	if (t == NULL || t->ssl == NULL) return -1;
	cert = SSL_get_certificate(t->ssl);
	if (cert == NULL) return -1;
	len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
	if (len <= 0 || der == NULL) return -1;
	if ((size_t)len > cap) { OPENSSL_free(der); return -1; }
	memcpy(out, der, (size_t)len);
	OPENSSL_free(der);
	return (ssize_t)len;
}

void
rdp_tls_close(struct rdp_tls *t)
{
	if (t == NULL) return;
	if (t->ssl != NULL) {
		(void)SSL_shutdown(t->ssl);
		SSL_free(t->ssl);
	}
	free(t);
}
