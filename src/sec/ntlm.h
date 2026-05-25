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
 * ntlm.h -- NTLMSSP wire format and NTLMv2 verification.
 *
 * Three messages, MS-NLMP § 2.2.1:
 *   NEGOTIATE_MESSAGE  (client -> server, type 1)
 *   CHALLENGE_MESSAGE  (server -> client, type 2)
 *   AUTHENTICATE_MESSAGE (client -> server, type 3)
 *
 * Common header is "NTLMSSP\0" + u32 message type.  Subsequent
 * fields are { u16 len, u16 maxlen, u32 offset } "Field" triples
 * pointing into the payload area; we serialise that ourselves.
 *
 * NTLMv2 verification (MS-NLMP § 3.3.2):
 *   NTHash         = MD4(UTF-16LE(password))
 *   NTLMv2Hash     = HMAC-MD5(NTHash, UTF-16LE(UPPER(user) || domain))
 *   NTProofStr     = HMAC-MD5(NTLMv2Hash, server_challenge || temp)
 *   SessionBaseKey = HMAC-MD5(NTLMv2Hash, NTProofStr)
 *   KeyExchangeKey = SessionBaseKey  (for NTLMv2 without anonymous)
 *   ExportedSessionKey =
 *       RC4-decrypt(KeyExchangeKey, EncryptedRandomSessionKey)
 *       when NTLMSSP_NEGOTIATE_KEY_EXCH is set, else KeyExchangeKey.
 */

#ifndef RDP_NTLM_H
#define RDP_NTLM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define NTLM_MSG_NEGOTIATE     0x00000001u
#define NTLM_MSG_CHALLENGE     0x00000002u
#define NTLM_MSG_AUTHENTICATE  0x00000003u

#define NTLMSSP_NEGOTIATE_UNICODE                  0x00000001u
#define NTLMSSP_NEGOTIATE_OEM                      0x00000002u
#define NTLMSSP_REQUEST_TARGET                     0x00000004u
#define NTLMSSP_NEGOTIATE_SIGN                     0x00000010u
#define NTLMSSP_NEGOTIATE_SEAL                     0x00000020u
#define NTLMSSP_NEGOTIATE_NTLM                     0x00000200u
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN              0x00008000u
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY 0x00080000u
#define NTLMSSP_NEGOTIATE_TARGET_INFO              0x00800000u
#define NTLMSSP_NEGOTIATE_VERSION                  0x02000000u
#define NTLMSSP_NEGOTIATE_128                      0x20000000u
#define NTLMSSP_NEGOTIATE_KEY_EXCH                 0x40000000u
#define NTLMSSP_NEGOTIATE_56                       0x80000000u

/* AV pair IDs from MS-NLMP § 2.2.2.1. */
#define MSV_AV_EOL              0
#define MSV_AV_NB_COMPUTER_NAME 1
#define MSV_AV_NB_DOMAIN_NAME   2
#define MSV_AV_DNS_COMPUTER_NAME 3
#define MSV_AV_DNS_DOMAIN_NAME   4
#define MSV_AV_TIMESTAMP        7
#define MSV_AV_FLAGS            6
#define MSV_AV_TARGET_NAME      9
#define MSV_AV_CHANNEL_BINDINGS 10
#define MSV_AV_SINGLE_HOST      8

struct ntlm_field {
	const uint8_t *data;
	size_t         len;
};

/* Parsed NEGOTIATE_MESSAGE.  We only inspect the negotiate flags so
 * we can echo back compatible ones in the CHALLENGE. */
struct ntlm_negotiate {
	uint32_t flags;
};

int ntlm_parse_negotiate(const uint8_t *buf, size_t len,
		struct ntlm_negotiate *out);

/* Build a CHALLENGE_MESSAGE.  Uses a freshly generated 8-byte
 * server challenge and embeds the supplied target name (the server
 * hostname or NetBIOS-ish equivalent) plus a TargetInfo AV-pair
 * block with timestamp.  Returns total wire bytes. */
ssize_t ntlm_build_challenge(uint8_t *out, size_t cap,
		uint32_t client_flags,
		const char *target_name,
		uint8_t challenge[8]);

/* Parsed AUTHENTICATE_MESSAGE -- enough to validate NTLMv2 and
 * extract user/domain. */
struct ntlm_authenticate {
	uint32_t flags;

	const uint8_t *lm_response;       size_t lm_response_len;
	const uint8_t *nt_response;       size_t nt_response_len;
	const uint8_t *domain_utf16;      size_t domain_utf16_len;
	const uint8_t *user_utf16;        size_t user_utf16_len;
	const uint8_t *workstation_utf16; size_t workstation_utf16_len;
	const uint8_t *enc_random_skey;   size_t enc_random_skey_len;

	const uint8_t *mic;               /* 16 bytes if present, else NULL */
};

int ntlm_parse_authenticate(const uint8_t *buf, size_t len,
		struct ntlm_authenticate *out);

/* Validate NTLMv2: returns 0 if the supplied cleartext password
 * (UTF-8) produces an NTProofStr that matches the first 16 bytes of
 * the NT response.  Fills the session keys for later RC4 unsealing
 * of EncryptedRandomSessionKey and TSCredentials. */
int ntlm_verify_ntlmv2(const uint8_t server_challenge[8],
		const struct ntlm_authenticate *auth,
		const char *user_utf8, const char *domain_utf8,
		const char *password_utf8,
		uint8_t session_base_key[16]);

/* Same but takes a pre-computed NT hash instead of cleartext. */
int ntlm_verify_ntlmv2_hash(const uint8_t server_challenge[8],
		const struct ntlm_authenticate *auth,
		const uint8_t nt_hash[16],
		uint8_t session_base_key[16]);

/* Derive the ExportedSessionKey: if NTLMSSP_NEGOTIATE_KEY_EXCH is
 * set, RC4-decrypt the EncryptedRandomSessionKey with the
 * KeyExchangeKey (== SessionBaseKey for NTLMv2 plain).  Otherwise
 * the ExportedSessionKey is just the SessionBaseKey. */
int ntlm_derive_exported_key(const struct ntlm_authenticate *auth,
		const uint8_t session_base_key[16],
		uint8_t exported_session_key[16]);

/* RC4 seal/unseal keys for client->server and server->client sub-
 * channels.  Derived from ExportedSessionKey + a fixed magic string
 * (MS-NLMP § 3.4.5.3).  Length is always 16 bytes. */
void ntlm_seal_key(int from_client_to_server,
		const uint8_t exported_session_key[16],
		uint8_t out_key[16]);

void ntlm_sign_key(int from_client_to_server,
		const uint8_t exported_session_key[16],
		uint8_t out_key[16]);

/* NTLM SEAL: encrypt + sign a message. Output is 16-byte signature
 * followed by the encrypted message. Returns total output length
 * (16 + msg_len) or -1 on error. */
ssize_t ntlm_seal_message(const uint8_t seal_key[16],
		const uint8_t sign_key[16],
		uint32_t seq_num,
		const uint8_t *msg, size_t msg_len,
		uint8_t *out, size_t out_cap);

#endif /* RDP_NTLM_H */
