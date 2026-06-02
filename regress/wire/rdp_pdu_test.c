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
 * rdp_pdu_test.c -- byte-layout check for the Save Session Info PDU
 * carrying TS_LOGON_INFO_VERSION_2.
 */

#include "../../src/wire/rdp_pdu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                               \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                   \
	exit(1);                                     \
} while (0)

static uint16_t
rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t
rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
	    | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
test_logon_v2(void)
{
	uint8_t buf[2048];
	ssize_t n;
	size_t i;
	/* alice in UTF-16LE plus the 2-byte null terminator. */
	static const uint8_t alice[] = {
		0x61, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x63, 0x00,
		0x65, 0x00, 0x00, 0x00
	};

	n = rdp_pdu_build_save_session_logon_v2(buf, sizeof buf, 0x3ea,
		0x000103EAu, "", "alice", 7);
	/* 18 hdr + 4 infoType + 18 fixed + 558 pad + 2 domain + 12 user. */
	if (n != 612) FAIL("total length: got %lld want 612", (long long)n);

	/* Share data header. */
	if (rd16(buf + 0) != 612) FAIL("totalLength %u", rd16(buf));
	if (buf[14] != 38) FAIL("pduType2 %u want 38", buf[14]);
	if (rd16(buf + 12) != 612 - 14) FAIL("uncompressedLength %u", rd16(buf + 12));

	/* TS_LOGON_INFO_VERSION_2 body. */
	if (rd32(buf + 18) != 1) FAIL("infoType %u want 1", rd32(buf + 18));
	if (rd16(buf + 22) != 1) FAIL("Version %u want 1", rd16(buf + 22));
	if (rd32(buf + 24) != 576) FAIL("Size %u want 576", rd32(buf + 24));
	if (rd32(buf + 28) != 7) FAIL("SessionId %u want 7", rd32(buf + 28));
	if (rd32(buf + 32) != 2) FAIL("cbDomain %u want 2", rd32(buf + 32));
	if (rd32(buf + 36) != 12) FAIL("cbUserName %u want 12", rd32(buf + 36));

	/* Pad: 558 zero bytes at offset 40. */
	for (i = 40; i < 40 + 558; i++)
		if (buf[i] != 0) FAIL("pad byte %zu nonzero", i);

	/* Domain at 598: empty, just the null terminator. */
	if (buf[598] != 0 || buf[599] != 0) FAIL("domain not empty NUL");

	/* UserName at 600: alice UTF-16LE + NUL. */
	if (memcmp(buf + 600, alice, sizeof alice) != 0)
		FAIL("username bytes wrong");
}

static void
test_truncation(void)
{
	uint8_t buf[2048];
	char longname[400];
	ssize_t n;
	uint32_t cb;

	memset(longname, 'a', sizeof longname - 1);
	longname[sizeof longname - 1] = '\0';

	n = rdp_pdu_build_save_session_logon_v2(buf, sizeof buf, 0x3ea,
		0x000103EAu, "", longname, 0);
	if (n < 0) FAIL("long username build failed");
	cb = rd32(buf + 36);
	/* UserName is clamped to 512 bytes including the null terminator. */
	if (cb > 512) FAIL("cbUserName %u exceeds client cap 512", cb);
	if ((cb % 2) != 0) FAIL("cbUserName %u not even", cb);
	/* Last UTF-16 unit of the UserName field must be the NUL. */
	if (buf[600 + cb - 2] != 0 || buf[600 + cb - 1] != 0)
		FAIL("username not null terminated");
	/* Total must match the share data header. */
	if (rd16(buf) != (uint16_t)n) FAIL("totalLength mismatch on long name");
}

static void
test_small_cap(void)
{
	uint8_t buf[2048];
	ssize_t n;

	n = rdp_pdu_build_save_session_logon_v2(buf, 10, 0x3ea,
		0x000103EAu, "", "alice", 0);
	if (n != -1) FAIL("small cap should return -1, got %lld", (long long)n);
}

int
main(void)
{
	test_logon_v2();
	test_truncation();
	test_small_cap();
	(void)printf("ok\n");
	return 0;
}
