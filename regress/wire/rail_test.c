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
 * rail_test.c -- MS-RDPERP RAIL order build/parse.
 *
 * Checks the server HANDSHAKE and EXEC_RESULT byte layout, the parse of
 * client HANDSHAKE / CLIENTSTATUS / EXEC orders (including the three
 * length-prefixed UTF-16 strings), and rejection of truncated or
 * inconsistent orders (covered by $(TEST_SAN)).
 */

#include "../../src/channels/rail.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
test_build(void)
{
	uint8_t out[64];
	ssize_t n;
	const uint8_t hs[] = { 0x05, 0x00, 0x08, 0x00, 0xD2, 0x04, 0x00, 0x00 };
	const uint8_t exe[] = { 'a', 0x00, 'b', 0x00 };  /* "ab" UTF-16LE */

	/* HANDSHAKE buildNumber 0x04D2 (1234). */
	n = rdp_rail_build_handshake(out, sizeof out, 1234);
	if (n != 8) FAIL("handshake len %zd", (ssize_t)n);
	if (memcmp(out, hs, 8) != 0) FAIL("handshake bytes");
	if (rdp_rail_build_handshake(out, 4, 1) != -1)
		FAIL("handshake should reject small buffer");

	/* EXEC_RESULT: header(4)+flags(2)+result(2)+raw(4)+pad(2)+len(2)+exe. */
	n = rdp_rail_build_exec_result(out, sizeof out, 0, RAIL_EXEC_S_OK,
		0, exe, sizeof exe);
	if (n != 16 + (ssize_t)sizeof exe) FAIL("exec_result len %zd",
		(ssize_t)n);
	if (out[0] != 0x80 || out[1] != 0x00) FAIL("exec_result orderType");
	if (out[2] != (uint8_t)(16 + sizeof exe) || out[3] != 0)
		FAIL("exec_result orderLength");
	if (out[6] != RAIL_EXEC_S_OK) FAIL("exec_result code");
	if (out[14] != sizeof exe || out[15] != 0) FAIL("exec_result exeLen");
	if (memcmp(out + 16, exe, sizeof exe) != 0) FAIL("exec_result exe");
	/* NULL exe yields a zero-length string. */
	n = rdp_rail_build_exec_result(out, sizeof out, 0, RAIL_EXEC_E_FAIL,
		1, NULL, 7);
	if (n != 16) FAIL("exec_result null exe len %zd", (ssize_t)n);
	if (out[14] != 0 || out[15] != 0) FAIL("exec_result null exeLen");
}

static void
test_parse(void)
{
	struct rdp_rail_order o;
	/* client HANDSHAKE */
	const uint8_t hs[] = { 0x05, 0x00, 0x08, 0x00, 0x39, 0x30, 0x00, 0x00 };
	/* CLIENTSTATUS flags 0x07 */
	const uint8_t cs[] = { 0x0B, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00 };
	/* EXEC: flags=0, exeLen=4 ("a\0b\0"), workLen=2 ("c\0"), argLen=0 */
	const uint8_t ex[] = {
		0x01, 0x00, 0x12, 0x00,   /* orderType EXEC, len 18 */
		0x00, 0x00,               /* flags */
		0x04, 0x00,               /* exeOrFileLength = 4 */
		0x02, 0x00,               /* workingDirLength = 2 */
		0x00, 0x00,               /* argumentsLength = 0 */
		'a', 0x00, 'b', 0x00,     /* exe "ab" */
		'c', 0x00                 /* workdir "c" */
	};

	if (rdp_rail_parse_order(hs, sizeof hs, &o) != 0) FAIL("parse hs");
	if (o.order_type != RAIL_ORDER_HANDSHAKE) FAIL("hs type");
	if (o.build_number != 0x3039) FAIL("hs build %u", o.build_number);

	if (rdp_rail_parse_order(cs, sizeof cs, &o) != 0) FAIL("parse cs");
	if (o.order_type != RAIL_ORDER_CLIENTSTATUS) FAIL("cs type");
	if (o.client_status != 0x07) FAIL("cs status");

	if (rdp_rail_parse_order(ex, sizeof ex, &o) != 0) FAIL("parse exec");
	if (o.order_type != RAIL_ORDER_EXEC) FAIL("exec type");
	if (o.exe_len != 4 || o.exe == NULL
	    || memcmp(o.exe, ex + 12, 4) != 0) FAIL("exec exe");
	if (o.workdir_len != 2 || o.workdir == NULL
	    || memcmp(o.workdir, ex + 16, 2) != 0) FAIL("exec workdir");
	if (o.args_len != 0 || o.args != NULL) FAIL("exec args");
}

static void
test_bad(void)
{
	struct rdp_rail_order o;
	const uint8_t hs[] = { 0x05, 0x00, 0x08, 0x00, 0x39, 0x30, 0x00, 0x00 };
	/* EXEC whose string lengths run past the declared orderLength. */
	const uint8_t ex_bad[] = {
		0x01, 0x00, 0x0E, 0x00,   /* len 14 */
		0x00, 0x00, 0x40, 0x00,   /* exeLen = 64 (overruns) */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00
	};
	size_t i;

	/* orderLength larger than the buffer is rejected. */
	{
		uint8_t big[] = { 0x05, 0x00, 0xFF, 0x00, 0, 0, 0, 0 };
		if (rdp_rail_parse_order(big, sizeof big, &o) != -1)
			FAIL("oversize orderLength accepted");
	}
	if (rdp_rail_parse_order(ex_bad, sizeof ex_bad, &o) != -1)
		FAIL("exec string overrun accepted");
	/* A header shorter than 4 bytes is rejected, never over-read. */
	for (i = 0; i < 4; i++) {
		if (rdp_rail_parse_order(hs, i, &o) != -1)
			FAIL("short header %zu accepted", i);
	}
}

int
main(void)
{
	test_build();
	test_parse();
	test_bad();
	(void)printf("rail_test: all ok\n");
	return 0;
}
