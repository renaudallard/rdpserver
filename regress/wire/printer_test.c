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
 * printer_test.c -- unit tests for the session printer module.
 *
 * Covers the two pieces that have no external dependency and that the live
 * CUPS path relies on being correct: the CUPS queue name sanitization rules
 * and the fixed wire header layout shared with rdp-cups-backend.
 */

#include "../../src/session/printer.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fails;

#define CHECK(cond, msg) do {						\
	if (!(cond)) {							\
		fprintf(stderr, "FAIL: %s (%s:%d)\n", msg,		\
		    __FILE__, __LINE__);				\
		fails++;						\
	}								\
} while (0)

static void
test_sanitize(void)
{
	char out[64];

	/* Plain ASCII name keeps its characters under the rdp- prefix. */
	CHECK(rdp_printer_sanitize("Office", out, sizeof out) == 0, "san ok");
	CHECK(strcmp(out, "rdp-Office") == 0, "ascii passthrough");

	/* Spaces, slashes, colons and other punctuation map to '_'. */
	CHECK(rdp_printer_sanitize("HP Laser/Jet:1", out, sizeof out) == 0,
	    "san ok2");
	CHECK(strcmp(out, "rdp-HP_Laser_Jet_1") == 0, "punct mapped");

	/* Dash, underscore and digits are preserved. */
	CHECK(rdp_printer_sanitize("a-b_c9", out, sizeof out) == 0, "san ok3");
	CHECK(strcmp(out, "rdp-a-b_c9") == 0, "dash/underscore/digit kept");

	/* UTF-8 multibyte bytes each become '_' (no raw high bytes leak). */
	CHECK(rdp_printer_sanitize("caf\xc3\xa9", out, sizeof out) == 0,
	    "san ok4");
	CHECK(strcmp(out, "rdp-caf__") == 0, "utf8 bytes mapped");
	{
		size_t i;
		for (i = 0; out[i] != '\0'; i++)
			CHECK((unsigned char)out[i] < 0x80, "ascii only");
	}

	/* Empty name falls back to a fixed stem. */
	CHECK(rdp_printer_sanitize("", out, sizeof out) == 0, "san empty");
	CHECK(strcmp(out, "rdp-printer") == 0, "empty fallback");

	/* Junk characters map to underscores (the name is non-empty, so no
	 * fallback): each '/' becomes '_'. */
	CHECK(rdp_printer_sanitize("///", out, sizeof out) == 0, "san junk");
	CHECK(strcmp(out, "rdp-___") == 0, "junk mapped to underscores");

	/* NULL name behaves like empty. */
	CHECK(rdp_printer_sanitize(NULL, out, sizeof out) == 0, "san null");
	CHECK(strcmp(out, "rdp-printer") == 0, "null fallback");

	/* A buffer too small to hold even the prefix fails cleanly. */
	CHECK(rdp_printer_sanitize("x", out, 4) == -1, "tiny buffer fails");

	/* A long name is bounded by the output buffer (no overflow). */
	{
		char big[300];
		char small[16];
		memset(big, 'A', sizeof big - 1);
		big[sizeof big - 1] = '\0';
		CHECK(rdp_printer_sanitize(big, small, sizeof small) == 0,
		    "san long");
		CHECK(strlen(small) < sizeof small, "long bounded");
		CHECK(strncmp(small, "rdp-A", 5) == 0, "long prefix");
	}
}

static void
test_wire_hdr(void)
{
	struct rdp_print_wire_hdr h;
	uint8_t buf[8];

	/* The header is exactly the two fields, no padding: this is the
	 * contract rdp-cups-backend writes and the session reads. */
	CHECK(sizeof h == 8, "wire hdr is 8 bytes");

	h.device_id = 0x11223344u;
	h.spool_len = 0x55667788u;
	memcpy(buf, &h, sizeof h);
	/* device_id occupies the first 4 bytes, spool_len the next 4. */
	{
		uint32_t a, b;
		memcpy(&a, buf, 4);
		memcpy(&b, buf + 4, 4);
		CHECK(a == 0x11223344u, "device_id at offset 0");
		CHECK(b == 0x55667788u, "spool_len at offset 4");
	}

	/* The session caps the forwarded spool at the worker's ceiling. */
	CHECK(RDP_PRINTER_MAX_SPOOL == RDP_BE_PRINT_JOB_MAX_SPOOL,
	    "spool cap matches worker");
	CHECK(RDP_PRINTER_MAX_SPOOL == 4u * 1024u * 1024u, "cap is 4 MiB");
}

int
main(void)
{
	test_sanitize();
	test_wire_hdr();
	if (fails == 0)
		printf("printer_test: all ok\n");
	return fails == 0 ? 0 : 1;
}
