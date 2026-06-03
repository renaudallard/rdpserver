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
 * tz_test.c -- client time zone (TS_TIME_ZONE_INFORMATION) to POSIX TZ.
 *
 * Exercises rdp_tz_to_posix over the common cases (DST, southern-hemisphere
 * DST, half-hour no-DST zone, UTC, unfilled block, implausible offset, tiny
 * buffer) and drives a crafted Client Info PDU through rdp_client_info_parse
 * to confirm the 172-byte block is decoded at the right offsets.
 */

#include "../../src/wire/sec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
chk(const char *what, const char *got, const char *want)
{
	if (strcmp(got, want) != 0)
		FAIL("%s: got \"%s\" want \"%s\"", what, got, want);
}

static void
test_synth(void)
{
	char out[64];
	struct rdp_tz_systemtime z;
	struct rdp_tz_systemtime us_std = { 11, 0, 1, 2, 0 }; /* 1st Sun Nov 2:00 */
	struct rdp_tz_systemtime us_dst = { 3, 0, 2, 2, 0 };  /* 2nd Sun Mar 2:00 */
	struct rdp_tz_systemtime eu_std = { 10, 0, 5, 3, 0 }; /* last Sun Oct 3:00 */
	struct rdp_tz_systemtime eu_dst = { 3, 0, 5, 2, 0 };  /* last Sun Mar 2:00 */
	int n;

	memset(&z, 0, sizeof z);

	/* US Eastern: UTC-5 standard, UTC-4 daylight. */
	n = rdp_tz_to_posix(300, 0, -60, &us_std, &us_dst, 1, out, sizeof out);
	if (n <= 0) FAIL("US Eastern returned %d", n);
	chk("US Eastern", out, "<-05>5<-04>4,M3.2.0/2,M11.1.0/2");

	/* Central Europe: UTC+1 standard, UTC+2 daylight (east of UTC, so
	 * the POSIX offsets are negative). */
	n = rdp_tz_to_posix(-60, 0, -60, &eu_std, &eu_dst, 1, out, sizeof out);
	if (n <= 0) FAIL("CET returned %d", n);
	chk("CET", out, "<+01>-1<+02>-2,M3.5.0/2,M10.5.0/3");

	/* India: UTC+5:30, no DST (half-hour offset). */
	n = rdp_tz_to_posix(-330, 0, 0, &z, &z, 1, out, sizeof out);
	if (n <= 0) FAIL("IST returned %d", n);
	chk("IST", out, "<+0530>-5:30");

	/* A real UTC client (name filled, zero bias, no DST). */
	n = rdp_tz_to_posix(0, 0, 0, &z, &z, 1, out, sizeof out);
	if (n <= 0) FAIL("UTC returned %d", n);
	chk("UTC", out, "<+00>0");

	/* An all-zero, name-less block is an unfilled field: leave the
	 * session in the server's zone (empty string, return 0). */
	out[0] = 'x';
	n = rdp_tz_to_posix(0, 0, 0, &z, &z, 0, out, sizeof out);
	if (n != 0) FAIL("unfilled block returned %d", n);
	chk("unfilled", out, "");

	/* Implausible offset is rejected (empty, return 0). */
	out[0] = 'x';
	n = rdp_tz_to_posix(5000, 0, 0, &z, &z, 1, out, sizeof out);
	if (n != 0) FAIL("bogus bias returned %d", n);
	chk("bogus bias", out, "");

	/* Extreme biases must be summed without signed overflow (UB) before
	 * the range check rejects them. */
	out[0] = 'x';
	n = rdp_tz_to_posix(2147483647, 1, 0, &z, &z, 1, out, sizeof out);
	if (n != 0) FAIL("overflow bias returned %d", n);
	chk("overflow bias", out, "");

	/* An out-of-range DST transition hour drops to the no-DST form
	 * rather than emitting a bogus rule. */
	{
		struct rdp_tz_systemtime bad = { 3, 0, 2, 99, 0 };
		n = rdp_tz_to_posix(300, 0, -60, &us_std, &bad, 1,
			out, sizeof out);
		if (n <= 0) FAIL("bad DST hour returned %d", n);
		chk("bad DST hour", out, "<-05>5");
	}

	/* A buffer too small reports -1 and leaves an empty string. */
	{
		char tiny[4];
		tiny[0] = 'x';
		n = rdp_tz_to_posix(300, 0, -60, &us_std, &us_dst, 1,
			tiny, sizeof tiny);
		if (n != -1) FAIL("tiny buffer returned %d", n);
		if (tiny[0] != '\0') FAIL("tiny buffer not cleared");
	}
}

static void
put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

/* Build a minimal ANSI Client Info body whose extraInfo carries a
 * US-Eastern TS_TIME_ZONE_INFORMATION, then confirm the parser decodes
 * it at the right byte offsets. */
static void
test_parse(void)
{
	uint8_t body[201];
	uint8_t *tz;
	struct rdp_client_info info;

	memset(body, 0, sizeof body);
	/* [0..17] codepage, flags (no UNICODE -> ANSI), and five zero cb
	 * fields.  Then five 1-byte string terminators (off 18..22). */
	/* extraInfo starts at off 23: AddressFamily(2)+cbAddress(2)=0
	 * (off->27), cbClientDir(2)=0 (off->29). */
	tz = body + 29;   /* clientTimeZone */
	put32(tz + 0, (uint32_t)300);          /* Bias = +300 (UTC-5) */
	tz[4] = 'E';                           /* StandardName[0] -> have_name */
	/* StandardDate: 1st Sunday of November at 02:00 */
	put16(tz + 68 + 2, 11);                /* wMonth */
	put16(tz + 68 + 4, 0);                 /* wDayOfWeek = Sunday */
	put16(tz + 68 + 6, 1);                 /* wDay = 1st */
	put16(tz + 68 + 8, 2);                 /* wHour */
	put32(tz + 84, 0);                     /* StandardBias */
	/* DaylightDate: 2nd Sunday of March at 02:00 */
	put16(tz + 152 + 2, 3);                /* wMonth */
	put16(tz + 152 + 4, 0);                /* wDayOfWeek = Sunday */
	put16(tz + 152 + 6, 2);                /* wDay = 2nd */
	put16(tz + 152 + 8, 2);                /* wHour */
	put32(tz + 168, (uint32_t)(-60));      /* DaylightBias = -60 */

	if (rdp_client_info_parse(body, sizeof body, &info, NULL, NULL) != 0)
		FAIL("client_info_parse failed");
	chk("parsed timezone", info.timezone, "<-05>5<-04>4,M3.2.0/2,M11.1.0/2");
}

int
main(void)
{
	test_synth();
	test_parse();
	(void)printf("tz_test: all ok\n");
	return 0;
}
