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
 * capset_test.c -- spot-check Demand Active byte layout.
 */

#include "../../src/wire/capset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static void
test_demand_active(void)
{
	uint8_t buf[2048];
	ssize_t n;
	uint16_t cap_count;

	n = rdp_capset_build_demand_active(buf, sizeof buf, 0x103EAu,
		1280, 720);
	if (n < 32) FAIL("demand active too short: %lld", (long long)n);
	/* shareId = 0x103EA at offset 0 (LE). */
	if (buf[0] != 0xea || buf[1] != 0x03 || buf[2] != 0x01 || buf[3] != 0)
		FAIL("shareId wrong: %02x%02x%02x%02x",
			buf[0], buf[1], buf[2], buf[3]);
	/* lengthSourceDescriptor at offset 4 LE = strlen("RDP")+1 = 4. */
	if (buf[4] != 4 || buf[5] != 0) FAIL("lenSrc");
	/* Source descriptor "RDP\0" at offset 8. */
	if (memcmp(buf + 8, "RDP\0", 4) != 0) FAIL("src descriptor");
	/* numberCapabilities follows at offset 12 (LE). */
	cap_count = (uint16_t)buf[12] | ((uint16_t)buf[13] << 8);
	if (cap_count != 11) FAIL("cap_count = %u", cap_count);
}

int
main(void)
{
	test_demand_active();
	return 0;
}
