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
 * keymap_test.c -- per-LCID greeter scancode-to-ASCII tables.
 *
 * Checks the layout dispatch and the characteristic keys that distinguish each
 * layout, so a hand-coding slip in a table or a wrong LCID alias is caught.
 */

#include "../../src/greeter/keymap.h"

#include <stdio.h>
#include <stdlib.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static char
k(uint32_t lcid, uint8_t sc, int shift)
{
	struct rdp_keymap km;
	rdp_keymap_for_lcid(lcid, &km);
	return rdp_keymap_lookup(&km, sc, 0, shift);
}

#define EXPECT(lcid, sc, sh, ch, name) do {                            \
	char got = k((lcid), (sc), (sh));                              \
	if (got != (char)(ch))                                         \
		FAIL("%s: lcid 0x%x sc 0x%02x shift %d -> %d, want %d", \
		    name, (unsigned)(lcid), (sc), (sh), got, (ch));    \
} while (0)

int
main(void)
{
	/* US (default for 0 and unknown). */
	EXPECT(0, 0x10, 0, 'q', "us");
	EXPECT(0, 0x1e, 0, 'a', "us");
	EXPECT(0, 0x03, 1, '@', "us");
	EXPECT(0, 0x2b, 0, '\\', "us");
	EXPECT(0x0409, 0x28, 1, '"', "us");

	/* UK: like US but the 2/'/# keys and the ISO key differ. */
	EXPECT(0x0809, 0x10, 0, 'q', "uk");
	EXPECT(0x0809, 0x03, 1, '"', "uk");
	EXPECT(0x0809, 0x28, 1, '@', "uk");
	EXPECT(0x0809, 0x2b, 0, '#', "uk");
	EXPECT(0x0809, 0x2b, 1, '~', "uk");
	EXPECT(0x0809, 0x56, 0, '\\', "uk");
	EXPECT(0x1809, 0x2b, 0, '#', "en-IE alias");

	/* French AZERTY: letters move. */
	EXPECT(0x040C, 0x10, 0, 'a', "fr");
	EXPECT(0x040C, 0x11, 0, 'z', "fr");
	EXPECT(0x040C, 0x02, 1, '1', "fr");
	EXPECT(0x140C, 0x10, 0, 'a', "fr-LU alias");
	EXPECT(0x180C, 0x11, 0, 'z', "fr-MC alias");

	/* German QWERTZ: y and z swap. */
	EXPECT(0x0407, 0x15, 0, 'z', "de");
	EXPECT(0x0407, 0x2c, 0, 'y', "de");
	EXPECT(0x0C07, 0x15, 0, 'z', "de-AT alias");
	EXPECT(0x1407, 0x2c, 0, 'y', "de-LI alias");

	/* Spanish QWERTY: digit-row shifts and the lower-row punctuation. */
	EXPECT(0x040A, 0x10, 0, 'q', "es");
	EXPECT(0x040A, 0x2c, 0, 'z', "es");
	EXPECT(0x040A, 0x08, 1, '/', "es");
	EXPECT(0x040A, 0x33, 1, ';', "es");
	EXPECT(0x040A, 0x0c, 0, '\'', "es");
	/* The n-with-tilde key has no ASCII char and must not borrow US ';'. */
	EXPECT(0x040A, 0x27, 0, 0, "es accented key blank");

	/* Common control keys and out-of-range guard. */
	EXPECT(0, 0x1c, 0, RDP_KEY_ENTER, "enter");
	EXPECT(0x040C, 0x39, 0, ' ', "space");
	EXPECT(0, 0x80, 0, 0, "out of range");
	EXPECT(0, 0xff, 1, 0, "out of range hi");

	(void)printf("keymap_test: all ok\n");
	return 0;
}
