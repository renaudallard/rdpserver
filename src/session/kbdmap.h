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
 * kbdmap.h -- map a Windows keyboard layout id (LCID) to an XKB layout
 * name so the session's Xvfb keymap follows the client.
 */
#ifndef RDP_KBDMAP_H
#define RDP_KBDMAP_H

#include <stddef.h>
#include <stdint.h>

/* Match on the low 16 bits (primary + sub language); the high 16 bits
 * select an IME / variant we do not distinguish.  Unknown or zero maps
 * to a usable US QWERTY.  variant is an XKB variant or NULL. */
static const struct {
	uint16_t id;
	const char *xkb;
	const char *variant;
} rdp_klid_xkb[] = {
	{ 0x0409, "us", NULL },  /* US English            */
	{ 0x0809, "gb", NULL },  /* UK English            */
	{ 0x040C, "fr", NULL },  /* French (France)       */
	{ 0x080C, "be", NULL },  /* Belgian French        */
	{ 0x100C, "ch", "fr" },  /* Swiss French          */
	{ 0x0407, "de", NULL },  /* German (Germany)      */
	{ 0x0807, "ch", NULL },  /* Swiss German          */
	{ 0x0410, "it", NULL },  /* Italian               */
	{ 0x040A, "es", NULL },  /* Spanish               */
	{ 0x0C0A, "es", NULL },  /* Spanish (modern)      */
	{ 0x0413, "nl", NULL },  /* Dutch                 */
	{ 0x041D, "se", NULL },  /* Swedish               */
	{ 0x040B, "fi", NULL },  /* Finnish               */
	{ 0x0406, "dk", NULL },  /* Danish                */
	{ 0x0414, "no", NULL },  /* Norwegian             */
	{ 0x0419, "ru", NULL },  /* Russian               */
	{ 0x0411, "jp", NULL },  /* Japanese              */
	{ 0x0816, "pt", NULL },  /* Portuguese (Portugal) */
	{ 0x0416, "br", NULL },  /* Portuguese (Brazil)   */
	{ 0x040E, "hu", NULL },  /* Hungarian             */
	{ 0x0415, "pl", NULL },  /* Polish                */
	{ 0x0405, "cz", NULL },  /* Czech                 */
	{ 0x041B, "sk", NULL },  /* Slovak                */
	{ 0x1009, "ca", NULL },  /* Canadian French       */
};

static inline void
rdp_klid_to_xkb(uint32_t lcid, const char **layout, const char **variant)
{
	uint16_t id = (uint16_t)(lcid & 0xffffu);
	size_t i;

	for (i = 0; i < sizeof rdp_klid_xkb / sizeof rdp_klid_xkb[0]; i++)
		if (rdp_klid_xkb[i].id == id) {
			*layout = rdp_klid_xkb[i].xkb;
			*variant = rdp_klid_xkb[i].variant;
			return;
		}
	*layout = "us";   /* unknown / zero -> usable QWERTY */
	*variant = NULL;
}

#endif /* RDP_KBDMAP_H */
