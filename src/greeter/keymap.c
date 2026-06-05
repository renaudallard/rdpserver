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
 * keymap.c -- per-LCID scancode-to-ASCII translation.
 *
 * Scancodes follow PC/AT set 1 (MS-RDPBCGR 2.2.8.1.2.2.1).  The
 * tables only cover keys that produce a character; modifiers,
 * navigation, and function keys return 0 so the caller can ignore
 * them.
 *
 * The greeter font is ASCII 0x20-0x7e, so every table emits only
 * ASCII.  Layout keys whose character is non-ASCII (accents, dead
 * keys, AltGr glyphs) are left 0 and thus ignored, the same way the
 * US table ignores keys it cannot translate.
 */

#include "keymap.h"

/* base[0x80]: character produced when neither Shift nor AltGr is held.
 * shifted[0x80]: character produced when Shift is held. */
static const char base[0x80] = {
	[0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
	[0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8',
	[0x0a] = '9', [0x0b] = '0', [0x0c] = '-', [0x0d] = '=',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r',
	[0x14] = 't', [0x15] = 'y', [0x16] = 'u', [0x17] = 'i',
	[0x18] = 'o', [0x19] = 'p', [0x1a] = '[', [0x1b] = ']',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'a', [0x1f] = 's', [0x20] = 'd', [0x21] = 'f',
	[0x22] = 'g', [0x23] = 'h', [0x24] = 'j', [0x25] = 'k',
	[0x26] = 'l', [0x27] = ';', [0x28] = '\'', [0x29] = '`',
	[0x2b] = '\\',
	[0x2c] = 'z', [0x2d] = 'x', [0x2e] = 'c', [0x2f] = 'v',
	[0x30] = 'b', [0x31] = 'n', [0x32] = 'm',
	[0x33] = ',', [0x34] = '.', [0x35] = '/',
	[0x39] = ' ',
	[0x01] = RDP_KEY_ESC,
};

static const char shifted[0x80] = {
	[0x02] = '!', [0x03] = '@', [0x04] = '#', [0x05] = '$',
	[0x06] = '%', [0x07] = '^', [0x08] = '&', [0x09] = '*',
	[0x0a] = '(', [0x0b] = ')', [0x0c] = '_', [0x0d] = '+',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'Q', [0x11] = 'W', [0x12] = 'E', [0x13] = 'R',
	[0x14] = 'T', [0x15] = 'Y', [0x16] = 'U', [0x17] = 'I',
	[0x18] = 'O', [0x19] = 'P', [0x1a] = '{', [0x1b] = '}',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'A', [0x1f] = 'S', [0x20] = 'D', [0x21] = 'F',
	[0x22] = 'G', [0x23] = 'H', [0x24] = 'J', [0x25] = 'K',
	[0x26] = 'L', [0x27] = ':', [0x28] = '"', [0x29] = '~',
	[0x2b] = '|',
	[0x2c] = 'Z', [0x2d] = 'X', [0x2e] = 'C', [0x2f] = 'V',
	[0x30] = 'B', [0x31] = 'N', [0x32] = 'M',
	[0x33] = '<', [0x34] = '>', [0x35] = '?',
	[0x39] = ' ',
	[0x01] = RDP_KEY_ESC,
};

char
rdp_keymap_us(uint8_t scancode, uint16_t flags, int shift)
{
	const char *t;

	(void)flags;
	if (scancode >= 0x80)
		return 0;
	t = shift ? shifted : base;
	return t[scancode];
}

/* French AZERTY (LCID 0x040C fr-FR, 0x080C fr-BE).  Keys that produce
 * an accented or dead-key glyph in this layout are left 0. */
static const char fr_base[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '&', [0x04] = '"', [0x05] = '\'', [0x06] = '(',
	[0x07] = '-', [0x09] = '_', [0x0c] = ')', [0x0d] = '=',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'a', [0x11] = 'z', [0x12] = 'e', [0x13] = 'r',
	[0x14] = 't', [0x15] = 'y', [0x16] = 'u', [0x17] = 'i',
	[0x18] = 'o', [0x19] = 'p', [0x1b] = '$',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'q', [0x1f] = 's', [0x20] = 'd', [0x21] = 'f',
	[0x22] = 'g', [0x23] = 'h', [0x24] = 'j', [0x25] = 'k',
	[0x26] = 'l', [0x27] = 'm', [0x2b] = '*',
	[0x2c] = 'w', [0x2d] = 'x', [0x2e] = 'c', [0x2f] = 'v',
	[0x30] = 'b', [0x31] = 'n', [0x32] = ',', [0x33] = ';',
	[0x34] = ':', [0x35] = '!',
	[0x39] = ' ', [0x56] = '<',
};

static const char fr_shifted[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
	[0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8',
	[0x0a] = '9', [0x0b] = '0', [0x0d] = '+',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'A', [0x11] = 'Z', [0x12] = 'E', [0x13] = 'R',
	[0x14] = 'T', [0x15] = 'Y', [0x16] = 'U', [0x17] = 'I',
	[0x18] = 'O', [0x19] = 'P',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'Q', [0x1f] = 'S', [0x20] = 'D', [0x21] = 'F',
	[0x22] = 'G', [0x23] = 'H', [0x24] = 'J', [0x25] = 'K',
	[0x26] = 'L', [0x27] = 'M', [0x28] = '%',
	[0x2c] = 'W', [0x2d] = 'X', [0x2e] = 'C', [0x2f] = 'V',
	[0x30] = 'B', [0x31] = 'N', [0x32] = '?', [0x33] = '.',
	[0x34] = '/',
	[0x39] = ' ', [0x56] = '>',
};

/* German QWERTZ (LCID 0x0407 de-DE, 0x0807 de-CH, 0x100C fr-CH).  The
 * Swiss layouts share the QWERTZ letter and digit rows; punctuation
 * differences land on dead/accented keys and stay 0. */
static const char de_base[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
	[0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8',
	[0x0a] = '9', [0x0b] = '0',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r',
	[0x14] = 't', [0x15] = 'z', [0x16] = 'u', [0x17] = 'i',
	[0x18] = 'o', [0x19] = 'p', [0x1b] = '+',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'a', [0x1f] = 's', [0x20] = 'd', [0x21] = 'f',
	[0x22] = 'g', [0x23] = 'h', [0x24] = 'j', [0x25] = 'k',
	[0x26] = 'l', [0x2b] = '#',
	[0x2c] = 'y', [0x2d] = 'x', [0x2e] = 'c', [0x2f] = 'v',
	[0x30] = 'b', [0x31] = 'n', [0x32] = 'm', [0x33] = ',',
	[0x34] = '.', [0x35] = '-',
	[0x39] = ' ', [0x56] = '<',
};

static const char de_shifted[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '!', [0x03] = '"', [0x05] = '$', [0x06] = '%',
	[0x07] = '&', [0x08] = '/', [0x09] = '(', [0x0a] = ')',
	[0x0b] = '=', [0x0c] = '?',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'Q', [0x11] = 'W', [0x12] = 'E', [0x13] = 'R',
	[0x14] = 'T', [0x15] = 'Z', [0x16] = 'U', [0x17] = 'I',
	[0x18] = 'O', [0x19] = 'P', [0x1b] = '*',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'A', [0x1f] = 'S', [0x20] = 'D', [0x21] = 'F',
	[0x22] = 'G', [0x23] = 'H', [0x24] = 'J', [0x25] = 'K',
	[0x26] = 'L', [0x2b] = '\'',
	[0x2c] = 'Y', [0x2d] = 'X', [0x2e] = 'C', [0x2f] = 'V',
	[0x30] = 'B', [0x31] = 'N', [0x32] = 'M', [0x33] = ';',
	[0x34] = ':', [0x35] = '_',
	[0x39] = ' ', [0x56] = '>',
};

/* UK English (LCID 0x0809 en-GB, 0x1809 en-IE).  QWERTY like US; only the
 * punctuation around the number row and the right-hand keys differ, plus the
 * extra ISO key (0x56).  The pound, not, and broken-bar glyphs are non-ASCII
 * and stay 0. */
static const char uk_base[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
	[0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8',
	[0x0a] = '9', [0x0b] = '0', [0x0c] = '-', [0x0d] = '=',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r',
	[0x14] = 't', [0x15] = 'y', [0x16] = 'u', [0x17] = 'i',
	[0x18] = 'o', [0x19] = 'p', [0x1a] = '[', [0x1b] = ']',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'a', [0x1f] = 's', [0x20] = 'd', [0x21] = 'f',
	[0x22] = 'g', [0x23] = 'h', [0x24] = 'j', [0x25] = 'k',
	[0x26] = 'l', [0x27] = ';', [0x28] = '\'', [0x29] = '`',
	[0x2b] = '#',
	[0x2c] = 'z', [0x2d] = 'x', [0x2e] = 'c', [0x2f] = 'v',
	[0x30] = 'b', [0x31] = 'n', [0x32] = 'm',
	[0x33] = ',', [0x34] = '.', [0x35] = '/',
	[0x39] = ' ', [0x56] = '\\',
};

static const char uk_shifted[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '!', [0x03] = '"', [0x05] = '$',
	[0x06] = '%', [0x07] = '^', [0x08] = '&', [0x09] = '*',
	[0x0a] = '(', [0x0b] = ')', [0x0c] = '_', [0x0d] = '+',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'Q', [0x11] = 'W', [0x12] = 'E', [0x13] = 'R',
	[0x14] = 'T', [0x15] = 'Y', [0x16] = 'U', [0x17] = 'I',
	[0x18] = 'O', [0x19] = 'P', [0x1a] = '{', [0x1b] = '}',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'A', [0x1f] = 'S', [0x20] = 'D', [0x21] = 'F',
	[0x22] = 'G', [0x23] = 'H', [0x24] = 'J', [0x25] = 'K',
	[0x26] = 'L', [0x27] = ':', [0x28] = '@', [0x2b] = '~',
	[0x2c] = 'Z', [0x2d] = 'X', [0x2e] = 'C', [0x2f] = 'V',
	[0x30] = 'B', [0x31] = 'N', [0x32] = 'M',
	[0x33] = '<', [0x34] = '>', [0x35] = '?',
	[0x39] = ' ', [0x56] = '|',
};

/* Spanish (LCID 0x040A es-ES).  QWERTY; the many accented and dead keys (n
 * with tilde, acute, grave, inverted marks, c-cedilla) are non-ASCII and stay
 * 0, so only the letters, digits and the punctuation that is unambiguously
 * ASCII are mapped. */
static const char es_base[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
	[0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8',
	[0x0a] = '9', [0x0b] = '0', [0x0c] = '\'',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r',
	[0x14] = 't', [0x15] = 'y', [0x16] = 'u', [0x17] = 'i',
	[0x18] = 'o', [0x19] = 'p', [0x1b] = '+',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'a', [0x1f] = 's', [0x20] = 'd', [0x21] = 'f',
	[0x22] = 'g', [0x23] = 'h', [0x24] = 'j', [0x25] = 'k',
	[0x26] = 'l',
	[0x2c] = 'z', [0x2d] = 'x', [0x2e] = 'c', [0x2f] = 'v',
	[0x30] = 'b', [0x31] = 'n', [0x32] = 'm',
	[0x33] = ',', [0x34] = '.', [0x35] = '-',
	[0x39] = ' ', [0x56] = '<',
};

static const char es_shifted[0x80] = {
	[0x01] = RDP_KEY_ESC,
	[0x02] = '!', [0x03] = '"', [0x05] = '$',
	[0x06] = '%', [0x07] = '&', [0x08] = '/', [0x09] = '(',
	[0x0a] = ')', [0x0b] = '=', [0x0c] = '?',
	[0x0e] = RDP_KEY_BACKSPACE, [0x0f] = RDP_KEY_TAB,
	[0x10] = 'Q', [0x11] = 'W', [0x12] = 'E', [0x13] = 'R',
	[0x14] = 'T', [0x15] = 'Y', [0x16] = 'U', [0x17] = 'I',
	[0x18] = 'O', [0x19] = 'P', [0x1b] = '*',
	[0x1c] = RDP_KEY_ENTER,
	[0x1e] = 'A', [0x1f] = 'S', [0x20] = 'D', [0x21] = 'F',
	[0x22] = 'G', [0x23] = 'H', [0x24] = 'J', [0x25] = 'K',
	[0x26] = 'L',
	[0x2c] = 'Z', [0x2d] = 'X', [0x2e] = 'C', [0x2f] = 'V',
	[0x30] = 'B', [0x31] = 'N', [0x32] = 'M',
	[0x33] = ';', [0x34] = ':', [0x35] = '_',
	[0x39] = ' ', [0x56] = '>',
};

void
rdp_keymap_for_lcid(uint32_t lcid, struct rdp_keymap *out)
{
	/* MS-LCID: the low 16 bits hold the language identifier. */
	uint16_t lang = (uint16_t)(lcid & 0xffffu);

	switch (lang) {
	case 0x040C:  /* fr-FR */
	case 0x080C:  /* fr-BE */
	case 0x140C:  /* fr-LU */
	case 0x180C:  /* fr-MC */
		out->base = fr_base;
		out->shifted = fr_shifted;
		break;
	case 0x0407:  /* de-DE */
	case 0x0807:  /* de-CH */
	case 0x0C07:  /* de-AT */
	case 0x1407:  /* de-LI */
	case 0x100C:  /* fr-CH (QWERTZ) */
		out->base = de_base;
		out->shifted = de_shifted;
		break;
	case 0x0809:  /* en-GB */
	case 0x1809:  /* en-IE */
		out->base = uk_base;
		out->shifted = uk_shifted;
		break;
	case 0x040A:  /* es-ES */
		out->base = es_base;
		out->shifted = es_shifted;
		break;
	default:      /* US and every unknown layout */
		out->base = base;
		out->shifted = shifted;
		break;
	}
}

char
rdp_keymap_lookup(const struct rdp_keymap *km, uint8_t scancode,
		uint16_t flags, int shift)
{
	const char *t;

	(void)flags;
	if (scancode >= 0x80)
		return 0;
	t = shift ? km->shifted : km->base;
	return t[scancode];
}
