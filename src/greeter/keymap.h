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
 * keymap.h -- minimal PC/AT scancode (set 1) -> ASCII map for the
 * greeter.  A small set of per-LCID tables is selected by the client
 * keyboard layout; unknown layouts fall back to US.
 */

#ifndef RDP_KEYMAP_H
#define RDP_KEYMAP_H

#include <stdint.h>

/* Special keys returned in addition to printable ASCII. */
#define RDP_KEY_ESC       0x1b
#define RDP_KEY_TAB       '\t'
#define RDP_KEY_ENTER     '\n'
#define RDP_KEY_BACKSPACE 0x08

/* Translate (scancode, modifiers) -> a printable character or one of
 * the RDP_KEY_* tokens above.  Returns 0 for non-translatable keys
 * (modifiers themselves, function keys, arrows, ...).
 *
 * `flags` follows the RDP fast-path scancode flags: bit 0 = release,
 * bit 1 = extended (E0 prefix), bit 2 = extended1 (Pause sequence).
 * Modifier state is supplied separately via `shift`. */
char rdp_keymap_us(uint8_t scancode, uint16_t flags, int shift);

/* A scancode->ASCII layout: two 0x80-entry tables, unshifted and
 * shifted.  Only ASCII 0x20-0x7e and the RDP_KEY_* tokens are emitted;
 * every other key is 0 (unmapped) because the greeter font is ASCII. */
struct rdp_keymap {
	const char *base;
	const char *shifted;
};

/* Pick the layout that matches a client keyboard LCID.  Only the low
 * 16 bits (the primary language id) are inspected; layouts we do not
 * carry a table for fall back to US. */
void rdp_keymap_for_lcid(uint32_t lcid, struct rdp_keymap *out);

/* Like rdp_keymap_us, but using the tables in `km`. */
char rdp_keymap_lookup(const struct rdp_keymap *km, uint8_t scancode,
		uint16_t flags, int shift);

#endif /* RDP_KEYMAP_H */
