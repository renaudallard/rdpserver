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
 * greeter.  US layout only in this drop; per-LCID tables are a
 * Phase D follow-up.
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

#endif /* RDP_KEYMAP_H */
