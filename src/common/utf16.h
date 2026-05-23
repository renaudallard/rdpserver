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
 * utf16.h -- UTF-16LE helpers.
 *
 * RDP uses UTF-16LE for nearly every string on the wire (usernames,
 * domains, channel data, clipboard).  These helpers convert to/from
 * UTF-8, which is what we use everywhere else in the program.
 *
 * Surrogate pairs are honoured.  Invalid sequences are reported as
 * errors; we do not silently substitute U+FFFD because doing so
 * would mask wire bugs.
 */

#ifndef RDP_UTF16_H
#define RDP_UTF16_H

#include <stddef.h>
#include <stdint.h>

/* Encode UTF-8 string s (length in bytes) into UTF-16LE at dst.
 * Writes at most dsize bytes.  Returns the number of UTF-16LE bytes
 * that would be written (so caller can detect truncation), or
 * (size_t)-1 if the UTF-8 is malformed. */
size_t rdp_utf8_to_utf16le(uint8_t *dst, size_t dsize,
		const char *s, size_t slen);

/* Decode UTF-16LE bytes into UTF-8 at dst.  Same semantics. */
size_t rdp_utf16le_to_utf8(char *dst, size_t dsize,
		const uint8_t *src, size_t slen);

#endif /* RDP_UTF16_H */
