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
 * buf.h -- bounded byte buffer.
 *
 * A small slab carrying a pointer, capacity, and current write
 * cursor.  Every write checks bounds and either succeeds or returns
 * an error; nothing in this API ever overflows the underlying memory.
 *
 * The buffer is the workhorse for wire encoding/decoding -- caps,
 * orders, channel framing -- where it lets call sites read like
 * straight-line code.
 */

#ifndef RDP_BUF_H
#define RDP_BUF_H

#include <stddef.h>
#include <stdint.h>

struct rdp_buf {
	uint8_t *data;
	size_t   cap;
	size_t   pos;
};

/* Initialise a buffer over caller-owned memory. */
void rdp_buf_init(struct rdp_buf *b, void *p, size_t cap);

/* Reset the cursor without zeroing storage. */
void rdp_buf_reset(struct rdp_buf *b);

/* Remaining writable space. */
size_t rdp_buf_space(const struct rdp_buf *b);

/* Used bytes (== current cursor). */
size_t rdp_buf_used(const struct rdp_buf *b);

/* Append.  Return 0 on success, -1 if the buffer would overflow.
 * On failure the cursor is unchanged. */
int rdp_buf_put(struct rdp_buf *b, const void *src, size_t n);
int rdp_buf_put_u8 (struct rdp_buf *b, uint8_t  v);
int rdp_buf_put_u16le(struct rdp_buf *b, uint16_t v);
int rdp_buf_put_u16be(struct rdp_buf *b, uint16_t v);
int rdp_buf_put_u32le(struct rdp_buf *b, uint32_t v);
int rdp_buf_put_u32be(struct rdp_buf *b, uint32_t v);

/* Reserve n bytes and return a pointer to the reserved region.
 * Returns NULL if reservation would overflow. */
void *rdp_buf_reserve(struct rdp_buf *b, size_t n);

/* Read cursor view -- pos = bytes consumed, cap = bytes available. */
int rdp_buf_get(struct rdp_buf *b, void *dst, size_t n);
int rdp_buf_get_u8 (struct rdp_buf *b, uint8_t  *v);
int rdp_buf_get_u16le(struct rdp_buf *b, uint16_t *v);
int rdp_buf_get_u16be(struct rdp_buf *b, uint16_t *v);
int rdp_buf_get_u32le(struct rdp_buf *b, uint32_t *v);
int rdp_buf_get_u32be(struct rdp_buf *b, uint32_t *v);

/* Skip n bytes; returns -1 if there aren't that many. */
int rdp_buf_skip(struct rdp_buf *b, size_t n);

#endif /* RDP_BUF_H */
