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
 * buf.c -- bounded byte buffer.
 */

#include "buf.h"

#include <string.h>

void
rdp_buf_init(struct rdp_buf *b, void *p, size_t cap)
{
	b->data = p;
	b->cap = cap;
	b->pos = 0;
}

void
rdp_buf_reset(struct rdp_buf *b)
{
	b->pos = 0;
}

size_t
rdp_buf_space(const struct rdp_buf *b)
{
	return b->cap - b->pos;
}

size_t
rdp_buf_used(const struct rdp_buf *b)
{
	return b->pos;
}

int
rdp_buf_put(struct rdp_buf *b, const void *src, size_t n)
{
	if (n > b->cap - b->pos)
		return -1;
	memcpy(b->data + b->pos, src, n);
	b->pos += n;
	return 0;
}

void *
rdp_buf_reserve(struct rdp_buf *b, size_t n)
{
	void *p;

	if (n > b->cap - b->pos)
		return NULL;
	p = b->data + b->pos;
	b->pos += n;
	return p;
}

int
rdp_buf_put_u8(struct rdp_buf *b, uint8_t v)
{
	if (b->cap - b->pos < 1)
		return -1;
	b->data[b->pos++] = v;
	return 0;
}

int
rdp_buf_put_u16le(struct rdp_buf *b, uint16_t v)
{
	if (b->cap - b->pos < 2)
		return -1;
	b->data[b->pos++] = (uint8_t)(v & 0xff);
	b->data[b->pos++] = (uint8_t)((v >> 8) & 0xff);
	return 0;
}

int
rdp_buf_put_u16be(struct rdp_buf *b, uint16_t v)
{
	if (b->cap - b->pos < 2)
		return -1;
	b->data[b->pos++] = (uint8_t)((v >> 8) & 0xff);
	b->data[b->pos++] = (uint8_t)(v & 0xff);
	return 0;
}

int
rdp_buf_put_u32le(struct rdp_buf *b, uint32_t v)
{
	if (b->cap - b->pos < 4)
		return -1;
	b->data[b->pos++] = (uint8_t)(v & 0xff);
	b->data[b->pos++] = (uint8_t)((v >> 8) & 0xff);
	b->data[b->pos++] = (uint8_t)((v >> 16) & 0xff);
	b->data[b->pos++] = (uint8_t)((v >> 24) & 0xff);
	return 0;
}

int
rdp_buf_put_u32be(struct rdp_buf *b, uint32_t v)
{
	if (b->cap - b->pos < 4)
		return -1;
	b->data[b->pos++] = (uint8_t)((v >> 24) & 0xff);
	b->data[b->pos++] = (uint8_t)((v >> 16) & 0xff);
	b->data[b->pos++] = (uint8_t)((v >> 8) & 0xff);
	b->data[b->pos++] = (uint8_t)(v & 0xff);
	return 0;
}

int
rdp_buf_get(struct rdp_buf *b, void *dst, size_t n)
{
	if (n > b->cap - b->pos)
		return -1;
	memcpy(dst, b->data + b->pos, n);
	b->pos += n;
	return 0;
}

int
rdp_buf_get_u8(struct rdp_buf *b, uint8_t *v)
{
	if (b->cap - b->pos < 1)
		return -1;
	*v = b->data[b->pos++];
	return 0;
}

int
rdp_buf_get_u16le(struct rdp_buf *b, uint16_t *v)
{
	uint8_t a, c;
	if (b->cap - b->pos < 2)
		return -1;
	a = b->data[b->pos++];
	c = b->data[b->pos++];
	*v = (uint16_t)a | ((uint16_t)c << 8);
	return 0;
}

int
rdp_buf_get_u16be(struct rdp_buf *b, uint16_t *v)
{
	uint8_t a, c;
	if (b->cap - b->pos < 2)
		return -1;
	a = b->data[b->pos++];
	c = b->data[b->pos++];
	*v = ((uint16_t)a << 8) | (uint16_t)c;
	return 0;
}

int
rdp_buf_get_u32le(struct rdp_buf *b, uint32_t *v)
{
	uint8_t a, c, d, e;
	if (b->cap - b->pos < 4)
		return -1;
	a = b->data[b->pos++];
	c = b->data[b->pos++];
	d = b->data[b->pos++];
	e = b->data[b->pos++];
	*v = (uint32_t)a
	   | ((uint32_t)c << 8)
	   | ((uint32_t)d << 16)
	   | ((uint32_t)e << 24);
	return 0;
}

int
rdp_buf_get_u32be(struct rdp_buf *b, uint32_t *v)
{
	uint8_t a, c, d, e;
	if (b->cap - b->pos < 4)
		return -1;
	a = b->data[b->pos++];
	c = b->data[b->pos++];
	d = b->data[b->pos++];
	e = b->data[b->pos++];
	*v = ((uint32_t)a << 24)
	   | ((uint32_t)c << 16)
	   | ((uint32_t)d << 8)
	   |  (uint32_t)e;
	return 0;
}

int
rdp_buf_skip(struct rdp_buf *b, size_t n)
{
	if (n > b->cap - b->pos)
		return -1;
	b->pos += n;
	return 0;
}
