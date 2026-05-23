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
 * str.c -- string helpers and libc polyfills.
 */

#include "str.h"

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int
rdp_consttime_eq(const void *a, const void *b, size_t n)
{
	const uint8_t *pa = a, *pb = b;
	uint8_t acc = 0;
	size_t i;

	for (i = 0; i < n; i++)
		acc |= (uint8_t)(pa[i] ^ pb[i]);
	return acc == 0 ? 0 : 1;
}

size_t
rdp_hex(char *dst, size_t dsize, const void *src, size_t n)
{
	static const char H[] = "0123456789abcdef";
	const uint8_t *p = src;
	size_t need = n * 2 + 1, w = 0, i;

	if (dsize == 0)
		return need - 1;
	for (i = 0; i < n && w + 2 < dsize; i++) {
		dst[w++] = H[p[i] >> 4];
		dst[w++] = H[p[i] & 0x0f];
	}
	dst[w] = '\0';
	return need - 1;
}

#if !HAVE_STRLCPY
size_t
strlcpy(char *dst, const char *src, size_t dsize)
{
	const char *s = src;
	size_t n = dsize;

	if (n != 0) {
		while (--n != 0) {
			if ((*dst++ = *s++) == '\0')
				break;
		}
	}
	if (n == 0) {
		if (dsize != 0)
			*dst = '\0';
		while (*s++)
			;
	}
	return (size_t)(s - src - 1);
}

size_t
strlcat(char *dst, const char *src, size_t dsize)
{
	const char *s = src;
	char *d = dst;
	size_t n = dsize, dlen;

	while (n-- != 0 && *d != '\0')
		d++;
	dlen = (size_t)(d - dst);
	n = dsize - dlen;
	if (n == 0)
		return dlen + strlen(s);
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';
	return dlen + (size_t)(s - src);
}
#endif

#if !HAVE_REALLOCARRAY
#include <errno.h>
#include <stdlib.h>

#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

void *
reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(optr, size * nmemb);
}
#endif

#if !HAVE_EXPLICIT_BZERO
/* Defeat dead-store elimination via a memory-clobbering asm barrier. */
void
explicit_bzero(void *buf, size_t len)
{
	volatile uint8_t *p = buf;
	while (len--)
		*p++ = 0;
	__asm__ __volatile__ ("" : : "r"(buf) : "memory");
}
#endif
