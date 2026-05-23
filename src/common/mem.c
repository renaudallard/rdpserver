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
 * mem.c -- allocation wrappers.
 */

#include "mem.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include <stdlib.h>
#include <string.h>

void *
rdp_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (p == NULL) {
		rdp_err("calloc(%zu, %zu): out of memory", nmemb, size);
		abort();
	}
	return p;
}

void *
rdp_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *p = reallocarray(ptr, nmemb, size);
	if (p == NULL) {
		rdp_err("reallocarray(%p, %zu, %zu): out of memory",
			ptr, nmemb, size);
		abort();
	}
	return p;
}

char *
rdp_strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = rdp_calloc(1, n);
	(void)memcpy(p, s, n);
	return p;
}

void
rdp_free(void *p)
{
	free(p);
}
